import fs from 'node:fs';
import path from 'node:path';
import { Wal } from './wal.js';

/**
 * Meridian embedded durable store.
 * - Collections of JSON documents (id → doc), with optional secondary indexes.
 * - Every mutation is appended to a write-ahead log (fsync) before being applied.
 * - Transactions append a single WAL line containing multiple ops (atomic).
 * - Periodic atomic snapshots compact the WAL (tmp file + rename + WAL reset).
 * - Crash recovery: load latest snapshot, replay WAL entries with seq > snapshot seq;
 *   a torn final line is discarded.
 * The DAO layer (src/app/db.js) enforces tenant scoping on top of this store;
 * the Postgres adapter path and row-level-security design are documented in
 * docs/ARCHITECTURE.md (production deployment).
 */
const SNAPSHOT_EVERY = 4000; // ops between compactions

export class Store {
  constructor(dataDir, { sync = true } = {}) {
    this.dataDir = dataDir;
    this.sync = sync;
    this.collections = new Map(); // name -> Map(id -> doc)
    this.indexes = new Map();     // name -> Map(indexName -> Map(key -> Set(id)))
    this.seq = 0;
    this.opCount = 0;
    this.meta = { snapshotSeq: 0, snapshotFile: null, version: 1 };
  }

  init() {
    fs.mkdirSync(this.dataDir, { recursive: true });
    const metaPath = path.join(this.dataDir, 'meta.json');
    if (fs.existsSync(metaPath)) {
      try { this.meta = { ...this.meta, ...JSON.parse(fs.readFileSync(metaPath, 'utf8')) }; } catch { /* corrupt meta: full replay */ }
    }
    // load snapshot
    if (this.meta.snapshotFile) {
      const snapPath = path.join(this.dataDir, this.meta.snapshotFile);
      if (fs.existsSync(snapPath)) {
        try {
          const snap = JSON.parse(fs.readFileSync(snapPath, 'utf8'));
          for (const [name, docs] of Object.entries(snap.collections || {})) {
            const map = new Map();
            for (const doc of docs) map.set(doc.id, doc);
            this.collections.set(name, map);
          }
          this.seq = snap.seq || 0;
        } catch { /* corrupt snapshot: fall back to WAL-only replay */ this.meta.snapshotSeq = 0; this.seq = 0; }
      }
    }
    // replay WAL
    const entries = Wal.readAll(path.join(this.dataDir, 'wal.jsonl'));
    let replayed = 0, discarded = 0;
    for (const entry of entries) {
      if (entry.seq <= (this.meta.snapshotSeq || 0)) { discarded++; continue; }
      this.#apply(entry);
      this.seq = entry.seq;
      replayed++;
    }
    this.wal = new Wal(path.join(this.dataDir, 'wal.jsonl'), { sync: this.sync });
    this.#rebuildIndexes();
    this.lastRecovery = { replayed, discarded, seq: this.seq, docs: this.#docCount() };
    return this;
  }

  #collection(name) {
    let c = this.collections.get(name);
    if (!c) { c = new Map(); this.collections.set(name, c); }
    return c;
  }

  addIndex(collection, indexName, keyFn) {
    if (!this.indexes.has(collection)) this.indexes.set(collection, new Map());
    this.indexes.get(collection).set(indexName, { keyFn, map: new Map() });
    this.#rebuildIndex(collection, indexName);
  }
  #rebuildIndexes() {
    for (const [collection, idxs] of this.indexes) {
      for (const indexName of idxs.keys()) this.#rebuildIndex(collection, indexName);
    }
  }
  #rebuildIndex(collection, indexName) {
    const idx = this.indexes.get(collection)?.get(indexName);
    if (!idx) return;
    idx.map = new Map();
    for (const [id, doc] of this.#collection(collection)) {
      const key = idx.keyFn(doc);
      if (key == null) continue;
      if (!idx.map.has(key)) idx.map.set(key, new Set());
      idx.map.get(key).add(id);
    }
  }
  #indexUpdate(collection, id, oldDoc, newDoc) {
    const idxs = this.indexes.get(collection);
    if (!idxs) return;
    for (const idx of idxs.values()) {
      const oldKey = oldDoc ? idx.keyFn(oldDoc) : null;
      const newKey = newDoc ? idx.keyFn(newDoc) : null;
      if (oldKey != null) idx.map.get(oldKey)?.delete(id);
      if (newKey != null) {
        if (!idx.map.has(newKey)) idx.map.set(newKey, new Set());
        idx.map.get(newKey).add(id);
      }
    }
  }

  #apply(entry) {
    if (entry.tx) {
      for (const op of entry.tx) this.#applyOp(op);
    } else this.#applyOp(entry);
  }
  #applyOp(op) {
    if (op.op === 'put') {
      const c = this.#collection(op.c);
      const old = c.get(op.d.id) || null;
      c.set(op.d.id, op.d);
      this.#indexUpdate(op.c, op.d.id, old, op.d);
    } else if (op.op === 'del') {
      const c = this.#collection(op.c);
      const old = c.get(op.id) || null;
      c.delete(op.id);
      this.#indexUpdate(op.c, op.id, old, null);
    }
  }
  #entry(ops) {
    const entry = ops.length === 1 ? { seq: this.seq + 1, ...ops[0] } : { seq: this.seq + 1, tx: ops };
    this.wal.append(entry);
    this.seq++;
    this.opCount++;
    this.#apply(entry);
    if (this.opCount >= SNAPSHOT_EVERY) this.snapshot();
    return entry.seq;
  }

  put(collection, doc) {
    if (!doc || !doc.id) throw new Error('document must have id');
    return this.#entry([{ op: 'put', c: collection, d: doc }]);
  }
  del(collection, id) {
    return this.#entry([{ op: 'del', c: collection, id }]);
  }
  /** Atomic multi-op transaction: all ops or none. */
  tx(ops) {
    if (!ops.length) return;
    return this.#entry(ops);
  }

  byId(collection, id) {
    return this.collections.get(collection)?.get(id) || null;
  }
  find(collection, predicate = () => true) {
    const c = this.collections.get(collection);
    if (!c) return [];
    const out = [];
    for (const doc of c.values()) if (predicate(doc)) out.push(doc);
    return out;
  }
  findOne(collection, predicate) {
    for (const doc of this.#collection(collection).values()) if (predicate(doc)) return doc;
    return null;
  }
  byIndex(collection, indexName, key) {
    const idx = this.indexes.get(collection)?.get(indexName);
    if (!idx) return [];
    const ids = idx.map.get(key);
    if (!ids) return [];
    const out = [];
    for (const id of ids) { const d = this.#collection(collection).get(id); if (d) out.push(d); }
    return out;
  }
  count(collection, predicate) {
    const c = this.collections.get(collection);
    if (!c) return 0;
    if (!predicate) return c.size;
    let n = 0;
    for (const doc of c.values()) if (predicate(doc)) n++;
    return n;
  }
  #docCount() {
    let n = 0;
    for (const c of this.collections.values()) n += c.size;
    return n;
  }

  /** Atomic snapshot + WAL reset. Safe across crash (tmp + rename). */
  snapshot() {
    const snap = { seq: this.seq, savedAt: new Date().toISOString(), collections: {} };
    for (const [name, c] of this.collections) {
      snap.collections[name] = [...c.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
    }
    const file = `snapshot-${this.seq}.json`;
    const tmp = path.join(this.dataDir, file + '.tmp');
    fs.writeFileSync(tmp, JSON.stringify(snap));
    fs.renameSync(tmp, path.join(this.dataDir, file));
    // prune older snapshots
    for (const f of fs.readdirSync(this.dataDir)) {
      if (f.startsWith('snapshot-') && f !== file && f.endsWith('.json')) {
        try { fs.unlinkSync(path.join(this.dataDir, f)); } catch { /* ignore */ }
      }
    }
    this.wal.reset();
    this.meta = { snapshotSeq: this.seq, snapshotFile: file, version: 1 };
    fs.writeFileSync(path.join(this.dataDir, 'meta.json'), JSON.stringify(this.meta));
    this.opCount = 0;
  }

  stats() {
    const collections = {};
    for (const [name, c] of this.collections) collections[name] = c.size;
    return { seq: this.seq, docs: this.#docCount(), collections, snapshotSeq: this.meta.snapshotSeq };
  }
  close() {
    try { if (this.opCount > 0) this.snapshot(); } catch { /* best effort */ }
    this.wal?.close();
  }
}

export function openStore(dataDir, opts = {}) {
  return new Store(dataDir, opts).init();
}
