import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { newId, sha256 } from '#core/util';
import { notFound } from '#core/errors';

/**
 * Tenant-isolated object storage. Content-addressed files on disk
 * (data/files/<tenant>/<fileId>) with metadata in the store. File ids are
 * generated (no user-controlled paths), names are sanitized at ingest,
 * and files live outside any served web root.
 */
export class FileStore {
  constructor(dataDir, store) {
    this.root = path.join(dataDir, 'files');
    this.store = store;
    fs.mkdirSync(this.root, { recursive: true });
  }
  put(tenantId, buffer, { name, mime, meta = {} } = {}) {
    const id = newId('file');
    const dir = path.join(this.root, tenantId);
    fs.mkdirSync(dir, { recursive: true });
    const disk = path.join(dir, id);
    fs.writeFileSync(disk, buffer);
    const record = {
      id, tenant_id: tenantId, name, mime, size: buffer.length,
      sha256: sha256(buffer), meta, disk,
      created_at: new Date().toISOString(),
    };
    this.store.put('files', record);
    return record;
  }
  get(tenantId, fileId) {
    const rec = this.store.byId('files', fileId);
    if (!rec || rec.tenant_id !== tenantId) throw notFound('file not found');
    return rec;
  }
  read(tenantId, fileId) {
    const rec = this.get(tenantId, fileId);
    return fs.readFileSync(rec.disk);
  }
  /** integrity check: recompute sha256 */
  verify(tenantId, fileId) {
    const rec = this.get(tenantId, fileId);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(rec.disk)).digest('hex');
    return { ok: actual === rec.sha256, expected: rec.sha256, actual };
  }
  remove(tenantId, fileId) {
    const rec = this.get(tenantId, fileId);
    try { fs.unlinkSync(rec.disk); } catch { /* already gone */ }
    this.store.del('files', rec.id);
  }
  list(tenantId) {
    return this.store.find('files', (f) => f.tenant_id === tenantId);
  }
}
