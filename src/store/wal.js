import fs from 'node:fs';

/**
 * Append-only write-ahead log with fsync durability.
 * One JSON object per line; transactions are a single line so they are atomic
 * with respect to crash recovery (a torn final line is discarded on recovery).
 */
export class Wal {
  constructor(path, { sync = true } = {}) {
    this.path = path;
    this.sync = sync;
    this.fd = fs.openSync(path, 'a');
    this.count = 0;
  }
  append(obj) {
    const line = JSON.stringify(obj) + '\n';
    fs.writeSync(this.fd, line);
    if (this.sync) fs.fsyncSync(this.fd);
    this.count++;
  }
  /** Iterate all intact lines. Returns [{line, seq}] */
  static readAll(path) {
    const out = [];
    if (!fs.existsSync(path)) return out;
    const content = fs.readFileSync(path, 'utf8');
    let start = 0;
    while (start < content.length) {
      const nl = content.indexOf('\n', start);
      if (nl === -1) break; // torn write at end — discard
      const line = content.slice(start, nl);
      if (line.trim().length) {
        try { out.push(JSON.parse(line)); } catch { /* corrupted line mid-file: stop replay here */ break; }
      }
      start = nl + 1;
    }
    return out;
  }
  /** Truncate WAL after a successful snapshot. */
  reset() {
    fs.closeSync(this.fd);
    fs.writeFileSync(this.path, '');
    this.fd = fs.openSync(this.path, 'a');
    this.count = 0;
  }
  close() { try { fs.closeSync(this.fd); } catch { /* already closed */ } }
}
