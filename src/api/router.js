import { toAppError } from '#core/errors';

/** Minimal Express-style router (zero dependencies). */
export class Router {
  constructor() {
    this.routes = [];
  }
  add(method, pattern, handler, opts = {}) {
    const paramNames = [];
    const regexSrc = pattern.replace(/:([A-Za-z0-9_]+)/g, (_, name) => { paramNames.push(name); return '([^/]+)'; });
    this.routes.push({ method, pattern, regex: new RegExp(`^${regexSrc}$`), paramNames, handler, opts });
  }
  get(p, h, o) { this.add('GET', p, h, o); }
  post(p, h, o) { this.add('POST', p, h, o); }
  patch(p, h, o) { this.add('PATCH', p, h, o); }
  put(p, h, o) { this.add('PUT', p, h, o); }
  delete(p, h, o) { this.add('DELETE', p, h, o); }
  match(method, path) {
    for (const r of this.routes) {
      if (r.method !== method && !(r.method === 'GET' && method === 'HEAD')) continue;
      const m = r.regex.exec(path);
      if (!m) continue;
      const params = {};
      r.paramNames.forEach((name, i) => { params[name] = decodeURIComponent(m[i + 1]); });
      return { route: r, params };
    }
    return null;
  }
}

/** JSON response helper. */
export function json(res, status, body, headers = {}) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': payload.length, ...headers });
  res.end(payload);
}

/** Read a request body with size cap. */
export function readBody(req, { limit = 25 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('payload too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export async function readJson(req, opts) {
  const buf = await readBody(req, opts);
  if (!buf.length) return {};
  try { return JSON.parse(buf.toString('utf8')); }
  catch { throw Object.assign(new Error('invalid JSON body'), { status: 400 }); }
}
