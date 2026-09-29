/** Generate the Meridian mark (favicon + logo SVGs) — no binary assets needed. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// A meridian: circle + vertical transit line through it, compass tick. Restrained, enterprise.
const favicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="6" fill="#1d2d44"/>
  <circle cx="16" cy="16" r="9.5" fill="none" stroke="#7fa3cf" stroke-width="1.6"/>
  <ellipse cx="16" cy="16" rx="4" ry="9.5" fill="none" stroke="#7fa3cf" stroke-width="1.2" opacity="0.75"/>
  <path d="M16 2.5 v3 M16 26.5 v3 M2.5 16 h3 M26.5 16 h3" stroke="#9db8d9" stroke-width="1.4" stroke-linecap="round"/>
  <circle cx="16" cy="16" r="1.6" fill="#e8eef5"/>
</svg>`;

const logo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 140 32">
  <g transform="translate(0,0)">
    <rect width="32" height="32" rx="6" fill="#1d2d44"/>
    <circle cx="16" cy="16" r="9.5" fill="none" stroke="#7fa3cf" stroke-width="1.6"/>
    <ellipse cx="16" cy="16" rx="4" ry="9.5" fill="none" stroke="#7fa3cf" stroke-width="1.2" opacity="0.75"/>
    <path d="M16 2.5 v3 M16 26.5 v3 M2.5 16 h3 M26.5 16 h3" stroke="#9db8d9" stroke-width="1.4" stroke-linecap="round"/>
    <circle cx="16" cy="16" r="1.6" fill="#e8eef5"/>
  </g>
  <text x="42" y="21.5" font-family="system-ui, -apple-system, 'Segoe UI', sans-serif" font-size="15" font-weight="600" letter-spacing="0.4" fill="currentColor">Meridian</text>
</svg>`;

for (const dir of [path.join(root, 'apps/client/public'), path.join(root, 'webroot')]) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'favicon.svg'), favicon);
}
fs.writeFileSync(path.join(root, 'apps/client/public/logo.svg'), logo);

/** Minimal dependency-free PNG writer (RGBA, no interlace). */
function writePng(file, width, height, rgba) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crcTable = [];
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c >>> 0; }
    let crc = 0xffffffff;
    for (const b of body) crc = crcTable[(crc ^ b) & 0xff] ^ (crc >>> 8);
    const crcBuf = Buffer.alloc(4); crcBuf.writeUInt32BE((crc ^ 0xffffffff) >>> 0);
    return Buffer.concat([len, body, crcBuf]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  fs.writeFileSync(file, png);
}

/** Render the Meridian mark (ring + meridian ellipse) at a given size. */
function renderMark(size) {
  const bg = [29, 45, 68];      // deep slate
  const ring = [127, 163, 207]; // steel blue
  const px = [232, 238, 245];   // near-white
  const rgba = Buffer.alloc(size * size * 4);
  const c = size / 2;
  const S = (v) => Math.max(0, Math.min(255, Math.round(v)));
  const put = (i, color, a) => { rgba[i] = S(color[0]); rgba[i + 1] = S(color[1]); rgba[i + 2] = S(color[2]); rgba[i + 3] = S(a * 255); };
  const ringW = Math.max(1.4, size * 0.05);
  const ellW = Math.max(1, size * 0.038);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      // rounded-square backdrop
      const r = size * 0.19;
      const dx = Math.max(Math.abs(x + 0.5 - c) - (c - r), 0);
      const dy = Math.max(Math.abs(y + 0.5 - c) - (c - r), 0);
      const inside = Math.hypot(dx, dy) <= r;
      if (!inside) { put(i, [0, 0, 0], 0); continue; }
      put(i, bg, 1);
      const nx = (x + 0.5 - c) / (c * 0.62);
      const ny = (y + 0.5 - c) / (c * 0.62);
      const dist = Math.hypot(nx, ny);
      // meridian ellipse: rx factor 0.42
      const ex = nx / 0.42;
      const edist = Math.hypot(ex, ny);
      // anti-aliased edges via distance overflow
      if (Math.abs(dist - 1) < ringW * 0.9) put(i, ring, Math.min(1, 1 - Math.abs(dist - 1) / (ringW * 0.9)));
      else if (Math.abs(edist - 1) < ellW) put(i, ring, 0.75);
      // compass ticks
      const tick = Math.max(1, size * 0.045);
      const nearAxis = (Math.abs(x + 0.5 - c) < tick / 2 && (y < c * 0.28 || y > size - c * 0.28))
        || (Math.abs(y + 0.5 - c) < tick / 2 && (x < c * 0.28 || x > size - c * 0.28));
      if (nearAxis) put(i, [157, 184, 217], 1);
      // center dot
      if (Math.hypot(x + 0.5 - c, y + 0.5 - c) < size * 0.055) put(i, px, 1);
    }
  }
  return rgba;
}

const iconDir = path.join(root, 'apps/desktop/src-tauri/icons');
fs.mkdirSync(iconDir, { recursive: true });
for (const [name, size] of [['32x32.png', 32], ['128x128.png', 128], ['128x128@2x.png', 256], ['icon.png', 256]]) {
  writePng(path.join(iconDir, name), size, size, renderMark(size));
}
console.log('[icons] favicon.svg + logo.svg (client) and 4 PNG app icons (desktop) written');
