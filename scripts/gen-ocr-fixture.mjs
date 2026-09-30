/**
 * Regenerates tests/fixtures/ocr-sample.png — the OCR test document.
 *
 * Deterministic, zero-dependency: a 5x7 bitmap font rendered to a grayscale
 * PNG (zlib + CRC32 via Node built-ins). The committed PNG is labeled test
 * infrastructure (same policy as the fixture TLS certificates); this script
 * exists so anyone can regenerate and diff it.
 *
 * Run: node scripts/gen-ocr-fixture.mjs
 */
import zlib from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';

const TEXT = 'MERIDIAN OCR 4217'; // ground truth the OCR engine must read
const SCALE = 16, GAP_COLS = 7, MARGIN = 60;

// 5x7 bitmap font (columns per row) — only the glyphs TEXT needs.
const F = {
  M: ['10001', '11011', '10101', '10001', '10001', '10001', '10001'],
  E: ['11111', '10000', '10000', '11110', '10000', '10000', '11111'],
  R: ['11110', '10001', '10001', '11110', '10011', '10101', '10001'],
  I: ['11111', '00100', '00100', '00100', '00100', '00100', '11111'],
  D: ['11110', '10001', '10001', '10001', '10001', '10001', '11110'],
  A: ['01110', '10001', '10001', '11111', '10001', '10001', '10001'],
  N: ['10001', '11001', '10101', '10011', '10001', '10001', '10001'],
  O: ['01110', '10001', '10001', '10001', '10001', '10001', '01110'],
  C: ['01110', '10001', '10000', '10000', '10000', '10001', '01110'],
  ' ': ['00000', '00000', '00000', '00000', '00000', '00000', '00000'],
  '4': ['00010', '00110', '01010', '10010', '11111', '00010', '00010'],
  '2': ['11110', '00001', '00001', '01110', '10000', '10000', '11111'],
  '1': ['00100', '01100', '00100', '00100', '00100', '00100', '01110'],
  '7': ['11111', '00001', '00010', '00100', '01000', '01000', '01000'],
};

function renderLine(text) {
  const h = 7 * SCALE, w = text.length * GAP_COLS * SCALE;
  const px = new Uint8Array(w * h).fill(255); // white background
  let cx = 0;
  for (const ch of text) {
    const glyph = F[ch];
    if (!glyph) throw new Error(`no glyph for '${ch}' — extend the font`);
    for (let r = 0; r < 7; r++) for (let c = 0; c < 5; c++) {
      if (glyph[r][c] !== '1') continue;
      for (let dy = 0; dy < SCALE; dy++) for (let dx = 0; dx < SCALE; dx++) {
        px[(r * SCALE + dy) * w + (cx + c * SCALE + dx)] = 0; // black ink
      }
    }
    cx += GAP_COLS * SCALE;
  }
  return { px, w, h };
}

// ---- minimal PNG encoder (8-bit grayscale, non-interlaced) ----
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
const crc32 = (buf) => { let c = 0xffffffff; for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};
function encodePng({ px, w, h }) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 0; // bit depth 8, grayscale
  const raw = Buffer.alloc((w + 1) * h); // filter byte 0 per scanline
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) raw[y * (w + 1) + 1 + x] = px[y * w + x];
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0)),
  ]);
}

// white margin around the text line (helps page segmentation)
const line = renderLine(TEXT);
const w = line.w + 2 * MARGIN, h = line.h + 2 * MARGIN;
const px = new Uint8Array(w * h).fill(255);
for (let y = 0; y < line.h; y++) for (let x = 0; x < line.w; x++) px[(y + MARGIN) * w + (x + MARGIN)] = line.px[y * line.w + x];

const png = encodePng({ px, w, h });
const out = path.resolve('tests/fixtures/ocr-sample.png');
mkdirSync(path.dirname(out), { recursive: true });
writeFileSync(out, png);
console.log(`[gen-ocr-fixture] wrote ${out} (${png.length} bytes, ${w}x${h}, ground truth: "${TEXT}")`);
