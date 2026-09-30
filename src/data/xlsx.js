import { Buffer } from 'node:buffer';

/**
 * Minimal real XLSX writer (Office Open XML), zero dependencies.
 * ZIP container with STORE entries + CRC-32; inline-string worksheets.
 */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function zipStore(entries) {
  // entries: [{name, data:Buffer}]
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8');
    const crc = crc32(e.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);       // version needed
    local.writeUInt16LE(0, 6);        // flags
    local.writeUInt16LE(0, 8);        // method: STORE
    local.writeUInt16LE(0, 10); local.writeUInt16LE(0, 12); // time/date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(e.data.length, 18);
    local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, nameBuf, e.data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8); central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12); central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(e.data.length, 20); central.writeUInt32LE(e.data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30); central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34); central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, nameBuf);
    offset += 30 + nameBuf.length + e.data.length;
  }
  const centralBuf = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4); end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralBuf, end]);
}

function xmlEscape(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
}

/** Convert a sheet of rows (array of objects) into worksheet XML. */
function sheetXml(rows) {
  const headers = rows.length ? Object.keys(rows[0]) : [];
  let xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
  // header row (row 1)
  xml += `<row r="1">` + headers.map((h, c) => `<c r="${cellRef(1, c + 1)}" t="inlineStr"><is><t>${xmlEscape(h)}</t></is></c>`).join('') + '</row>';
  rows.forEach((row, r) => {
    const rowIdx = r + 2;
    xml += `<row r="${rowIdx}">`;
    headers.forEach((h, c) => {
      const v = row[h];
      const ref = cellRef(rowIdx, c + 1);
      if (v == null || v === '') xml += '';
      else if (typeof v === 'number' && Number.isFinite(v)) xml += `<c r="${ref}"><v>${v}</v></c>`;
      else if (typeof v === 'boolean') xml += `<c r="${ref}" t="b"><v>${v ? 1 : 0}</v></c>`;
      else xml += `<c r="${ref}" t="inlineStr"><is><t>${xmlEscape(v)}</t></is></c>`;
    });
    xml += '</row>';
  });
  xml += '</sheetData></worksheet>';
  return xml;
}
function cellRef(row, col) {
  let c = col, s = '';
  while (c > 0) { const m = (c - 1) % 26; s = String.fromCharCode(65 + m) + s; c = Math.floor((c - 1) / 26); }
  return `${s}${row}`;
}

/** Write an XLSX workbook: {sheetName: rows[]} → Buffer */
export function writeXlsx(sheets) {
  const names = Object.keys(sheets);
  const entries = [];
  entries.push({ name: '[Content_Types].xml', data: Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
    '<Default Extension="xml" ContentType="application/xml"/>' +
    `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
    names.map((n, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('') +
    '</Types>') });
  entries.push({ name: '_rels/.rels', data: Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
    '</Relationships>') });
  entries.push({ name: 'xl/workbook.xml', data: Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
    `<sheets>${names.map((n, i) => `<sheet name="${xmlEscape(n.slice(0, 31))}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`) });
  entries.push({ name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    names.map((n, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('') +
    '</Relationships>') });
  names.forEach((n, i) => {
    entries.push({ name: `xl/worksheets/sheet${i + 1}.xml`, data: Buffer.from(sheetXml(sheets[n])) });
  });
  return zipStore(entries);
}

/** Parse our own XLSX (round-trip verification in tests): unzip STORE entries. */
export function readXlsxSheets(buf) {
  const sheets = {};
  let pos = 0;
  const files = {};
  while (pos + 30 <= buf.length) {
    if (buf.readUInt32LE(pos) !== 0x04034b50) break;
    const nameLen = buf.readUInt16LE(pos + 26);
    const extraLen = buf.readUInt16LE(pos + 28);
    const dataSize = buf.readUInt32LE(pos + 18);
    const name = buf.slice(pos + 30, pos + 30 + nameLen).toString('utf8');
    const data = buf.slice(pos + 30 + nameLen + extraLen, pos + 30 + nameLen + extraLen + dataSize);
    files[name] = data;
    pos += 30 + nameLen + extraLen + dataSize;
  }
  const wb = files['xl/workbook.xml']?.toString('utf8') || '';
  const rels = files['xl/_rels/workbook.xml.rels']?.toString('utf8') || '';
  const nameById = {};
  for (const m of rels.matchAll(/Id="(rId\d+)"[^>]*Target="([^"]+)"/g)) nameById[m[1]] = m[2];
  for (const m of wb.matchAll(/<sheet name="([^"]*)" sheetId="\d+" r:id="(rId\d+)"/g)) {
    // rels targets are relative to xl/ (e.g. "worksheets/sheet1.xml")
    const target = nameById[m[2]];
    const xml = files[`xl/${target}`]?.toString('utf8') || '';
    const rows = [];
    let current = null;
    for (const rm of xml.matchAll(/<row r="(\d+)">(.*?)<\/row>/g)) {
      const cells = {};
      for (const cm of rm[2].matchAll(/<c r="([A-Z]+\d+)"(?: t="(\w+)")?(?:\/|>(?:<is><t>(.*?)<\/t><\/is>|<v>(.*?)<\/v>)<\/c>)/g)) {
        const colLetters = cm[1].replace(/\d+/, '');
        let col = 0;
        for (const ch of colLetters) col = col * 26 + (ch.charCodeAt(0) - 64);
        let val = cm[3] ?? cm[4] ?? '';
        if (cm[2] === 'b') val = val === '1';
        else if (cm[4] !== undefined && cm[4] !== '' && !Number.isNaN(Number(cm[4]))) val = Number(cm[4]);
        cells[col] = val;
      }
      rows.push(cells);
    }
    const headers = {};
    for (const [col, v] of Object.entries(rows[0] || {})) headers[col] = v;
    const out = rows.slice(1).map((r) => {
      const obj = {};
      for (const [col, h] of Object.entries(headers)) obj[h] = r[col] ?? '';
      return obj;
    });
    sheets[m[1]] = out;
  }
  return sheets;
}

export { zipStore, crc32 };
export { deflateSync } from 'node:zlib';
