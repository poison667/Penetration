/**
 * RFC 4180-compliant CSV parse/stringify (handles quoted fields, embedded
 * delimiters, escaped quotes, CRLF) with delimiter sniffing.
 */
export function parseCsv(text, { delimiter } = {}) {
  const src = String(text ?? '').replace(/^\uFEFF/, '');
  const delim = delimiter || sniffDelimiter(src);
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQuotes = false; i++; continue;
      }
      field += ch; i++; continue;
    }
    if (ch === '"') { inQuotes = true; i++; continue; }
    if (ch === delim) { row.push(field); field = ''; i++; continue; }
    if (ch === '\r' && src[i + 1] === '\n') { row.push(field); rows.push(row); row = []; field = ''; i += 2; continue; }
    if (ch === '\n' || ch === '\r') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
    field += ch; i++;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  // drop fully-empty trailing rows
  while (rows.length && rows[rows.length - 1].every((c) => c === '')) rows.pop();
  if (!rows.length) return { headers: [], rows: [] };
  const headers = rows[0].map((h, i) => (h.trim() || `column_${i + 1}`));
  const data = rows.slice(1).map((r) => {
    const obj = {};
    headers.forEach((h, idx) => { obj[h] = r[idx] ?? ''; });
    return obj;
  });
  return { headers, rows: data };
}

export function stringifyCsv(rows, { delimiter = ',' } = {}) {
  if (!rows.length) return '';
  const headers = Object.keys(rows[0]);
  const esc = (v) => {
    const s = v == null ? '' : String(v);
    return /["\n\r,;\t]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.map(esc).join(delimiter)];
  for (const r of rows) lines.push(headers.map((h) => esc(r[h])).join(delimiter));
  return lines.join('\r\n') + '\r\n';
}

function sniffDelimiter(src) {
  const sample = src.split(/\r?\n/).slice(0, 5);
  const counts = { ',': 0, ';': 0, '\t': 0 };
  for (const line of sample) {
    let inQ = false;
    for (const ch of line) {
      if (ch === '"') inQ = !inQ;
      else if (!inQ && ch in counts) counts[ch]++;
    }
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][1] > 0
    ? Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0]
    : ',';
}
