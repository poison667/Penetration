import zlib from 'node:zlib';
import { htmlToText } from '#lib/html';

/**
 * Document text extraction.
 * - TXT/MD/CSV/JSON: direct
 * - HTML: DOM-based text extraction
 * - PDF: text-layer extraction (objects → streams → inflate → text-showing operators)
 * - Images/scanned PDFs: requires an OCR provider adapter (probed at runtime,
 *   status reported honestly when unavailable)
 */
export function extractText(buffer, mime, name = '') {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (mime === 'application/pdf' || ext === 'pdf') return extractPdfText(buffer);
  if (mime === 'text/html' || ext === 'html' || ext === 'htm') return { text: htmlToText(buffer.toString('utf8')), method: 'html_dom', pages: 1 };
  if (ext === 'json' || mime === 'application/json') {
    try {
      const parsed = JSON.parse(buffer.toString('utf8'));
      const text = JSON.stringify(parsed, null, 1);
      return { text, method: 'json_pretty', pages: 1 };
    } catch { return { text: buffer.toString('utf8'), method: 'raw_text', pages: 1, warning: 'invalid JSON — raw text used' }; }
  }
  if (ext === 'csv' || mime === 'text/csv') {
    return { text: buffer.toString('utf8'), method: 'csv_text', pages: 1 };
  }
  // images and unknown binary types need OCR
  if (mime?.startsWith('image/') || ext === 'png' || ext === 'jpg' || ext === 'jpeg' || ext === 'tiff' || ext === 'webp') {
    return { text: null, method: 'none', requires_ocr: true, ocr_available: false, pages: null, note: 'OCR provider not configured in this deployment (see docs/LIMITATIONS.md)' };
  }
  if (mime === 'application/zip' || ext === 'zip' || mime?.startsWith('application/vnd.openxmlformats') || ext === 'docx' || ext === 'xlsx') {
    return { text: null, method: 'none', requires_ocr: false, pages: null, note: 'OOXML container — extraction adapter not active in this deployment; stored as binary with SHA-256' };
  }
  return { text: buffer.toString('utf8'), method: 'raw_text', pages: 1 };
}

/** PDF text-layer extraction (FlateDecode + text operators). */
export function extractPdfText(buffer) {
  const pages = [];
  // find all stream objects
  const raw = buffer;
  let pos = 0;
  const streams = [];
  const objRe = /(\d+)\s+(\d+)\s+obj\b/g;
  let m;
  while ((m = objRe.exec(raw.toString('latin1'))) !== null) {
    const objStart = m.index;
    const endIdx = raw.indexOf('endobj', objStart);
    if (endIdx === -1) continue;
    const seg = raw.subarray(objStart, endIdx);
    const streamStart = seg.indexOf('stream');
    if (streamStart === -1) continue;
    let dataStart = streamStart + 6;
    if (seg[dataStart] === 0x0d) dataStart++;
    if (seg[dataStart] === 0x0a) dataStart++;
    const streamEnd = seg.indexOf('endstream', dataStart);
    if (streamEnd === -1) continue;
    const head = seg.subarray(0, streamStart).toString('latin1');
    const isFlate = /FlateDecode/.test(head);
    const isPage = /\/Type\s*\/Page\b/.test(head);
    const isFont = /\/Font/.test(head);
    let data = seg.subarray(dataStart, streamEnd);
    if (isFlate) {
      try { data = zlib.inflateSync(data); } catch {
        try { data = zlib.inflateRawSync(data); } catch { continue; }
      }
    }
    streams.push({ num: m[1], head, data, isPage });
  }
  let text = '';
  let pageCount = 0;
  for (const s of streams) {
    if (s.isPage) pageCount++;
    const content = s.data.toString('latin1');
    // BT ... ET text blocks; extract Tj, TJ, ', " operands
    const texts = [];
    const tokenRe = /\((?:\\.|[^\\()])*\)|\bTd\b|\bTD\b|\bT\*\b|\bTj\b|\bTJ\b|\bTf\b|\bET\b|\bBT\b|\bTm\b/g;
    let inText = false;
    let t;
    while ((t = tokenRe.exec(content)) !== null) {
      const tok = t[0];
      if (tok === 'BT') { inText = true; continue; }
      if (tok === 'ET') { inText = false; continue; }
      if (!inText) continue;
      if (tok.startsWith('(')) texts.push(decodePdfString(tok.slice(1, -1)));
      else if (tok === 'Td' || tok === 'TD' || tok === 'T*' || tok === 'Tm') texts.push('\n');
    }
    const pageText = texts.join('').replace(/\n{2,}/g, '\n').trim();
    if (pageText) { text += pageText + '\n\n'; pages.push(pageText); }
  }
  if (!pages.length) {
    return { text: text.trim() || null, method: 'pdf_text_layer', pages: pageCount, note: pageCount ? 'No text layer extracted (likely scanned image PDF — OCR provider required)' : 'No pages parsed' };
  }
  return { text: text.trim(), method: 'pdf_text_layer', pages: Math.max(pageCount, pages.length) };
}

function decodePdfString(s) {
  return s
    .replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t')
    .replace(/\\([()\\])/g, '$1')
    .replace(/\\([0-7]{1,3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)));
}
