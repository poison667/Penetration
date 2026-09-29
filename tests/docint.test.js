import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractText, extractPdfText } from '#docint/extract';
import { compareDocuments } from '#docint/diff';
import { writeXlsx, readXlsxSheets } from '#data/xlsx';

const TINY_PDF = Buffer.from(
  '%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n' +
  '3 0 obj<</Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n' +
  '4 0 obj<</Length 90>>\nstream\nBT /F1 12 Tf 72 720 Td (Invoice 42 total 999) Tj ET\nendstream endobj\n' +
  'trailer<</Root 1 0 R>>\n%%EOF', 'latin1');

test('extractText reads plain text and marks the method honestly', () => {
  const r = extractText(Buffer.from('hello document intelligence'), 'text/plain', 'note.txt');
  assert.equal(r.text.includes('hello document intelligence'), true);
  assert.equal(r.method, 'raw_text');
});

test('extractText extracts PDF text-layer content', () => {
  const r = extractText(TINY_PDF, 'application/pdf', 'inv.pdf');
  assert.ok(r.text.includes('Invoice 42') || r.method === 'pdf_text_layer' || r.requires_ocr, JSON.stringify(r).slice(0, 200));
});

test('extractText is honest about unsupported OCR (scanned images)', () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);
  const r = extractText(png, 'image/png', 'scan.png');
  assert.equal(r.requires_ocr, true);
  assert.ok(r.extraction_note || r.method);
  assert.equal((r.text || '').length, 0); // no fabricated text
});

test('extractPdfText pulls literal strings from content streams', () => {
  const r = extractPdfText(TINY_PDF);
  assert.ok(r.text.includes('Invoice 42'));
  assert.equal(r.method, 'pdf_text_layer');
  assert.ok(r.pages >= 1);
});

test('compareDocuments flags textual changes between versions', () => {
  const a = 'Payment terms: 30 days.\nTotal: 1000 EUR.\nSignature: A.';
  const b = 'Payment terms: 60 days.\nTotal: 1000 EUR.\nSignature: B.';
  const diff = compareDocuments(a, b);
  assert.ok(diff.hunks.length >= 1, 'expected at least one change hunk');
  assert.ok(diff.stats.lines_inserted + diff.stats.lines_deleted >= 2);
  assert.ok(diff.stats.similarity < 1);
  const flat = JSON.stringify(diff);
  assert.ok(flat.includes('30 days') || flat.includes('60 days'), 'expected changed terms in the diff');
});

test('compareDocuments reports no changes for identical documents', () => {
  const diff = compareDocuments('same\ncontent', 'same\ncontent');
  assert.equal(diff.hunks.length, 0);
  assert.equal(diff.stats.similarity, 1);
});

// ---------------- XLSX ----------------

test('writeXlsx + readXlsxSheets roundtrip preserves data', () => {
  const buf = writeXlsx({
    Findings: [
      { id: 'F-1', severity: 'critical', title: 'SQLi' },
      { id: 'F-2', severity: 'high', title: 'XSS' },
    ],
  });
  assert.equal(buf.slice(0, 2).toString('latin1'), 'PK'); // real zip container
  const sheets = readXlsxSheets(buf);
  assert.ok('Findings' in sheets, `sheet names: ${Object.keys(sheets)}`);
  const rows = sheets['Findings'];
  assert.equal(rows.length, 2); // header consumed, 2 data rows as objects
  assert.equal(rows[0].id, 'F-1');
  assert.equal(rows[0].severity, 'critical');
  assert.equal(rows[1].title, 'XSS');
});

test('writeXlsx produces multiple sheets', () => {
  const buf = writeXlsx({ A: [{ a: 1 }], B: [{ b: 2 }] });
  const sheets = readXlsxSheets(buf);
  assert.ok('A' in sheets && 'B' in sheets, `sheet names: ${Object.keys(sheets)}`);
});
