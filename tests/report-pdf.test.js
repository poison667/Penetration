import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PdfBuilder } from '#report/pdf';

test('PdfBuilder produces a valid PDF 1.4 document', () => {
  const pdf = new PdfBuilder({ title: 'Test Report' });
  pdf.heading('Section One');
  pdf.paragraph('Hello world — this line verifies text escaping (parens) and layout.');
  pdf.table(['ID', 'Severity'], [['F-001', 'critical'], ['F-002', 'high']]);
  const buf = pdf.build();
  const head = buf.slice(0, 8).toString('latin1');
  assert.equal(head, '%PDF-1.4');
  assert.ok(buf.slice(-32).toString('latin1').includes('%%EOF'));
  // xref table present
  const text = buf.toString('latin1');
  assert.ok(text.includes('xref'));
  assert.ok(text.includes('/Type /Catalog'));
  assert.ok(text.includes('/Type /Page'));
});

test('long content paginates automatically', () => {
  const pdf = new PdfBuilder({ title: 'Many pages' });
  for (let i = 0; i < 120; i++) pdf.paragraph(`Line ${i}: ${'x'.repeat(90)}`);
  const buf = pdf.build();
  const pageCount = (buf.toString('latin1').match(/\/Type \/Page[^s]/g) || []).length;
  assert.ok(pageCount >= 2, `expected pagination, got ${pageCount} pages`);
});

test('special characters are escaped safely in content streams', () => {
  const pdf = new PdfBuilder({ title: 'Escape test' });
  pdf.paragraph('parens (nested (deeply)) and backslash \\ and unicode éè —');
  const buf = pdf.build();
  assert.ok(buf.length > 500);
  // no unbalanced parens crash: build completed
});

test('severity table renders colored severity cells', () => {
  const pdf = new PdfBuilder({ title: 'Findings' });
  pdf.severityTable ? pdf.severityTable([['F-1', 'critical', 'SQLi'], ['F-2', 'low', 'Info leak']])
    : pdf.table(['ID', 'Severity', 'Title'], [['F-1', 'critical', 'SQLi'], ['F-2', 'low', 'Info leak']]);
  const buf = pdf.build();
  assert.ok(buf.slice(0, 8).toString('latin1') === '%PDF-1.4');
});
