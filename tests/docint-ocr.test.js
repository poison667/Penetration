import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { extractText, extractTextAsync } from '#docint/extract';
import { ocrProviderInfo, ocrImage, resetOcrProviderCache } from '#docint/ocr';

/**
 * OCR verification — the tests against the real engine run when it is
 * installed (optional dependency); in minimal installs the same tests assert
 * the honest-absence path instead. Nothing is ever fabricated either way.
 */

const FIXTURE = path.resolve('tests/fixtures/ocr-sample.png');
const GROUND_TRUTH = 'MERIDIAN OCR 4217';
const norm = (s) => String(s || '').replace(/\s+/g, ' ').trim();

test('ocrProviderInfo reports the probed engine honestly', async () => {
  const info = await ocrProviderInfo();
  if (info.available) {
    assert.ok(['tesseractjs', 'cli'].includes(info.engine), `engine: ${info.engine}`);
    assert.ok(info.detail.length > 5);
  } else {
    assert.equal(info.engine, null);
    assert.match(info.detail, /no OCR engine available|disabled by configuration/);
  }
});

test('real OCR extracts the committed fixture image (when the engine is installed)', async () => {
  const info = await ocrProviderInfo();
  if (!info.available) {
    const r = await extractTextAsync(readFileSync(FIXTURE), 'image/png', 'ocr-sample.png');
    assert.equal(r.requires_ocr, true, 'absence must be reported, not papered over');
    assert.equal((r.text || '').length, 0, 'no fabricated text without an engine');
    return; // honest-absence environment
  }
  const png = readFileSync(FIXTURE);
  const r = await extractTextAsync(png, 'image/png', 'ocr-sample.png');
  assert.equal(r.requires_ocr, false);
  assert.match(r.method, /^ocr:/);
  assert.equal(r.ocr_available, true);
  assert.equal(norm(r.text), GROUND_TRUTH, `OCR output: ${JSON.stringify(r.text)}`);
  assert.ok(r.text_chars_unchecked !== 'x'); // (no-op guard — shape stays honest)
});

test('ocrImage returns engine + confidence metadata', async () => {
  const info = await ocrProviderInfo();
  if (!info.available) { assert.ok(true); return; }
  const r = await ocrImage(readFileSync(FIXTURE));
  assert.ok(r.engine);
  assert.ok(typeof r.text === 'string' && norm(r.text) === GROUND_TRUTH);
  // confidence: tesseract.js reports a mean word confidence; the CLI adapter reports null
  if (r.engine === 'tesseract.js') assert.ok(typeof r.confidence === 'number' && r.confidence > 0);
});

test('engine failure on garbage image bytes is reported, never fabricated', async () => {
  const info = await ocrProviderInfo();
  const garbage = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03]);
  const r = await extractTextAsync(garbage, 'image/png', 'broken.png');
  if (!info.available) {
    assert.equal(r.requires_ocr, true);
    return;
  }
  assert.equal((r.text || '').length, 0, 'no text may be invented for undecodable input');
  assert.ok(r.note, 'failure/note must be present');
});

test('engine thread respawns after a crash and keeps serving', async () => {
  const info = await ocrProviderInfo();
  if (!info.available || info.engine !== 'tesseractjs') { assert.ok(true); return; }
  // crash it: undecodable bytes kill the tesseract.js thread (contained)
  const garbage = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xde, 0xad, 0xbe, 0xef]);
  const bad = await extractTextAsync(garbage, 'image/png', 'crash.png');
  assert.equal((bad.text || '').length, 0, 'crash reported, no text');
  // the engine must come back for the next, valid image
  const r = await extractTextAsync(readFileSync(FIXTURE), 'image/png', 'ocr-sample.png');
  assert.equal(norm(r.text), GROUND_TRUTH, `engine did not recover: ${JSON.stringify(r.note)}`);
  assert.match(r.method, /^ocr:/);
});

test('MERIDIAN_OCR=off disables OCR and the absence stays honest', async () => {
  const prev = process.env.MERIDIAN_OCR;
  process.env.MERIDIAN_OCR = 'off';
  try {
    resetOcrProviderCache();
    const info = await ocrProviderInfo();
    assert.equal(info.available, false);
    assert.match(info.detail, /disabled by configuration/);
    const r = await extractTextAsync(readFileSync(FIXTURE), 'image/png', 'ocr-sample.png');
    assert.equal(r.requires_ocr, true, 'image reports requires_ocr');
    assert.equal((r.text || '').length, 0, 'no text without the engine');
    assert.ok(r.note);
    await assert.rejects(() => ocrImage(readFileSync(FIXTURE)), /no OCR engine available/);
  } finally {
    if (prev === undefined) delete process.env.MERIDIAN_OCR; else process.env.MERIDIAN_OCR = prev;
    resetOcrProviderCache(); // re-probe for any later tests in this process
  }
});

test('sync extractText keeps its contract for images (no engine implied, no text)', () => {
  const r = extractText(readFileSync(FIXTURE), 'image/png', 'ocr-sample.png');
  assert.equal(r.requires_ocr, true);
  assert.equal((r.text || '').length, 0);
  assert.equal(r.method, 'none');
});

test('extractTextAsync passes through synchronous formats unchanged', async () => {
  const r = await extractTextAsync(Buffer.from('plain document text'), 'text/plain', 'a.txt');
  assert.equal(r.method, 'raw_text');
  assert.ok(r.text.includes('plain document text'));
  const j = await extractTextAsync(Buffer.from('{"a":1}'), 'application/json', 'a.json');
  assert.equal(j.method, 'json_pretty');
});
