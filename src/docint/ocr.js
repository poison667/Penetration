import { Worker } from 'node:worker_threads';
import { spawn } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';

/**
 * OCR provider layer — runtime-probed, never fabricated, crash-contained.
 *
 * Probe order (cached; MERIDIAN_OCR=off disables entirely):
 *   1. tesseract.js (optional engine dependency, WASM Tesseract) — executed in
 *      a DISPOSABLE worker thread per job. Two hard requirements drive this:
 *      (a) tesseract.js re-throws image-decoding failures at the process level
 *          (its worker 'error' handler does `process.nextTick(() => { throw })`),
 *          so in-process execution would let one malformed upload crash the
 *          whole platform — in a thread, the throw only kills the thread;
 *      (b) a persistent thread with a live message listener keeps the host
 *          process alive at exit even after Worker#unref() (verified on
 *          Node 20), which would hang API/test processes. A per-job thread is
 *      terminated as soon as its result (or crash) is observed, so no handles
 *      outlive the call. Language data comes from vendor/tessdata/ when
 *      present (fully offline).
 *   2. system `tesseract` binary — for deployments with native Tesseract.
 *   3. none — callers report `requires_ocr` honestly and extract no text.
 *
 * The platform core stays zero-runtime-dependency (D1/D25).
 */

const OCR_OFF = () => (process.env.MERIDIAN_OCR || '').toLowerCase() === 'off';
const VENDOR_TESSDATA = () => {
  const p = process.env.MERIDIAN_OCR_LANGPATH || path.resolve('vendor/tessdata');
  try { accessSync(path.join(p, 'eng.traineddata'), constants.R_OK); return p; } catch { return null; }
};

let resolved = undefined; // undefined = not probed, null = unavailable

async function probeTesseractJs() {
  try {
    const mod = await import('tesseract.js');
    if (typeof mod.createWorker !== 'function') return null;
    return { kind: 'tesseractjs' };
  } catch { return null; /* optional dependency not installed */ }
}

function probeSystemTesseract() {
  return new Promise((resolve) => {
    const t = spawn('tesseract', ['--version'], { stdio: 'ignore' });
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    t.on('error', () => finish(null));
    t.on('close', (code) => finish(code === 0 ? { kind: 'cli' } : null));
    setTimeout(() => { try { t.kill(); } catch {} finish(null); }, 2000);
  });
}

async function resolveProvider() {
  if (OCR_OFF()) return null;
  const js = await probeTesseractJs();
  if (js) return js;
  const cli = await probeSystemTesseract();
  return cli; // may be null → honest absence
}

/** { available, engine, detail } — probes once, cached. */
export async function ocrProviderInfo() {
  if (resolved === undefined) resolved = await resolveProvider();
  if (!resolved) {
    return { available: false, engine: null, detail: OCR_OFF() ? 'OCR disabled by configuration (MERIDIAN_OCR=off)' : 'no OCR engine available (install the optional tesseract.js dependency or a system tesseract binary)' };
  }
  const detail = resolved.kind === 'tesseractjs'
    ? `tesseract.js (WASM Tesseract)${VENDOR_TESSDATA() ? ', offline language data from vendor/tessdata' : ', default remote language data'}`
    : 'system tesseract binary (CLI)';
  return { available: true, engine: resolved.kind, detail };
}

/* ------------- disposable engine thread (tesseract.js, per job) ------------- */
const THREAD_FILE = fileURLToPath(new URL('./ocr-thread.mjs', import.meta.url));

function threadOcr(buffer, { lang, timeoutMs = 180_000 }) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(THREAD_FILE);
    worker.unref(); // belt & braces — the thread is terminated explicitly below
    let settled = false;
    const settle = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(v);
      try { worker.terminate(); } catch { /* */ } // job done (or failed) — the thread is disposable
    };
    const timer = setTimeout(() => settle(reject, new Error('OCR engine timeout')), timeoutMs);
    worker.on('message', (m) => {
      if (m?.kind !== 'job') return;
      if (m.ok) settle(resolve, { text: m.text, confidence: m.confidence, engine: 'tesseract.js' });
      else settle(reject, new Error(m.error));
    });
    worker.on('error', (e) => settle(reject, new Error(`ocr engine thread crashed: ${String(e?.message || e).slice(0, 200)}`)));
    worker.on('exit', (code) => { if (code !== 0) settle(reject, new Error(`ocr engine thread exited unexpectedly (${code})`)); });
    worker.postMessage({ kind: 'job', buffer, lang, langPath: VENDOR_TESSDATA() });
  });
}

/* ---------------- system tesseract CLI ---------------- */
function cliOcr(buffer, { lang = 'eng', timeoutMs = 120_000 } = {}) {
  return new Promise((resolve, reject) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'meridian-ocr-'));
    const inFile = path.join(dir, 'in.png');
    try { writeFileSync(inFile, buffer); } catch (e) { rmSync(dir, { recursive: true, force: true }); return reject(e); }
    const p = spawn('tesseract', [inFile, 'stdout', '-l', lang], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    const timer = setTimeout(() => { try { p.kill('SIGKILL'); } catch {} reject(new Error('tesseract CLI timeout')); }, timeoutMs);
    p.stdout.on('data', (c) => { out += c; });
    p.stderr.on('data', (c) => { err += c; });
    p.on('error', (e) => { clearTimeout(timer); rmSync(dir, { recursive: true, force: true }); reject(e); });
    p.on('close', (code) => {
      clearTimeout(timer);
      rmSync(dir, { recursive: true, force: true });
      if (code === 0) resolve({ text: out, confidence: null, engine: 'tesseract-cli' });
      else reject(new Error(`tesseract CLI exited ${code}: ${err.slice(0, 300)}`));
    });
  });
}

/**
 * Run OCR on an image buffer. Throws on engine failure — callers report the
 * failure honestly and must never substitute fabricated text.
 * @returns {Promise<{text: string, confidence: number|null, engine: string}>}
 */
export async function ocrImage(buffer, { lang = 'eng' } = {}) {
  if (resolved === undefined) resolved = await resolveProvider();
  if (!resolved) throw new Error('no OCR engine available');
  if (resolved.kind === 'tesseractjs') return threadOcr(buffer, { lang });
  return cliOcr(buffer, { lang });
}

/** Test hook: drop the provider cache (re-probes on next use). */
export function resetOcrProviderCache() {
  resolved = undefined;
}
