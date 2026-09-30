import { parentPort } from 'node:worker_threads';

/**
 * OCR engine thread — one job per thread, disposable by design.
 *
 * tesseract.js re-throws image-decoding failures at the process level (its
 * worker 'error' handler does `process.nextTick(() => { throw err })`), so it
 * must never run in the API/worker process: a malformed upload would crash the
 * platform. Here that throw only kills this thread, and the parent
 * (src/docint/ocr.js) reports the failure honestly. The thread is terminated
 * by the parent as soon as the result (or crash) is observed — nothing
 * outlives the call, so no lingering handles can hold a process open.
 */

parentPort.on('message', async (m) => {
  if (m?.kind !== 'job') return;
  let worker = null;
  try {
    const { createWorker } = await import('tesseract.js');
    const opts = m.langPath ? { langPath: m.langPath, cachePath: m.langPath } : {};
    worker = await createWorker(m.lang || 'eng', 1, opts);
    const { data } = await worker.recognize(m.buffer);
    parentPort.postMessage({ kind: 'job', ok: true, text: String(data.text || ''), confidence: typeof data.confidence === 'number' ? data.confidence : null });
  } catch (e) {
    // decode/engine errors that reject cleanly land here; crashes that don't
    // simply kill this thread (the parent handles 'error'/'exit' the same way)
    try { parentPort.postMessage({ kind: 'job', ok: false, error: String(e?.message || e).slice(0, 500) }); } catch { /* thread is dying */ }
  } finally {
    try { if (worker) await worker.terminate(); } catch { /* */ }
  }
});
