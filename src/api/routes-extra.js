import crypto from 'node:crypto';
import { badRequest, notFound, unauthorized, forbidden } from '#core/errors';
import { requireAuth as requireAuthMW, authenticateApiKey, authenticate } from './authn.js';
import { validate, V } from '#core/validate';
import { recordAudit, verifyAuditChain } from '#app/audit';
import { balanceOf, buildInvoice } from '#app/billing';
import { notify, listNotifications, markRead } from '#app/notify';
import { runMonitor } from '#worker/monitors';
import { parseCron, nextRun } from '#auto/cron';
import { saveWorkflow, runWorkflow } from '#auto/workflow';
import { extractText } from '#docint/extract';
import { sha256, nowIso } from '#core/util';
import { parseMultipart, sniffMagic, sanitizeFilename } from '#sec/http';
import { resolveProvider } from '#ai/providers';
import { bus, TOPICS } from '#core/events';

const UPLOAD_MAX = 15 * 1024 * 1024;
const DOC_EXTS = ['txt', 'md', 'csv', 'json', 'html', 'htm', 'pdf', 'png', 'jpg', 'jpeg', 'zip', 'docx', 'xlsx'];

/** Registers monitoring, data, documents, KB/AI, automation, billing, support, admin, meta routes. */
export function registerExtraRoutes(router, app) {
  const { db, files } = app;

  // ---------------- MONITORS ----------------
  router.get('/api/v1/monitors', async (ctx) => {
    requireAuth(ctx, ['monitors:read']);
    const { rows, total } = db.list('monitors', ctx.tid, { limit: 200 });
    ctx.respond(200, { monitors: rows, total });
  });
  router.post('/api/v1/monitors', async (ctx) => {
    requireAuth(ctx, ['monitors:write']);
    const body = validate({
      name: V.string({ min: 2, max: 80 }), type: V.enum(['http', 'keyword', 'content_hash', 'tls_cert', 'dns', 'api', 'port']),
      asset_id: V.string({ max: 60 }), url: V.url({ allowPrivate: true }), interval_seconds: V.int({ min: 30, max: 86400 }),
      config: V.record(V.any()).optional(),
    }, ctx.body);
    const monitor = db.insert('monitors', {
      tenant_id: ctx.tid, name: body.name, type: body.type, asset_id: body.asset_id || null,
      url: body.url, interval_seconds: body.interval_seconds, config: body.config || {},
      enabled: true, last_status: null, last_run_at: null, next_run_at: nowIso(), created_at: nowIso(),
    });
    ctx.respond(201, { monitor });
  });
  router.patch('/api/v1/monitors/:id', async (ctx) => {
    requireAuth(ctx, ['monitors:write']);
    const body = validate({ enabled: V.boolean(), name: V.string({ min: 2, max: 80 }), interval_seconds: V.int({ min: 30, max: 86400 }), config: V.record(V.any()).optional() }, ctx.body, { partial: true });
    const monitor = db.update('monitors', ctx.tid, ctx.params.id, body);
    ctx.respond(200, { monitor });
  });
  router.delete('/api/v1/monitors/:id', async (ctx) => {
    requireAuth(ctx, ['monitors:write']);
    db.remove('monitors', ctx.tid, ctx.params.id);
    ctx.respond(200, { ok: true });
  });
  router.get('/api/v1/monitors/:id/checks', async (ctx) => {
    requireAuth(ctx, ['monitors:read']);
    const monitor = db.byId('monitors', ctx.tid, ctx.params.id);
    if (!monitor) throw notFound('monitor not found');
    const checks = db.store.byIndex('monitor_checks', 'monitor_ts', `${monitor.id}|`).length
      ? db.store.find('monitor_checks', (c) => c.monitor_id === monitor.id).sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, Number(ctx.query.get('limit') || 100))
      : db.store.find('monitor_checks', (c) => c.monitor_id === monitor.id).sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, Number(ctx.query.get('limit') || 100));
    const events = db.store.find('monitor_events', (e) => e.tenant_id === ctx.tid && e.monitor_id === monitor.id).sort((a, b) => (a.ts < b.ts ? 1 : -1)).slice(0, 50);
    ctx.respond(200, { checks, events });
  });
  router.post('/api/v1/monitors/:id/test', async (ctx) => {
    requireAuth(ctx, ['monitors:write']);
    const monitor = db.byId('monitors', ctx.tid, ctx.params.id);
    if (!monitor) throw notFound('monitor not found');
    const result = await runMonitor(db, monitor);
    ctx.respond(200, { check: result.check, events: result.events });
  });

  // ---------------- DATA SOURCES + RUNS ----------------
  router.get('/api/v1/data/sources', async (ctx) => {
    requireAuth(ctx, ['data:read']);
    const { rows, total } = db.list('data_sources', ctx.tid, { limit: 200 });
    ctx.respond(200, { sources: rows, total });
  });
  router.post('/api/v1/data/sources', async (ctx) => {
    requireAuth(ctx, ['data:write']);
    const { fields, files: uploads } = ctx.multipart;
    if (!uploads?.length) throw badRequest('upload a CSV or JSON file (multipart field "file")');
    const up = uploads[0];
    if (up.data.length > UPLOAD_MAX) throw badRequest('file exceeds 15MB limit');
    const sniffed = sniffMagic(up.data);
    const name = sanitizeFilename(up.filename);
    const ext = name.split('.').pop().toLowerCase();
    if (!['csv', 'json', 'txt', 'tsv'].includes(ext)) throw badRequest('allowed data formats: .csv, .tsv, .json, .txt');
    const rec = files.put(ctx.tid, up.data, { name, mime: up.contentType, meta: { kind: 'data_source' } });
    const source = db.insert('data_sources', { tenant_id: ctx.tid, name: fields.name || name, format: ext === 'json' ? 'json' : 'csv', file_id: rec.id, rows: countRows(ext, up.data), size: up.data.length, sha256: rec.sha256, created_at: nowIso() });
    bus.publish(TOPICS.dataImported, { tenant_id: ctx.tid, asset: null, source_id: source.id, name: source.name });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'data.imported', resource: 'data_source', resourceId: source.id, detail: { name, rows: source.rows } });
    ctx.respond(201, { source });
  });
  router.delete('/api/v1/data/sources/:id', async (ctx) => {
    requireAuth(ctx, ['data:write']);
    db.remove('data_sources', ctx.tid, ctx.params.id);
    ctx.respond(200, { ok: true });
  });
  router.get('/api/v1/data/sources/:id/preview', async (ctx) => {
    requireAuth(ctx, ['data:read']);
    const source = db.byId('data_sources', ctx.tid, ctx.params.id);
    if (!source) throw notFound('source not found');
    const buf = files.read(ctx.tid, source.file_id);
    let rows = [];
    if (source.format === 'json') { rows = JSON.parse(buf.toString('utf8')); if (!Array.isArray(rows)) rows = [rows]; }
    else { const { parseCsv } = await import('#data/csv'); rows = parseCsv(buf.toString('utf8')).rows; }
    ctx.respond(200, { columns: rows.length ? Object.keys(rows[0]) : [], sample: rows.slice(0, 25), total_rows: rows.length });
  });
  // ---- Data Workbench: run profiling / cleansing / dedup / transform / anomaly ----
  router.post('/api/v1/data/runs', async (ctx) => {
    requireAuth(ctx, ['data:write']);
    const body = validate({
      source_id: V.string({ min: 2, max: 60 }),
      operation: V.enum(['profile', 'cleanse', 'dedupe', 'transform', 'anomaly']),
      options: V.record(V.any()).optional(),
    }, ctx.body);
    const source = db.byId('data_sources', ctx.tid, body.source_id);
    if (!source) throw notFound('source not found');
    const buf = files.read(ctx.tid, source.file_id);
    let rows;
    if (source.format === 'json') { rows = JSON.parse(buf.toString('utf8')); if (!Array.isArray(rows)) rows = [rows]; }
    else { const { parseCsv } = await import('#data/csv'); rows = parseCsv(buf.toString('utf8')).rows; }
    const t0 = Date.now();
    const runBase = { tenant_id: ctx.tid, source_id: source.id, operation: body.operation, options: body.options || {}, input_rows: rows.length, started_at: nowIso() };
    let run;
    if (body.operation === 'profile') {
      const { profile } = await import('#data/profile');
      const result = profile(rows);
      run = db.insert('data_runs', { ...runBase, status: 'COMPLETED', finished_at: nowIso(), duration_ms: Date.now() - t0, result });
    } else if (body.operation === 'anomaly') {
      const { detectAnomalies } = await import('#data/anomaly');
      const result = detectAnomalies(rows, (body.options || {}));
      run = db.insert('data_runs', { ...runBase, status: 'COMPLETED', finished_at: nowIso(), duration_ms: Date.now() - t0, result });
    } else {
      let outRows; let opMeta = null;
      if (body.operation === 'cleanse') {
        const { cleanse } = await import('#data/cleanse');
        const rules = (body.options || {}).rules || [{ column: '*', rule: 'trim' }, { column: '*', rule: 'fill_null', params: { value: '' } }];
        const res = cleanse(rows, rules);
        outRows = res.rows ?? res; opMeta = { changes: res.changes ?? res.applied ?? null };
      } else if (body.operation === 'dedupe') {
        const { dedupe } = await import('#data/dedup');
        const opts = body.options || {};
        const res = dedupe(rows, opts.key_columns || null, { mode: opts.mode || 'exact', threshold: opts.threshold ?? 2 });
        outRows = res.rows; opMeta = { stats: res.stats, duplicates: res.duplicates.slice(0, 100) };
      } else {
        const { transform } = await import('#data/transform');
        const res = transform(rows, (body.options || {}).steps || []);
        outRows = res.rows; opMeta = { lineage: res.lineage };
      }
      const { stringifyCsv } = await import('#data/csv');
      const csv = stringifyCsv(outRows);
      const rec = files.put(ctx.tid, Buffer.from(csv, 'utf8'), { name: `${source.name}.${body.operation}.csv`, mime: 'text/csv', meta: { kind: 'data_run_output', source_id: source.id } });
      run = db.insert('data_runs', { ...runBase, status: 'COMPLETED', finished_at: nowIso(), duration_ms: Date.now() - t0, output_rows: outRows.length, output_file_id: rec.id, output_sha256: rec.sha256, meta: opMeta });
    }
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'data.run', resource: 'data_run', resourceId: run.id, detail: { operation: body.operation, source: source.name, input_rows: run.input_rows, output_rows: run.output_rows ?? null } });
    ctx.respond(201, { run });
  });
  router.get('/api/v1/data/runs', async (ctx) => {
    requireAuth(ctx, ['data:read']);
    const { rows, total } = db.list('data_runs', ctx.tid, { limit: 100 });
    ctx.respond(200, { runs: rows, total });
  });
  router.get('/api/v1/data/runs/:id', async (ctx) => {
    requireAuth(ctx, ['data:read']);
    const run = db.byId('data_runs', ctx.tid, ctx.params.id);
    if (!run) throw notFound('run not found');
    let preview = null;
    if (run.output_file_id) {
      const buf = files.read(ctx.tid, run.output_file_id);
      const { parseCsv } = await import('#data/csv');
      const parsed = parseCsv(buf.toString('utf8'));
      preview = { columns: parsed.headers, sample: parsed.rows.slice(0, 20) };
    }
    ctx.respond(200, { run, preview });
  });
  router.get('/api/v1/data/runs/:id/download', async (ctx) => {
    requireAuth(ctx, ['data:read']);
    const run = db.byId('data_runs', ctx.tid, ctx.params.id);
    if (!run?.output_file_id) throw notFound('run output not found');
    const rec = files.get(ctx.tid, run.output_file_id);
    ctx.respondRaw(200, files.read(ctx.tid, run.output_file_id), 'text/csv', { 'content-disposition': `attachment; filename="${rec.name}"` });
  });

  // ---------------- DOCUMENT VAULT ----------------
  router.get('/api/v1/documents', async (ctx) => {
    requireAuth(ctx, ['documents:read']);
    const { rows, total } = db.list('documents', ctx.tid, { limit: 200 });
    ctx.respond(200, { documents: rows.map(docSummary), total });
  });
  router.post('/api/v1/documents', async (ctx) => {
    requireAuth(ctx, ['documents:write']);
    const { fields, files: uploads } = ctx.multipart;
    if (!uploads?.length) throw badRequest('upload a document (multipart field "file")');
    const up = uploads[0];
    if (up.data.length > UPLOAD_MAX) throw badRequest('document exceeds 15MB limit');
    const name = sanitizeFilename(up.filename);
    const ext = name.split('.').pop().toLowerCase();
    if (!DOC_EXTS.includes(ext)) throw badRequest(`unsupported document type .${ext} (allowed: ${DOC_EXTS.join(', ')})`);
    if (ext === 'txt' && sniffMagic(up.data) && !/^text|json|csv/i.test(up.contentType)) {
      // content/extension mismatch check (upload security)
      throw badRequest('content does not match declared type');
    }
    const rec = files.put(ctx.tid, up.data, { name, mime: up.contentType || 'application/octet-stream', meta: { kind: 'document' } });
    const extraction = extractText(up.data, up.contentType, name);
    const doc = db.insert('documents', {
      tenant_id: ctx.tid, file_id: rec.id, name, mime: up.contentType || 'application/octet-stream',
      size: up.data.length, sha256: rec.sha256,
      extracted_text: (extraction.text || '').slice(0, 2_000_000), text_chars: (extraction.text || '').length,
      extraction_method: extraction.method, extraction_note: extraction.note || null, requires_ocr: !!extraction.requires_ocr,
      extracted_text_sha256: extraction.text ? sha256(extraction.text) : null,
      extracted_at: extraction.text ? nowIso() : null,
      tags: (fields.tags || '').split(',').map((t) => t.trim()).filter(Boolean),
      created_at: nowIso(),
    });
    bus.publish(TOPICS.fileChanged, { tenant_id: ctx.tid, asset: null, document_id: doc.id, name: doc.name, sha256: doc.sha256 });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'document.uploaded', resource: 'document', resourceId: doc.id, detail: { name, sha256: rec.sha256.slice(0, 16) } });
    ctx.respond(201, { document: docSummary(doc) });
  });
  router.get('/api/v1/documents/:id', async (ctx) => {
    requireAuth(ctx, ['documents:read']);
    const doc = db.byId('documents', ctx.tid, ctx.params.id);
    if (!doc) throw notFound('document not found');
    ctx.respond(200, { document: docSummary(doc), text_preview: (doc.extracted_text || '').slice(0, 5000) });
  });
  router.delete('/api/v1/documents/:id', async (ctx) => {
    requireAuth(ctx, ['documents:write']);
    const doc = db.remove('documents', ctx.tid, ctx.params.id);
    files.remove(ctx.tid, doc.file_id);
    ctx.respond(200, { ok: true });
  });
  router.get('/api/v1/documents/:id/verify', async (ctx) => {
    requireAuth(ctx, ['documents:read']);
    const doc = db.byId('documents', ctx.tid, ctx.params.id);
    if (!doc) throw notFound('document not found');
    const result = files.verify(ctx.tid, doc.file_id);
    ctx.respond(200, { integrity_ok: result.ok, expected_sha256: result.expected, actual_sha256: result.actual });
  });
  router.get('/api/v1/documents/:id/download', async (ctx) => {
    requireAuth(ctx, ['documents:read']);
    const doc = db.byId('documents', ctx.tid, ctx.params.id);
    if (!doc) throw notFound('document not found');
    const rec = files.get(ctx.tid, doc.file_id);
    ctx.respondRaw(200, files.read(ctx.tid, doc.file_id), rec.mime, { 'content-disposition': `attachment; filename="${rec.name}"` });
  });

  // ---------------- KNOWLEDGE BASES + AI ----------------
  router.get('/api/v1/kb', async (ctx) => {
    requireAuth(ctx, ['ai:read']);
    const { rows, total } = db.list('kbases', ctx.tid, { limit: 100 });
    ctx.respond(200, { kbs: rows, total });
  });
  router.post('/api/v1/kb', async (ctx) => {
    requireAuth(ctx, ['ai:write']);
    const body = validate({ name: V.string({ min: 2, max: 80 }), document_ids: V.array(V.string({ min: 2, max: 60 }), { max: 100 }) }, ctx.body);
    const { chunkText } = await import('#ai/rag');
    const kb = db.insert('kbases', { tenant_id: ctx.tid, name: body.name, document_ids: body.document_ids, chunks: 0, created_at: nowIso() });
    let count = 0;
    for (const id of body.document_ids) {
      const doc = db.byId('documents', ctx.tid, id);
      if (!doc) throw notFound(`document ${id} not found`);
      const chunks = chunkText(doc.extracted_text || '');
      chunks.forEach((text, i) => { db.insert('kb_chunks', { tenant_id: ctx.tid, kb_id: kb.id, doc_id: doc.id, ordinal: i, text, tokens: text.split(/\s+/).length }); count++; });
    }
    db.store.put('kbases', { ...kb, chunks: count });
    ctx.respond(201, { kb: { ...kb, chunks: count } });
  });
  router.delete('/api/v1/kb/:id', async (ctx) => {
    requireAuth(ctx, ['ai:write']);
    db.remove('kbases', ctx.tid, ctx.params.id);
    for (const chunk of db.store.find('kb_chunks', (c) => c.kb_id === ctx.params.id && c.tenant_id === ctx.tid)) db.store.del('kb_chunks', chunk.id);
    ctx.respond(200, { ok: true });
  });
  /** Grounded Q&A over a knowledge base (BM25 retrieval + provider). */
  router.post('/api/v1/kb/:id/ask', async (ctx) => {
    requireAuth(ctx, ['ai:read']);
    const body = validate({ question: V.string({ min: 3, max: 1000 }) }, ctx.body);
    const kb = db.byId('kbases', ctx.tid, ctx.params.id);
    if (!kb) throw notFound('knowledge base not found');
    const { BM25Index } = await import('#ai/rag');
    const chunks = db.store.find('kb_chunks', (c) => c.tenant_id === ctx.tid && c.kb_id === kb.id);
    if (!chunks.length) throw badRequest('knowledge base is empty — run extraction and indexing first');
    const index = new BM25Index();
    const byId = new Map();
    for (const c of chunks) { index.add(c.id, c.text); byId.set(c.id, c); }
    const hits = index.search(body.question, { limit: 6 });
    const context = hits.map((h) => { const c = byId.get(h.id); return { id: `chunk:${h.id.slice(-8)}`, text: c.text, source: `doc:${(db.byIdGlobal('documents', c.doc_id)?.name || c.doc_id)}`, score: +h.score.toFixed(3) }; });
    const provider = resolveProvider();
    const answer = await provider.complete({ prompt: body.question, context });
    ctx.respond(200, { question: body.question, ...answer, retrieved: context.length, kb: { id: kb.id, name: kb.name, chunks: chunks.length } });
  });
  router.get('/api/v1/ai/providers', async (ctx) => {
    requireAuth(ctx, ['ai:read']);
    const external = !!process.env.MERIDIAN_AI_API_KEY;
    ctx.respond(200, {
      active_provider: resolveProvider().name,
      external_llm_configured: external,
      grounded: true,
      note: external ? 'External LLM configured via MERIDIAN_AI_* environment — answers are grounded with retrieved context.' : 'Using the built-in deterministic grounded-synthesis provider (no external LLM configured). Answers cite evidence chunks and refuse when retrieval is empty.',
    });
  });

  // ---------------- AUTOMATION: RULES ----------------
  router.get('/api/v1/automation/rules', async (ctx) => {
    requireAuth(ctx, ['automation:read']);
    const { rows, total } = db.list('rules', ctx.tid, { limit: 200 });
    ctx.respond(200, { rules: rows, total });
  });
  router.post('/api/v1/automation/rules', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const body = validate({
      name: V.string({ min: 2, max: 80 }),
      trigger: V.object({ type: V.enum(['schedule', 'monitor_event', 'job_completed', 'webhook', 'import', 'file_change', 'manual']), config: V.record(V.any()).optional() }),
      conditions: V.string({ max: 500 }).optional(),
      actions: V.array(V.object({ type: V.string({ min: 2, max: 40 }) }), { min: 1, max: 10 }),
    }, ctx.body);
    // validate condition expression compiles
    if (body.conditions) { const { compileExpression } = await import('#core/expr'); try { compileExpression(body.conditions); } catch (e) { throw badRequest(`invalid condition expression: ${e.message}`); } }
    const rule = db.insert('rules', { tenant_id: ctx.tid, name: body.name, trigger: body.trigger, conditions: body.conditions || null, actions: body.actions, enabled: true, last_fired_at: null, created_at: nowIso() });
    ctx.respond(201, { rule });
  });
  router.patch('/api/v1/automation/rules/:id', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const body = validate({ enabled: V.boolean(), name: V.string({ min: 2, max: 80 }), conditions: V.string({ max: 500 }).optional() }, ctx.body, { partial: true });
    const rule = db.update('rules', ctx.tid, ctx.params.id, body);
    ctx.respond(200, { rule });
  });
  router.delete('/api/v1/automation/rules/:id', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    db.remove('rules', ctx.tid, ctx.params.id);
    ctx.respond(200, { ok: true });
  });
  router.post('/api/v1/automation/rules/:id/test', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const result = await app.automation.fireRule(ctx.params.id, { event: { type: 'manual', test: true } });
    ctx.respond(200, { result });
  });
  router.get('/api/v1/automation/runs', async (ctx) => {
    requireAuth(ctx, ['automation:read']);
    const { rows, total } = db.list('rule_runs', ctx.tid, { limit: 100 });
    ctx.respond(200, { runs: rows, total });
  });

  // ---------------- AUTOMATION: WORKFLOWS + SCHEDULES ----------------
  router.get('/api/v1/automation/workflows', async (ctx) => {
    requireAuth(ctx, ['automation:read']);
    const { rows, total } = db.list('workflows', ctx.tid, { limit: 100 });
    const versions = db.store.find('workflow_versions', (v) => v.tenant_id === ctx.tid);
    ctx.respond(200, { workflows: rows, versions: versions.length, total });
  });
  router.post('/api/v1/automation/workflows', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const body = validate({ name: V.string({ min: 2, max: 80 }), definition: V.object({ steps: V.array(V.any(), { min: 1, max: 50 }) }) }, ctx.body);
    let wf;
    try { wf = saveWorkflow(db, ctx.tid, { name: body.name, definition: body.definition }); }
    catch (e) { throw badRequest(`invalid workflow definition: ${e.message}`); }
    ctx.respond(201, { workflow: wf });
  });
  router.put('/api/v1/automation/workflows/:id', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const body = validate({ name: V.string({ min: 2, max: 80 }), definition: V.object({ steps: V.array(V.any(), { min: 1, max: 50 }) }) }, ctx.body);
    let wf;
    try { wf = saveWorkflow(db, ctx.tid, { id: ctx.params.id, name: body.name, definition: body.definition }); }
    catch (e) { throw badRequest(`invalid workflow definition: ${e.message}`); }
    ctx.respond(200, { workflow: wf });
  });
  router.post('/api/v1/automation/workflows/:id/run', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const run = await runWorkflow(db, ctx.tid, ctx.params.id, { event: { type: 'manual', user: ctx.auth.user.id } }, { requestService: app.requestService, generateReport: app.generateReport });
    ctx.respond(202, { run });
  });
  router.get('/api/v1/automation/workflows/:id/runs', async (ctx) => {
    requireAuth(ctx, ['automation:read']);
    const runs = db.store.find('workflow_runs', (r) => r.tenant_id === ctx.tid && r.workflow_id === ctx.params.id).sort((a, b) => (a.started_at < b.started_at ? 1 : -1)).slice(0, 50);
    ctx.respond(200, { runs });
  });
  router.get('/api/v1/automation/schedules', async (ctx) => {
    requireAuth(ctx, ['automation:read']);
    const { rows, total } = db.list('schedules', ctx.tid, { limit: 100 });
    ctx.respond(200, { schedules: rows, total });
  });
  router.post('/api/v1/automation/schedules', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const body = validate({
      name: V.string({ min: 2, max: 80 }), cron: V.string({ min: 9, max: 60 }),
      rule_id: V.string({ max: 60 }), workflow_id: V.string({ max: 60 }),
    }, ctx.body, { partial: true });
    let cron;
    try { cron = parseCron(body.cron); } catch (e) { throw badRequest(`invalid cron: ${e.message}`); }
    if (!body.rule_id && !body.workflow_id) throw badRequest('schedule requires rule_id or workflow_id');
    const schedule = db.insert('schedules', { tenant_id: ctx.tid, name: body.name, cron: body.cron, rule_id: body.rule_id || null, workflow_id: body.workflow_id || null, enabled: true, next_run_at: nextRun(cron).toISOString(), last_run_at: null, created_at: nowIso() });
    ctx.respond(201, { schedule });
  });
  router.delete('/api/v1/automation/schedules/:id', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    db.remove('schedules', ctx.tid, ctx.params.id);
    ctx.respond(200, { ok: true });
  });

  // ---------------- WEBHOOKS ----------------
  router.post('/api/v1/webhooks', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    const body = validate({ event: V.enum(['monitor_event', 'job_completed', 'finding_created']), url: V.url({ schemes: ['http:', 'https:'] }) }, ctx.body);
    const token = `mwh_${crypto.randomBytes(20).toString('base64url')}`;
    const secret = crypto.randomBytes(24).toString('base64url');
    const rec = db.insert('webhook_endpoints', { tenant_id: ctx.tid, event: body.event, url: body.url, token_hash: sha256(token), secret, enabled: true, created_at: nowIso() });
    ctx.respond(201, { id: rec.id, token, secret, note: 'POST to /api/v1/hooks/{token} to trigger automation; outbound calls sign payloads with HMAC-SHA256 using the secret' });
  });
  router.get('/api/v1/webhooks', async (ctx) => {
    requireAuth(ctx, ['automation:read']);
    const rows = db.store.find('webhook_endpoints', (w) => w.tenant_id === ctx.tid);
    ctx.respond(200, { webhooks: rows.map((w) => ({ ...w, token_hash: undefined, secret: undefined })) });
  });
  router.delete('/api/v1/webhooks/:id', async (ctx) => {
    requireAuth(ctx, ['automation:write']);
    db.remove('webhook_endpoints', ctx.tid, ctx.params.id);
    ctx.respond(200, { ok: true });
  });

  // ---------------- BILLING ----------------
  router.get('/api/v1/billing', async (ctx) => {
    requireAuth(ctx, ['billing:read']);
    const sub = db.store.findOne('subscriptions', (s) => s.tenant_id === ctx.tid && s.status === 'active');
    const { balance, entries } = balanceOf(db, ctx.tid);
    const ledger = db.store.find('credit_ledger', (l) => l.tenant_id === ctx.tid).sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 100);
    ctx.respond(200, { subscription: sub, balance, ledger_entries: entries, ledger, plans: (await import('#app/catalog')).PLANS });
  });
  router.post('/api/v1/billing/subscribe', async (ctx) => {
    requireAuth(ctx, ['billing:write']);
    const body = validate({ plan: V.enum(['free', 'pro', 'business', 'enterprise']) }, ctx.body);
    const { PLANS } = await import('#app/catalog');
    const plan = PLANS.find((p) => p.key === body.plan);
    if (!plan) throw badRequest('unknown plan');
    const existing = db.store.findOne('subscriptions', (s) => s.tenant_id === ctx.tid && s.status === 'active');
    if (existing) db.store.put('subscriptions', { ...existing, status: 'cancelled', ended_at: nowIso() });
    const sub = db.insert('subscriptions', { tenant_id: ctx.tid, plan_key: plan.key, status: 'active', current_period_start: nowIso(), current_period_end: null });
    db.store.put('tenants', { ...db.byIdGlobal('tenants', ctx.tid), plan: plan.key });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'billing.subscribed', resource: 'subscription', resourceId: sub.id, detail: { plan: plan.key } });
    ctx.respond(200, { subscription: sub, note: plan.price_cents ? 'Payment processing is handled by the payment provider adapter, which is not configured in this deployment — the subscription is recorded and grants are applied, but no charge occurs (see docs/LIMITATIONS.md).' : 'Plan activated.' });
  });
  router.get('/api/v1/billing/invoices', async (ctx) => {
    requireAuth(ctx, ['billing:read']);
    const { rows, total } = db.list('invoices', ctx.tid, { limit: 50 });
    ctx.respond(200, { invoices: rows, total });
  });

  // ---------------- NOTIFICATIONS + TASKS ----------------
  router.get('/api/v1/notifications', async (ctx) => {
    requireAuth(ctx, []);
    ctx.respond(200, { notifications: listNotifications(db, ctx.tid, ctx.auth.user.id, { unreadOnly: ctx.query.get('unread') === '1' }) });
  });
  router.post('/api/v1/notifications/:id/read', async (ctx) => {
    requireAuth(ctx, []);
    markRead(db, ctx.tid, ctx.auth.user.id, ctx.params.id);
    ctx.respond(200, { ok: true });
  });
  router.post('/api/v1/notifications/read-all', async (ctx) => {
    requireAuth(ctx, []);
    for (const n of listNotifications(db, ctx.tid, ctx.auth.user.id, { unreadOnly: true })) markRead(db, ctx.tid, ctx.auth.user.id, n.id);
    ctx.respond(200, { ok: true });
  });
  router.get('/api/v1/tasks', async (ctx) => {
    requireAuth(ctx, []);
    const { rows, total } = db.list('tasks', ctx.tid, { limit: 100 });
    ctx.respond(200, { tasks: rows, total });
  });
  router.post('/api/v1/tasks', async (ctx) => {
    requireAuth(ctx, []);
    const body = validate({ title: V.string({ min: 2, max: 200 }), due: V.string({ max: 40 }).optional() }, ctx.body, { partial: true });
    const task = db.insert('tasks', { tenant_id: ctx.tid, title: body.title, status: 'open', source: 'user', due: body.due || null, detail: null, created_at: nowIso() });
    ctx.respond(201, { task });
  });
  router.patch('/api/v1/tasks/:id', async (ctx) => {
    requireAuth(ctx, []);
    const body = validate({ status: V.enum(['open', 'in_progress', 'done', 'cancelled']) }, ctx.body, { partial: true });
    const task = db.update('tasks', ctx.tid, ctx.params.id, body);
    ctx.respond(200, { task });
  });

  // ---------------- SUPPORT ----------------
  router.get('/api/v1/tickets', async (ctx) => {
    requireAuth(ctx, ['support:read']);
    const { rows, total } = db.list('tickets', ctx.tid, { limit: 100 });
    ctx.respond(200, { tickets: rows, total });
  });
  router.post('/api/v1/tickets', async (ctx) => {
    requireAuth(ctx, ['support:write']);
    const body = validate({ subject: V.string({ min: 3, max: 200 }), priority: V.enum(['low', 'normal', 'high', 'urgent']), message: V.string({ min: 5, max: 8000 }) }, ctx.body);
    const ticket = db.insert('tickets', { tenant_id: ctx.tid, user_id: ctx.auth.user.id, subject: body.subject, priority: body.priority || 'normal', status: 'open', created_at: nowIso(), updated_at: nowIso() });
    db.insert('ticket_messages', { tenant_id: ctx.tid, ticket_id: ticket.id, author_id: ctx.auth.user.id, author_name: ctx.auth.user.name, body: body.message, internal: false, created_at: nowIso() });
    ctx.respond(201, { ticket });
  });
  router.get('/api/v1/tickets/:id', async (ctx) => {
    requireAuth(ctx, ['support:read']);
    const ticket = db.byId('tickets', ctx.tid, ctx.params.id);
    if (!ticket) throw notFound('ticket not found');
    const messages = db.store.find('ticket_messages', (m) => m.tenant_id === ctx.tid && m.ticket_id === ticket.id).sort((a, b) => (a.created_at < b.created_at ? -1 : 1));
    ctx.respond(200, { ticket, messages });
  });
  router.post('/api/v1/tickets/:id/messages', async (ctx) => {
    requireAuth(ctx, ['support:write']);
    const body = validate({ message: V.string({ min: 1, max: 8000 }) }, ctx.body);
    const ticket = db.byId('tickets', ctx.tid, ctx.params.id);
    if (!ticket) throw notFound('ticket not found');
    const msg = db.insert('ticket_messages', { tenant_id: ctx.tid, ticket_id: ticket.id, author_id: ctx.auth.user.id, author_name: ctx.auth.user.name, body: body.message, internal: false, created_at: nowIso() });
    db.store.put('tickets', { ...ticket, updated_at: nowIso(), status: ticket.status === 'resolved' ? 'open' : ticket.status });
    bus.publish(TOPICS.ticketUpdated, { tenant_id: ctx.tid, ticket_id: ticket.id });
    ctx.respond(201, { message: msg });
  });
  router.patch('/api/v1/tickets/:id', async (ctx) => {
    requireAuth(ctx, ['support:write']);
    const body = validate({ status: V.enum(['open', 'pending', 'resolved', 'closed']) }, ctx.body, { partial: true });
    const ticket = db.update('tickets', ctx.tid, ctx.params.id, body);
    ctx.respond(200, { ticket });
  });

  // ---------------- AUDIT ----------------
  router.get('/api/v1/audit', async (ctx) => {
    requireAuth(ctx, ['audit:read']);
    const { rows, total } = db.list('audit', ctx.tid, { limit: 200 });
    ctx.respond(200, { entries: rows, total });
  });
  router.get('/api/v1/audit/verify', async (ctx) => {
    requireAuth(ctx, ['audit:read']);
    ctx.respond(200, verifyAuditChain(db.store, ctx.tid));
  });

  // ---------------- ADMIN (platform) ----------------
  router.get('/api/v1/admin/tenants', async (ctx) => {
    requireStaff(ctx);
    const tenants = db.store.find('tenants', () => true);
    ctx.respond(200, { tenants: tenants.map((t) => ({ ...t, users: db.store.count('users', (u) => u.tenant_id === t.id), jobs: db.store.count('jobs', (j) => j.tenant_id === t.id) })) });
  });
  router.patch('/api/v1/admin/tenants/:id', async (ctx) => {
    requireStaff(ctx);
    const body = validate({ status: V.enum(['active', 'suspended']) }, ctx.body, { partial: true });
    const tenant = db.byIdGlobal('tenants', ctx.params.id);
    if (!tenant) throw notFound('tenant not found');
    db.store.put('tenants', { ...tenant, ...body });
    ctx.respond(200, { tenant });
  });
  router.get('/api/v1/admin/jobs', async (ctx) => {
    requireStaff(ctx);
    const jobs = db.store.find('jobs', () => true).sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 200);
    ctx.respond(200, { jobs: jobs.map((j) => ({ id: j.id, tenant_id: j.tenant_id, service_key: j.service_key, state: j.state, error: j.error, created_at: j.created_at })) });
  });
  router.get('/api/v1/admin/system', async (ctx) => {
    requireStaff(ctx);
    ctx.respond(200, {
      version: '1.0.0',
      node: process.version,
      uptime_s: Math.floor(process.uptime()),
      store: db.store.stats(),
      queue_depth: db.store.count('jobs', (j) => j.state === 'QUEUED'),
      scheduler: app.scheduler?.stats || null,
      memory_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
    });
  });
  router.get('/api/v1/admin/audit', async (ctx) => {
    requireStaff(ctx);
    const entries = db.store.find('audit', () => true).sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).slice(0, 300);
    ctx.respond(200, { entries });
  });
  router.get('/api/v1/admin/audit/verify', async (ctx) => {
    requireStaff(ctx);
    ctx.respond(200, verifyAuditChain(db.store, undefined));
  });

  // ---------------- DIAGNOSTICS ----------------
  router.post('/api/v1/support/diagnostics', async (ctx) => {
    requireAuth(ctx, ['support:write']);
    const diagnostics = {
      generated_at: nowIso(),
      platform: { version: '1.0.0', node: process.version, mode: app.config.mode },
      store: db.store.stats(),
      store_recovery: db.store.lastRecovery,
      recent_errors: db.store.find('job_logs', (l) => l.tenant_id === ctx.tid && l.level === 'error').slice(-20),
      open_findings: db.store.count('findings', (f) => f.tenant_id === ctx.tid && f.status === 'open'),
      monitors: db.store.count('monitors', (m) => m.tenant_id === ctx.tid),
      audit_integrity: verifyAuditChain(db.store, ctx.tid),
      configuration_redacted: { data_dir: 'configured', external_llm: !!process.env.MERIDIAN_AI_API_KEY, smtp: 'adapter-not-configured' },
    };
    const buf = Buffer.from(JSON.stringify(diagnostics, null, 2));
    const rec = files.put(ctx.tid, buf, { name: `diagnostics-${Date.now()}.json`, mime: 'application/json', meta: { kind: 'diagnostics' } });
    ctx.respond(200, { diagnostics, download_file_id: rec.id });
  });

  // ---------------- INBOUND WEBHOOKS ----------------
  router.post('/api/v1/hooks/:token', async (ctx) => {
    const token = ctx.params.token;
    const rec = db.store.findOne('webhook_endpoints', (w) => w.token_hash === sha256(token) && w.enabled);
    if (!rec) throw notFound('unknown webhook token');
    bus.publish(TOPICS.webhook, { tenant_id: rec.tenant_id, asset: null, webhook_id: rec.id, event: rec.event, payload: ctx.body, received_at: nowIso() });
    ctx.respond(202, { ok: true, message: 'webhook accepted — matching automation rules are being evaluated' });
  });

  // ---------------- META ----------------
  router.get('/api/v1/health', async (ctx) => {
    ctx.respond(200, { ok: true, version: '1.0.0', time: nowIso(), store_seq: db.store.seq });
  });
}

function requireAuth(ctx, perms) {
  requireAuthMW(perms)(ctx);
}
function requireStaff(ctx) {
  if (!ctx.auth || !ctx.auth.user.is_staff) throw forbidden('platform staff access required');
}
function docSummary(d) {
  return { id: d.id, name: d.name, mime: d.mime, size: d.size, sha256: d.sha256, text_chars: d.text_chars, extraction_method: d.extraction_method, extraction_note: d.extraction_note, requires_ocr: d.requires_ocr, tags: d.tags, extracted_at: d.extracted_at, created_at: d.created_at };
}
function countRows(ext, buf) {
  try {
    if (ext === 'json') { const j = JSON.parse(buf.toString('utf8')); return Array.isArray(j) ? j.length : 1; }
    return parseCsv(buf.toString('utf8')).rows.length;
  } catch { return 0; }
}
