import { parseCsv, stringifyCsv } from '#data/csv';
import { profile } from '#data/profile';
import { cleanse } from '#data/cleanse';
import { dedupe } from '#data/dedup';
import { transform } from '#data/transform';
import { detectAnomalies } from '#data/anomaly';
import { extractText } from '#docint/extract';
import { compareDocuments } from '#docint/diff';
import { chunkText, BM25Index } from '#ai/rag';
import { assessReadiness } from '#ai/readiness';
import { resolveProvider } from '#ai/providers';
import { sha256 } from '#core/util';
import { notFound, badRequest } from '#core/errors';

/** Service adapters for data / document / AI services. */

function loadSourceRows(db, files, tenantId, sourceId) {
  const source = db.byId('data_sources', tenantId, sourceId);
  if (!source) throw notFound('data source not found');
  const buf = files.read(tenantId, source.file_id);
  if (source.format === 'json') {
    let rows = JSON.parse(buf.toString('utf8'));
    if (!Array.isArray(rows)) rows = [rows];
    return { source, rows };
  }
  const { rows } = parseCsv(buf.toString('utf8'));
  return { source, rows };
}

export async function runDataService(db, files, job, service, params) {
  if (!params.source_id) throw badRequest('data services require source_id');
  const { source, rows } = loadSourceRows(db, files, job.tenant_id, params.source_id);
  let result;
  switch (service.key) {
    case 'data_profile': {
      const stats = profile(rows);
      result = { kind: 'profile', stats, rows: rows.length };
      break;
    }
    case 'data_cleanse': {
      const rules = params.rules || [{ column: '*', rule: 'trim' }, { column: '*', rule: 'strip_html' }];
      const out = cleanse(rows, rules);
      result = { kind: 'cleanse', ...out.stats, changes: out.changes.slice(0, 1000) };
      var outputRows = out.rows;
      break;
    }
    case 'data_dedup': {
      const keys = String(params.keys || '').split(',').map((s) => s.trim()).filter(Boolean);
      const out = dedupe(rows, keys, { mode: params.mode || 'exact', threshold: 2 });
      result = { kind: 'dedup', ...out.stats, duplicates: out.duplicates.slice(0, 500) };
      var outputRows = out.rows;
      break;
    }
    case 'data_transform': {
      const steps = params.steps || [];
      const out = transform(rows, steps);
      result = { kind: 'transform', lineage: out.lineage, rows: out.rows.length };
      var outputRows = out.rows;
      break;
    }
    case 'data_anomaly': {
      const out = detectAnomalies(rows);
      result = { kind: 'anomaly', anomalies: out.anomalies.slice(0, 1000), anomaly_count: out.anomalies.length, column_stats: out.column_stats, analyzed_columns: out.analyzed_columns };
      var outputRows = rows;
      break;
    }
    default: throw badRequest(`unknown data service: ${service.key}`);
  }
  // persist output dataset + run record
  let output = null;
  if (outputRows) {
    const csv = Buffer.from(stringifyCsv(outputRows), 'utf8');
    output = files.put(job.tenant_id, csv, { name: `${service.key}-output-${Date.now()}.csv`, mime: 'text/csv', meta: { kind: 'data_output', source_id: source.id, rows: outputRows.length } });
  }
  const run = db.insert('data_runs', {
    tenant_id: job.tenant_id, job_id: job.id, source_id: source.id, kind: service.key,
    config: params, stats: result, output_file_id: output?.id || null,
    state: 'completed', created_at: new Date().toISOString(),
  });
  return { kind: 'data', service: service.key, run_id: run.id, rows: rows.length, output_file_id: output?.id || null, message: `${service.key}: ${rows.length} rows processed`, detail: result };
}

export async function runDocService(db, files, job, service, params) {
  switch (service.key) {
    case 'doc_extract': {
      const doc = db.byId('documents', job.tenant_id, params.document_id);
      if (!doc) throw notFound('document not found');
      const buf = files.read(job.tenant_id, doc.file_id);
      const extraction = extractText(buf, doc.mime, doc.name);
      const text = extraction.text || '';
      const updated = { ...doc, extracted_text: text.slice(0, 2_000_000), text_chars: text.length, extraction_method: extraction.method, extraction_note: extraction.note || null, requires_ocr: !!extraction.requires_ocr, extracted_text_sha256: text ? sha256(text) : null, extracted_at: new Date().toISOString() };
      db.store.put('documents', updated);
      return { kind: 'documents', service: 'doc_extract', document_id: doc.id, method: extraction.method, chars: text.length, requires_ocr: !!extraction.requires_ocr, note: extraction.note || null, message: `Extraction (${extraction.method}): ${text.length} chars` };
    }
    case 'doc_compare': {
      const a = db.byId('documents', job.tenant_id, params.doc_a);
      const b = db.byId('documents', job.tenant_id, params.doc_b);
      if (!a || !b) throw notFound('document not found');
      const result = compareDocuments(a.extracted_text || '', b.extracted_text || '');
      const run = db.insert('data_runs', {
        tenant_id: job.tenant_id, job_id: job.id, source_id: null, kind: 'doc_compare',
        config: { doc_a: a.id, doc_b: b.id }, stats: result.stats, state: 'completed',
      });
      return { kind: 'documents', service: 'doc_compare', run_id: run.id, stats: result.stats, hunks: result.hunks.length, message: `Comparison: similarity ${(result.stats.similarity * 100).toFixed(1)}%` };
    }
    default: throw badRequest(`unknown document service: ${service.key}`);
  }
}

export async function runAiService(db, files, job, service, params, asset) {
  switch (service.key) {
    case 'kb_build': {
      const docIds = String(params.document_ids || '').split(',').map((s) => s.trim()).filter(Boolean);
      const docs = docIds.map((id) => db.byId('documents', job.tenant_id, id)).filter(Boolean);
      if (!docs.length) throw badRequest('no valid documents for knowledge base');
      const kb = db.insert('kbases', { tenant_id: job.tenant_id, name: params.name || 'Knowledge base', document_ids: docs.map((d) => d.id), chunks: 0, created_at: new Date().toISOString() });
      let chunkCount = 0;
      for (const doc of docs) {
        const text = doc.extracted_text || '';
        const chunks = chunkText(text);
        chunks.forEach((text, i) => {
          db.insert('kb_chunks', { tenant_id: job.tenant_id, kb_id: kb.id, doc_id: doc.id, ordinal: i, text, tokens: text.split(/\s+/).length });
          chunkCount++;
        });
      }
      db.store.put('kbases', { ...kb, chunks: chunkCount });
      return { kind: 'ai', service: 'kb_build', kb_id: kb.id, documents: docs.length, chunks: chunkCount, message: `Indexed ${chunkCount} chunks from ${docs.length} documents` };
    }
    case 'ai_readiness': {
      const assessment = assessReadiness(db, job.tenant_id, asset?.id || null);
      return { kind: 'ai', service: 'ai_readiness', assessment, message: `AI readiness: ${assessment.overall_score}/100 (${assessment.classification})` };
    }
    case 'ai_analyze': {
      const finding = db.byId('findings', job.tenant_id, params.finding_id);
      if (!finding) throw notFound('finding not found');
      const evidence = finding.evidence_ids.map((id) => db.byIdGlobal('evidence', id)).filter(Boolean);
      const context = [
        { id: `check:${finding.check_id}`, text: `${finding.title}. ${finding.facts.join(' ')}`, source: 'finding' },
        ...evidence.map((ev, i) => ({ id: `evidence:${ev.id}`, text: summarizeEvidence(ev), source: `evidence:${ev.kind}` })),
      ];
      const provider = resolveProvider();
      const result = await provider.complete({
        prompt: `Explain the security impact and remediation of finding ${finding.fid} (${finding.title}, severity ${finding.severity}).`,
        context,
      });
      const analysis = {
        finding_id: finding.id, fid: finding.fid, provider: result.provider, grounded: true,
        answer: result.answer, citations: result.citations, confidence: result.confidence,
        note: result.note || null, generated_at: new Date().toISOString(),
        disclaimer: 'This analysis is generated from stored evidence records only. It introduces no new measurements.',
      };
      db.store.put('findings', { ...finding, ai_analysis: analysis });
      return { kind: 'ai', service: 'ai_analyze', finding_id: finding.id, analysis, message: `Grounded analysis of ${finding.fid} via ${result.provider}` };
    }
    default: throw badRequest(`unknown AI service: ${service.key}`);
  }
}

function summarizeEvidence(ev) {
  const c = ev.content || {};
  if (c.kind === 'http_exchange') return `HTTP ${c.response?.status} from ${c.request?.url} — headers: ${JSON.stringify(c.response?.headers || {}).slice(0, 300)}; body excerpt: ${String(c.response?.body_excerpt || '').slice(0, 300)}`;
  return `${ev.description}: ${JSON.stringify(c).slice(0, 400)}`;
}
