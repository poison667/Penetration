/** Analysis views: data workbench, document vault, AI workspace, automation. */
import React, { useRef, useState } from 'react';
import { api, fmt, upload, DataSource, DataRun, Kb, Workflow, WorkflowRun, Schedule } from '../api';
import { useApp } from '../state';
import { Panel, PageHead, DataTable, StateBadge, Badge, Field, Modal, KV, Tabs, useAsync, Err, CodeBlock, EmptyGate } from '../ui';

/* ----------------------------- Data workbench ---------------------------- */
const OPS = [
  { key: 'profile', label: 'Profile', desc: 'Column types, nulls, distincts, top values' },
  { key: 'cleanse', label: 'Cleanse', desc: 'Trim, normalize whitespace, fix types' },
  { key: 'dedupe', label: 'Dedupe', desc: 'Remove duplicate rows by key columns' },
  { key: 'transform', label: 'Transform', desc: 'Rename, select, derive columns' },
  { key: 'anomaly', label: 'Anomaly', desc: 'Statistical outliers (MAD / IQR)' },
];

export function DataView() {
  const { toast } = useApp();
  const sources = useAsync(() => api<{ sources: DataSource[] }>('/api/v1/data/sources'), []);
  const runs = useAsync(() => api<{ runs: DataRun[] }>('/api/v1/data/runs?limit=100'), []);
  const fileRef = useRef<HTMLInputElement>(null);
  const [runFor, setRunFor] = useState<DataSource | null>(null);
  const [op, setOp] = useState('profile');
  const [opParams, setOpParams] = useState<Record<string, unknown>>({});
  const [preview, setPreview] = useState<any>(null);

  const doUpload = async (file: File) => {
    try { await upload('/api/v1/data/sources', file, { name: file.name }); toast(`Uploaded ${file.name}`); sources.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const runOp = async () => {
    if (!runFor) return;
    const opts: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(opParams)) {
      if (typeof v === 'string' && (v.trim().startsWith('[') || v.trim().startsWith('{'))) {
        try { opts[k] = JSON.parse(v); } catch { toast(`${k}: invalid JSON`, 'err'); return; }
      } else opts[k] = v;
    }
    try {
      const j = await api<{ run: DataRun }>('/api/v1/data/runs', { method: 'POST', body: { source_id: runFor.id, operation: op, options: opts } });
      toast('Run completed'); setRunFor(null); runs.refresh();
      
    } catch (e: any) { toast(e.message, 'err'); }
  };
  const showPreview = async (s: DataSource) => {
    try { const j = await api<{ columns: string[]; sample: any[]; total_rows: number }>(`/api/v1/data/sources/${s.id}/preview`); setPreview(j); }
    catch (e: any) { toast(e.message, 'err'); }
  };

  return (
    <>
      <PageHead title="Data workbench" desc="Profile, cleanse, deduplicate, transform and detect anomalies in real datasets."
        actions={<><input ref={fileRef} type="file" accept=".csv,.json,.txt,.xlsx" style={{ display: 'none' }} onChange={(e) => e.target.files?.[0] && void doUpload(e.target.files[0])} /><button className="primary" onClick={() => fileRef.current?.click()}>Upload dataset</button></>} />
      <Err error={sources.error} />
      <Panel title="Datasets" pad={false}>
        <DataTable
          rows={sources.data?.sources}
          loading={sources.loading}
          empty="Upload a CSV/XLSX/JSON file to begin."
          cols={[
            { key: 'name', label: 'Dataset' },
            { key: 'kind', label: 'Kind', render: (s: any) => <Badge tone="plain">{s.kind}</Badge> },
            { key: 'rows', label: 'Rows', className: 'num', render: (s: any) => fmt.num(s.rows) },
            { key: 'cols', label: 'Columns', className: 'num', render: (s: any) => fmt.num(s.columns) },
            { key: 'size', label: 'Size', className: 'num', render: (s: any) => fmt.bytes(s.size_bytes) },
            { key: 'created', label: 'Uploaded', render: (s) => fmt.dt(s.created_at) },
            { key: 'act', label: '', render: (s) => (
              <span style={{ display: 'flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                <button className="sm" onClick={() => void showPreview(s)}>Preview</button>
                <button className="sm primary" onClick={() => { setRunFor(s); setOpParams({}); }}>Run</button>
                <button className="sm danger" onClick={async () => { try { await api(`/api/v1/data/sources/${s.id}`, { method: 'DELETE' }); toast('Deleted'); sources.refresh(); } catch (e: any) { toast(e.message, 'err'); } }}>Delete</button>
              </span>
            ) },
          ]}
        />
      </Panel>
      <Panel title="Runs" pad={false}>
        <DataTable
          rows={runs.data?.runs}
          loading={runs.loading}
          empty="No operations run yet."
          cols={[
            { key: 'op', label: 'Operation', render: (r) => <Badge tone="accent">{r.operation}</Badge> },
            { key: 'src', label: 'Dataset', render: (r: any) => sources.data?.sources.find((s) => s.id === r.source_id)?.name || r.source_id.slice(0, 10) + '…' },
            { key: 'state', label: 'State', render: (r: any) => <StateBadge s={r.status || r.state} /> },
            { key: 'stats', label: 'Result', render: (r: any) => r.result || r.meta ? <span style={{ fontSize: 11.5 }}>{fmt.trunc(JSON.stringify(r.result || r.meta), 80)}</span> : (r.error || '—') },
            { key: 'created', label: 'When', render: (r) => fmt.dt(r.created_at) },
            { key: 'act', label: '', render: (r) => r.output_file_id ? <a href={`/api/v1/data/runs/${r.id}/download`} onClick={(e) => e.stopPropagation()} target="_blank" rel="noreferrer">Download</a> : null },
          ]}
        />
      </Panel>
      {runFor && (
        <Modal title={`Run operation — ${runFor.name}`} onClose={() => setRunFor(null)} footer={<><button className="ghost" onClick={() => setRunFor(null)}>Cancel</button><button className="primary" onClick={runOp}>Run {op}</button></>}>
          {OPS.map((o) => (
            <label key={o.key} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '8px 6px', borderRadius: 4, cursor: 'pointer', background: op === o.key ? 'var(--accent-weak)' : 'transparent', marginBottom: 4, fontWeight: 400 }}>
              <input type="radio" checked={op === o.key} onChange={() => setOp(o.key)} style={{ width: 'auto', marginTop: 3 }} />
              <span><b>{o.label}</b><div style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>{o.desc}</div></span>
            </label>
          ))}
          <div className="section-label">Options</div>
          {op === 'dedupe' && <Field label="Key columns" help="Comma-separated column names identifying a duplicate. Empty = derive from the data."><input value={String(opParams.key_columns ?? '')} onChange={(e) => setOpParams({ key_columns: e.target.value })} placeholder="email, name" /></Field>}
          {op === 'dedupe' && <div className="form-row">
            <Field label="Mode"><select value={String(opParams.mode ?? 'exact')} onChange={(e) => setOpParams({ ...opParams, mode: e.target.value })}>{['exact', 'normalized', 'fuzzy'].map((m) => <option key={m}>{m}</option>)}</select></Field>
            <Field label="Fuzzy threshold"><input value={String(opParams.threshold ?? '2')} onChange={(e) => setOpParams({ ...opParams, threshold: Number(e.target.value) || 2 })} inputMode="numeric" /></Field>
          </div>}
          {op === 'cleanse' && <Field label="Rules (JSON array)" help='Each rule: {"column": "*", "rule": "trim" | "fill_null" | …}. Leave empty for the sensible default set.'><textarea value={String(opParams.rules ?? '')} onChange={(e) => setOpParams({ ...opParams, rules: e.target.value })} placeholder={'[{"column":"*","rule":"trim"}]'} /></Field>}
          {op === 'transform' && <Field label="Steps (JSON array)" help='Each step: {"op": "rename", "from": "old", "to": "new"} — ops: rename, select, drop, derive…'><textarea value={String(opParams.steps ?? '')} onChange={(e) => setOpParams({ ...opParams, steps: e.target.value })} placeholder={'[{"op":"rename","from":"score","to":"risk_score"}]'} /></Field>}
          {op === 'anomaly' && <div className="form-row">
            <Field label="z-score threshold"><input value={String(opParams.zThreshold ?? '3')} onChange={(e) => setOpParams({ ...opParams, zThreshold: Number(e.target.value) || 3 })} inputMode="numeric" /></Field>
            <Field label="IQR multiplier"><input value={String(opParams.iqrMultiplier ?? '1.5')} onChange={(e) => setOpParams({ ...opParams, iqrMultiplier: Number(e.target.value) || 1.5 })} inputMode="numeric" /></Field>
          </div>}
          {op === 'profile' && <div className="notice">Profiling computes per-column types, nulls, distincts and top values — no options needed.</div>}
        </Modal>
      )}
      {preview && (
        <Modal title={`Preview — ${preview.total_rows} rows`} wide onClose={() => setPreview(null)}>
          <div className="tbl-wrap" style={{ maxHeight: '50vh' }}>
            <table className="tbl">
              <thead><tr>{preview.columns.map((c: string) => <th key={c}>{c}</th>)}</tr></thead>
              <tbody>
                {preview.sample.map((row: any, i: number) => <tr key={i}>{preview.columns.map((c: string) => <td key={c}>{String(row[c] ?? '—')}</td>)}</tr>)}
              </tbody>
            </table>
          </div>
        </Modal>
      )}
    </>
  );
}

/* ----------------------------- Document vault ---------------------------- */
export function DocumentsView() {
  const { toast } = useApp();
  const docs = useAsync(() => api<{ documents: any[] }>('/api/v1/documents'), []);
  const fileRef = useRef<HTMLInputElement>(null);
  const [sel, setSel] = useState<any>(null);
  const detail = useAsync(() => sel ? api<{ document: any; text_preview: string }>(`/api/v1/documents/${sel.id}`) : Promise.resolve(null), [sel]);
  const uploadDoc = async (file: File) => {
    try { await upload('/api/v1/documents', file, { name: file.name }); toast(`Stored ${file.name}`); docs.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const verify = async (d: any) => {
    try { const j = await api<{ integrity_ok: boolean; expected_sha256: string; actual_sha256: string }>(`/api/v1/documents/${d.id}/verify`); toast(j.integrity_ok ? 'Integrity verified' : 'INTEGRITY MISMATCH', j.integrity_ok ? 'ok' : 'err'); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const extract = async (d: any) => {
    try {
      const j = await api<{ document: any; text_preview: string; ocr: { engine: string } | null }>(`/api/v1/documents/${d.id}/extract`, { method: 'POST', body: {} });
      toast(j.ocr ? `Extracted via ${j.ocr.engine}: ${j.document.text_chars} chars` : `Extraction (${j.document.extraction_method}): ${j.document.text_chars} chars`);
      docs.refresh();
      if (sel?.id === d.id) detail.refresh();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <>
      <PageHead title="Document vault" desc="Text extraction, integrity verification and comparison. Images run through a real OCR engine when one is available (probed at runtime) — otherwise the status is reported honestly, never fabricated."
        actions={<><input ref={fileRef} type="file" style={{ display: 'none' }} onChange={(e) => e.target.files?.[0] && void uploadDoc(e.target.files[0])} /><button className="primary" onClick={() => fileRef.current?.click()}>Upload document</button></>} />
      <Err error={docs.error} />
      <Panel pad={false}>
        <DataTable
          rows={docs.data?.documents}
          loading={docs.loading}
          empty="Upload PDFs, text files or documents to extract and compare."
          cols={[
            { key: 'name', label: 'Document' },
            { key: 'kind', label: 'Type', render: (d: any) => <Badge tone="plain">{d.kind || d.mime || '—'}</Badge> },
            { key: 'method', label: 'Extraction', render: (d: any) => d.extraction_method ? <Badge tone={d.extraction_method === 'requires_ocr' ? 'warn' : 'ok'}>{d.extraction_method}</Badge> : '—' },
            { key: 'sha', label: 'sha256', render: (d: any) => <span className="mono" style={{ fontSize: 10.5 }}>{d.sha256?.slice(0, 18)}…</span> },
            { key: 'created', label: 'Uploaded', render: (d: any) => fmt.dt(d.created_at) },
            { key: 'act', label: '', render: (d: any) => (
              <span style={{ display: 'flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                <button className="sm" onClick={() => void extract(d)}>Extract</button>
                <button className="sm" onClick={() => void verify(d)}>Verify</button>
                <button className="sm" onClick={() => setSel(d)}>Open</button>
              </span>
            ) },
          ]}
        />
      </Panel>
      {sel && (
        <Modal title={sel.name || sel.id} wide onClose={() => setSel(null)}>
          <KV rows={[
            ['Document id', <span className="mono">{sel.id}</span>],
            ['sha256', <span className="mono">{(detail.data as any)?.document?.sha256 || sel.sha256}</span>],
            ['Extraction method', (detail.data as any)?.document?.extraction_method || '—'],
            ['Size', fmt.bytes((detail.data as any)?.document?.size_bytes || sel.size_bytes)],
            ...((detail.data as any)?.document?.extraction_note ? [['Note', (detail.data as any).document.extraction_note] as [string, React.ReactNode]] : []),
          ]} />
          <div className="section-label">Extracted text</div>
          {(detail.data as any)?.text_preview ? <CodeBlock text={(detail.data as any).text_preview} /> : <div className="empty">No text extracted yet — run Extract (images are read by a real OCR engine when available; absence or failure is reported, never fabricated).</div>}
          <div style={{ marginTop: 10 }}>
            <a href={`/api/v1/documents/${sel.id}/download`} target="_blank" rel="noreferrer">Download original</a>
          </div>
        </Modal>
      )}
    </>
  );
}

/* ------------------------------ AI workspace ----------------------------- */
export function AiView() {
  const { toast } = useApp();
  const providers = useAsync(() => api<any>('/api/v1/ai/providers'), []);
  const kbs = useAsync(() => api<{ kbs: Kb[] }>('/api/v1/kb'), []);
  const docs = useAsync(() => api<{ documents: any[] }>('/api/v1/documents'), []);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [picked, setPicked] = useState<string[]>([]);
  const [askFor, setAskFor] = useState<Kb | null>(null);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<any>(null);
  const createKb = async () => {
    try { await api('/api/v1/kb', { method: 'POST', body: { name, document_ids: picked } }); toast('Knowledge base created'); setCreating(false); setName(''); setPicked([]); kbs.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const ask = async () => {
    if (!askFor || !question.trim()) return;
    try { const j = await api<any>(`/api/v1/kb/${askFor.id}/ask`, { method: 'POST', body: { question } }); setAnswer(j); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <>
      <PageHead title="AI workspace" desc="Grounded analysis over knowledge bases. Answers cite retrieved evidence; nothing is fabricated."
        actions={<button className="primary" onClick={() => setCreating(true)}>New knowledge base</button>} />
      <div className="grid cols-3">
        <Panel title="AI providers">
          <KV rows={(Array.isArray(providers.data) ? providers.data : (providers.data?.providers || [])).map((p: any, i: number) => [
            p.name || p.key || `provider ${i}`, <Badge tone={p.available || p.active ? 'ok' : 'plain'}>{p.available || p.active ? 'active' : 'not configured'}</Badge>,
          ])} />
          <div className="notice" style={{ marginTop: 10 }}>The default provider is a deterministic, evidence-grounded retriever. External LLMs plug in via configuration — the platform never lets any provider originate measurements.</div>
        </Panel>
        <div className="grid" style={{ gridTemplateColumns: '1fr' }}>
          <Panel title="Knowledge bases" pad={false}>
            <DataTable
              rows={kbs.data?.kbs}
              loading={kbs.loading}
              empty="Create a knowledge base from uploaded documents."
              cols={[
                { key: 'name', label: 'Knowledge base' },
                { key: 'chunks', label: 'Chunks', className: 'num', render: (k: any) => fmt.num(k.chunks) },
                { key: 'created', label: 'Created', render: (k) => fmt.dt(k.created_at) },
                { key: 'act', label: '', render: (k) => <button className="sm primary" onClick={() => { setAskFor(k); setAnswer(null); setQuestion(''); }}>Ask</button> },
              ]}
            />
          </Panel>
        </div>
      </div>
      {creating && (
        <Modal title="New knowledge base" onClose={() => setCreating(false)} footer={<><button className="ghost" onClick={() => setCreating(false)}>Cancel</button><button className="primary" onClick={createKb} disabled={!name || !picked.length}>Create</button></>}>
          <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Q3 audit references" /></Field>
          <Field label="Documents" help="Text is chunked and indexed with BM25 for grounded retrieval.">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {(docs.data?.documents || []).map((d: any) => (
                <label key={d.id} style={{ display: 'flex', gap: 8, fontWeight: 400 }}>
                  <input type="checkbox" checked={picked.includes(d.id)} onChange={(e) => setPicked(e.target.checked ? [...picked, d.id] : picked.filter((x) => x !== d.id))} style={{ width: 'auto' }} />
                  {d.name || d.id}
                </label>
              ))}
              {!docs.data?.documents?.length && <EmptyGate>No documents yet — upload some in the document vault first.</EmptyGate>}
            </div>
          </Field>
        </Modal>
      )}
      {askFor && (
        <Modal title={`Ask — ${askFor.name}`} wide onClose={() => setAskFor(null)}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Ask a question answerable from the indexed documents…" onKeyDown={(e) => e.key === 'Enter' && void ask()} />
            <button className="primary" onClick={ask} disabled={!question.trim()}>Ask</button>
          </div>
          {answer && (
            <div style={{ marginTop: 14 }}>
              {answer.grounded === false && <div className="notice warn">The provider could not ground an answer in the indexed evidence.</div>}
              <div className="fact-block facts" style={{ borderLeftColor: 'var(--accent)' }}>
                <div className="lbl">Answer {answer.grounded ? '· grounded' : ''}</div>
                <div>{answer.answer || answer.text}</div>
              </div>
              {answer.citations?.length ? (
                <>
                  <div className="section-label">Citations</div>
                  {answer.citations.map((c: any, i: number) => (
                    <div key={i} className="fact-block" style={{ borderLeftColor: 'var(--border-strong)', fontSize: 11.5 }}>
                      <span className="mono">{c.document_id?.slice(0, 12) || 'doc'}…</span> — {c.excerpt || c.text}
                    </div>
                  ))}
                </>
              ) : null}
              {answer.retrieved != null && <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-faint)' }}>{answer.retrieved} chunk(s) retrieved</div>}
            </div>
          )}
        </Modal>
      )}
    </>
  );
}

/* ------------------------------- Automation ------------------------------ */
export function AutomationView() {
  const { toast } = useApp();
  const [tab, setTab] = useState('workflows');
  const workflows = useAsync(() => api<{ workflows: Workflow[] }>('/api/v1/automation/workflows'), []);
  const schedules = useAsync(() => api<{ schedules: Schedule[] }>('/api/v1/automation/schedules'), []);
  const runs = useAsync(() => api<{ runs: WorkflowRun[] }>('/api/v1/automation/runs?limit=100'), []);
  const [wfEditor, setWfEditor] = useState<{ existing?: Workflow } | null>(null);
  const [schedCreator, setSchedCreator] = useState(false);

  const runWf = async (w: Workflow) => {
    try { await api(`/api/v1/automation/workflows/${w.id}/run`, { method: 'POST', body: {} }); toast('Workflow started'); setTimeout(() => runs.refresh(), 600); }
    catch (e: any) { toast(e.message, 'err'); }
  };

  return (
    <>
      <PageHead title="Automation" desc="Versioned workflows, cron schedules and event rules driving real platform actions." />
      <Tabs tabs={[{ key: 'workflows', label: 'Workflows' }, { key: 'runs', label: 'Runs' }, { key: 'schedules', label: 'Schedules' }]} active={tab} onPick={setTab} />
      {tab === 'workflows' && (
        <Panel pad={false} title="">
          <DataTable
            rows={workflows.data?.workflows}
            loading={workflows.loading}
            empty="No workflows defined."
            cols={[
              { key: 'name', label: 'Workflow' },
              { key: 'v', label: 'Version', render: (w: any) => <Badge tone="plain">v{w.version}</Badge> },
              { key: 'steps', label: 'Steps', className: 'num', render: (w: any) => w.definition?.steps?.length ?? '—' },
              { key: 'updated', label: 'Updated', render: (w: any) => fmt.dt(w.updated_at || w.created_at) },
              { key: 'act', label: '', render: (w: any) => (
                <span style={{ display: 'flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                  <button className="sm primary" onClick={() => void runWf(w)}>Run now</button>
                  <button className="sm" onClick={() => setWfEditor({ existing: w })}>Edit</button>
                </span>
              ) },
            ]}
          />
          <div style={{ padding: 12, borderTop: '1px solid var(--border)' }}>
            <button className="primary" onClick={() => setWfEditor({})}>New workflow</button>
          </div>
        </Panel>
      )}
      {tab === 'runs' && (
        <Panel pad={false}>
          <DataTable
            rows={runs.data?.runs}
            loading={runs.loading}
            empty="No automation runs yet."
            rowKey={(r, i) => r.id || String(i)}
            cols={[
              { key: 'wf', label: 'Workflow', render: (r: any) => workflows.data?.workflows.find((w) => w.id === r.workflow_id)?.name || r.workflow_id?.slice(0, 10) + '…' },
              { key: 'state', label: 'State', render: (r) => <StateBadge s={r.state} /> },
              { key: 'steps', label: 'Steps', render: (r: any) => (r.step_states || []).map((s: any) => <span key={s.step_id} title={`${s.step_id}: ${s.state}`} style={{ display: 'inline-block', width: 10, height: 10, borderRadius: 2, marginRight: 3, background: s.state === 'succeeded' ? 'var(--ok)' : s.state === 'failed' ? 'var(--danger)' : 'var(--border-strong)' }} />) },
              { key: 'started', label: 'Started', render: (r: any) => fmt.dt(r.started_at) },
              { key: 'err', label: 'Error', render: (r: any) => r.error ? <span style={{ color: 'var(--danger)' }}>{fmt.trunc(r.error, 50)}</span> : '—' },
            ]}
          />
        </Panel>
      )}
      {tab === 'schedules' && (
        <Panel pad={false}>
          <DataTable
            rows={schedules.data?.schedules}
            loading={schedules.loading}
            empty="No schedules yet."
            rowKey={(s, i) => s.id || String(i)}
            cols={[
              { key: 'cron', label: 'Cron', render: (s: any) => <span className="mono">{s.cron}</span> },
              { key: 'target', label: 'Runs', render: (s: any) => s.workflow_id ? `workflow ${workflows.data?.workflows.find((w) => w.id === s.workflow_id)?.name || '…'}` : `rule ${s.rule_id?.slice(0, 10)}…` },
              { key: 'enabled', label: 'Enabled', render: (s: any) => <StateBadge s={s.enabled ? 'active' : 'paused'} /> },
              { key: 'next', label: 'Next run', render: (s: any) => fmt.dt(s.next_run_at) },
              { key: 'last', label: 'Last run', render: (s: any) => fmt.dt(s.last_run_at) },
            ]}
          />
          <div style={{ padding: 12, borderTop: '1px solid var(--border)' }}>
            <button className="primary" onClick={() => setSchedCreator(true)}>New schedule</button>
          </div>
        </Panel>
      )}
      {wfEditor && <WorkflowEditor existing={wfEditor.existing} onClose={() => setWfEditor(null)} onSaved={() => { setWfEditor(null); workflows.refresh(); }} />}
      {schedCreator && <ScheduleCreator workflows={workflows.data?.workflows || []} onClose={() => setSchedCreator(false)} onSaved={() => { setSchedCreator(false); schedules.refresh(); }} />}
    </>
  );
}

const WF_TEMPLATE = {
  name: 'New workflow',
  definition: {
    steps: [
      { id: 'step1', type: 'notify', title: 'Automation ran', body: 'Hello from Meridian automation' },
    ],
  },
};

function WorkflowEditor({ existing, onClose, onSaved }: { existing?: Workflow; onClose: () => void; onSaved: () => void }) {
  const { toast } = useApp();
  const [text, setText] = useState(JSON.stringify(existing ? { name: existing.name, definition: existing.definition } : WF_TEMPLATE, null, 2));
  const save = async () => {
    let parsed: any;
    try { parsed = JSON.parse(text); } catch (e: any) { toast(`Invalid JSON: ${e.message}`, 'err'); return; }
    try {
      if (existing) await api(`/api/v1/automation/workflows/${existing.id}`, { method: 'PUT', body: parsed });
      else await api('/api/v1/automation/workflows', { method: 'POST', body: parsed });
      toast('Workflow saved'); onSaved();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <Modal title={existing ? `Edit workflow — ${existing.name}` : 'New workflow'} wide onClose={onClose}
      footer={<><button className="ghost" onClick={onClose}>Cancel</button><button className="primary" onClick={save}>Save</button></>}>
      <div className="notice">Step types: <code>service</code> (run a catalog service), <code>notify</code>, <code>condition</code>, <code>api_call</code>, <code>delay</code>, <code>report</code>. Definitions are validated at save time.</div>
      <textarea value={text} onChange={(e) => setText(e.target.value)} style={{ minHeight: 300 }} />
    </Modal>
  );
}

function ScheduleCreator({ workflows, onClose, onSaved }: { workflows: Workflow[]; onClose: () => void; onSaved: () => void }) {
  const { toast } = useApp();
  const [cron, setCron] = useState('0 6 * * 1');
  const [wfId, setWfId] = useState(workflows[0]?.id || '');
  const create = async () => {
    try { await api('/api/v1/automation/schedules', { method: 'POST', body: { cron, workflow_id: wfId } }); toast('Schedule created'); onSaved(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <Modal title="New schedule" onClose={onClose} footer={<><button className="ghost" onClick={onClose}>Cancel</button><button className="primary" onClick={create} disabled={!wfId}>Create</button></>}>
      <Field label="Workflow">
        <select value={wfId} onChange={(e) => setWfId(e.target.value)}>
          {workflows.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
        </select>
      </Field>
      <Field label="Cron expression" help="Standard 5-field cron: minute hour day month weekday.">
        <input value={cron} onChange={(e) => setCron(e.target.value)} className="mono" />
      </Field>
    </Modal>
  );
}
