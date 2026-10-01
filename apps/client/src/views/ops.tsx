/** Operations views: dashboard, jobs, assets, findings, evidence, security, monitoring. */
import React, { useState } from 'react';
import { api, fmt, upload, Job, Finding, Evidence, Asset, Monitor, MonitorCheck, Service } from '../api';
import { useApp } from '../state';
import { Panel, PageHead, Stat, DataTable, SevBadge, StateBadge, Badge, Field, Modal, KV, Chips, Progress, FactBlocks, CodeBlock, useAsync, Err, Dot } from '../ui';
import { SeverityBar } from '../shell';

/* ------------------------------- Dashboard ------------------------------- */
export function DashboardView() {
  const { session, navigate } = useApp();
  const jobs = useAsync(() => api<{ jobs: (Job & { findings_count: number | null })[]; total: number }>('/api/v1/jobs?limit=8'), []);
  const findings = useAsync(() => api<{ findings: Finding[]; total: number }>('/api/v1/findings?limit=200'), []);
  const monitors = useAsync(() => api<{ monitors: Monitor[]; total: number }>('/api/v1/monitors'), []);
  const reports = useAsync(() => api<{ reports: any[]; total: number }>('/api/v1/reports?limit=5'), []);

  const sevCounts: Record<string, number> = {};
  let openCount = 0;
  for (const f of findings.data?.findings || []) {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
    if (f.status === 'open') openCount++;
  }
  const running = (jobs.data?.jobs || []).filter((j) => ['RUNNING', 'ANALYZING', 'QUALITY_CHECK', 'QUEUED', 'VALIDATING', 'REQUESTED', 'RETRYING'].includes(j.state));
  const monitorsDown = (monitors.data?.monitors || []).filter((m) => (m as any).last_status === 'down').length;

  return (
    <>
      <PageHead title={`Welcome, ${session?.user.name?.split(' ')[0] || ''}`} desc="Live position across your audit, security and monitoring programs." />
      <Err error={jobs.error || findings.error} />
      <div className="grid cols-4">
        <Stat k="Open findings" v={fmt.num(openCount)} d={`${findings.data?.total ?? '—'} total recorded`} tone={sevCounts.critical ? 'err' : undefined} />
        <Stat k="Critical / High" v={`${sevCounts.critical || 0} / ${sevCounts.high || 0}`} d="unresolved severity mix" tone={sevCounts.critical ? 'err' : sevCounts.high ? 'warn' : 'ok'} />
        <Stat k="Jobs in flight" v={fmt.num(running.length)} d={`${jobs.data?.total ?? '—'} all-time`} />
        <Stat k="Monitors" v={fmt.num(monitors.data?.total)} d={monitorsDown ? `${monitorsDown} down` : 'all healthy'} tone={monitorsDown ? 'err' : 'ok'} />
      </div>
      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <Panel title="Findings by severity" pad>
          <SeverityBar counts={sevCounts} />
          <div className="kv" style={{ marginTop: 10 }}>
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <React.Fragment key={s}>
                <dt><SevBadge sev={s} /></dt>
                <dd style={{ fontVariantNumeric: 'tabular-nums' }}>{sevCounts[s] || 0}</dd>
              </React.Fragment>
            ))}
          </div>
        </Panel>
        <Panel title="Recent jobs" actions={<a href="#/jobs">View all</a>}>
          <DataTable
            rows={jobs.data?.jobs}
            loading={jobs.loading}
            empty="No jobs yet — request a service from the marketplace."
            cols={[
              { key: 'service', label: 'Service', render: (j) => <span className="mono">{j.service_key}</span> },
              { key: 'state', label: 'State', render: (j) => <StateBadge s={j.state} /> },
              { key: 'findings', label: 'Findings', className: 'num', render: (j: any) => fmt.num(j.findings_count) },
              { key: 'created', label: 'Created', render: (j) => fmt.dt(j.created_at) },
            ]}
            onRow={(j) => navigate(`/jobs/${j.id}`)}
          />
        </Panel>
      </div>
      <div className="grid cols-2">
        <Panel title="Latest reports" actions={<a href="#/reports">View all</a>}>
          <DataTable
            rows={reports.data?.reports}
            loading={reports.loading}
            empty="No reports generated yet."
            cols={[
              { key: 'kind', label: 'Kind', render: (r: any) => r.kind?.replace(/_/g, ' ') },
              { key: 'format', label: 'Format', render: (r: any) => <Badge tone="plain">{r.format.toUpperCase()}</Badge> },
              { key: 'n', label: 'Findings', className: 'num', render: (r: any) => fmt.num(r.findings_count) },
              { key: 'created', label: 'Created', render: (r: any) => fmt.dt(r.created_at) },
            ]}
            onRow={(r: any) => { window.open(`/api/v1/reports/${r.id}/download`, '_blank'); }}
          />
        </Panel>
        <Panel title="Monitors" actions={<a href="#/monitoring">Manage</a>}>
          <DataTable
            rows={monitors.data?.monitors}
            loading={monitors.loading}
            empty="No monitors configured."
            cols={[
              { key: 'name', label: 'Monitor', render: (m) => <span>{(m as any).name || m.url} <span style={{ color: 'var(--text-faint)' }}>({m.type})</span></span> },
              { key: 'enabled', label: 'Enabled', render: (m) => m.enabled ? <Dot tone={(m as any).last_status === 'down' ? 'err' : 'ok'} /> : <Dot tone="idle" /> },
              { key: 'last', label: 'Last status', render: (m: any) => m.last_status ? <StateBadge s={m.last_status} /> : '—' },
              { key: 'checked', label: 'Last run', render: (m: any) => fmt.dt(m.last_run_at) },
              { key: 'next', label: 'Next run', render: (m: any) => fmt.dt(m.next_run_at) },
            ]}
            onRow={() => navigate('/monitoring')}
          />
        </Panel>
      </div>
    </>
  );
}

/* ---------------------------------- Jobs --------------------------------- */
const JOB_STATES = ['ALL', 'REQUESTED', 'VALIDATING', 'QUEUED', 'RUNNING', 'ANALYZING', 'QUALITY_CHECK', 'COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED', 'RETRYING'];

export function JobsView() {
  const { navigate } = useApp();
  const [state, setState] = useState('ALL');
  const jobs = useAsync(() => api<{ jobs: (Job & { findings_count: number | null })[]; total: number }>(`/api/v1/jobs?limit=100${state !== 'ALL' ? `&state=${state}` : ''}`), [state]);
  const [tick, setTick] = useState(0);
  useAsync(() => api('/api/v1/health').catch(() => null), [tick]);
  React.useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <>
      <PageHead title="Jobs" desc="Every execution runs the full pipeline: validation, engines, analysis, quality check, evidence, report history." />
      <div className="toolbar">
        <select value={state} onChange={(e) => setState(e.target.value)}>
          {JOB_STATES.map((s) => <option key={s} value={s}>{s === 'ALL' ? 'All states' : s}</option>)}
        </select>
        <div className="grow" />
        <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>{fmt.num(jobs.data?.total)} jobs</span>
      </div>
      <Err error={jobs.error} />
      <Panel pad={false}>
        <DataTable
          rows={jobs.data?.jobs}
          loading={jobs.loading}
          empty="No jobs match. Request a service from the marketplace."
          cols={[
            { key: 'id', label: 'Job', render: (j) => <span className="mono">{j.id.slice(0, 14)}…</span> },
            { key: 'service', label: 'Service', render: (j) => <span className="mono">{j.service_key}</span> },
            { key: 'state', label: 'State', render: (j) => <><StateBadge s={j.state} /></> },
            { key: 'progress', label: 'Progress', w: 110, render: (j) => j.state === 'COMPLETED' ? <span style={{ color: 'var(--ok)' }}>100%</span> : <Progress pct={j.progress || 0} /> },
            { key: 'findings', label: 'Findings', className: 'num', render: (j: any) => fmt.num(j.findings_count) },
            { key: 'qc', label: 'QC', render: (j: any) => j.qc ? <span title={`${j.qc.evidence_records} evidence records`}>{j.qc.engines_failed ? <Badge tone="err">{j.qc.engines_failed} engines failed</Badge> : <Badge tone="ok">{j.qc.engines_run} engines</Badge>}</span> : '—' },
            { key: 'created', label: 'Created', render: (j) => fmt.dt(j.created_at) },
            { key: 'finished', label: 'Finished', render: (j) => fmt.dt(j.finished_at) },
          ]}
          onRow={(j) => navigate(`/jobs/${j.id}`)}
        />
      </Panel>
    </>
  );
}

function RetestPanel({ runId }: { runId: string }) {
  const { navigate, toast } = useApp();
  const r = useAsync(() => api<{ retest: any }>(`/api/v1/retests/${runId}`), [runId]);
  const rt: any = (r.data as any)?.retest;
  const genReport = async () => {
    try {
      const res = await api<{ report: any }>('/api/v1/reports', { method: 'POST', body: { kind: 'retest_report', retest_id: runId, format: 'pdf' } });
      window.open(`/api/v1/reports/${res.report.id}/download`, '_blank');
    } catch (e: any) { toast(e.message, 'err'); }
  };
  if (r.loading) return <Panel title="Retest verdicts"><div className="loading">Loading verdicts…</div></Panel>;
  if (r.error) return <Err error={r.error} />;
  if (!rt) return null;
  const tone = (v: string) => (v === 'fixed' ? 'ok' : v === 'reproduced' ? 'err' : v === 'new' ? 'accent' : 'warn') as 'ok' | 'err' | 'accent' | 'warn';
  return (
    <Panel title={`Retest verdicts — vs source run ${(rt.source_job_id || '').slice(0, 12)}…`} pad={false}>
      <div style={{ display: 'flex', gap: 18, padding: '14px 16px', flexWrap: 'wrap', alignItems: 'center' }}>
        {[['reproduced', 'still present'], ['fixed', 'fixed'], ['inconclusive', 'inconclusive'], ['new', 'new']].map(([k, label]) => (
          <div key={k} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <Badge tone={tone(k)}>{rt.verdicts?.[k] ?? 0}</Badge>
            <span style={{ fontSize: 12, opacity: 0.75 }}>{label}</span>
          </div>
        ))}
        <div style={{ flex: 1 }} />
        <button className="ghost" onClick={genReport}>Retest report (PDF)</button>
      </div>
      {rt.severity_changes?.length ? (
        <div style={{ padding: '0 16px 10px', fontSize: 12, opacity: 0.8 }}>
          Severity changes: {rt.severity_changes.map((c: any) => `${c.fid} ${c.from}→${c.to}`).join(' · ')}
        </div>
      ) : null}
      <DataTable
        rows={rt.items}
        empty="No verdicts."
        cols={[
          { key: 'fid', label: 'FID', render: (i: any) => <span className="mono">{i.fid}</span> },
          { key: 'verdict', label: 'Verdict', render: (i: any) => <Badge tone={tone(i.verdict)}>{String(i.verdict).toUpperCase()}</Badge> },
          { key: 'sev', label: 'Severity', render: (i: any) => <SevBadge sev={i.severity} /> },
          { key: 'check', label: 'Check', render: (i: any) => <span className="mono">{i.check_id}</span> },
          { key: 'title', label: 'Title' },
          { key: 'ep', label: 'Endpoint', render: (i: any) => <span className="mono" style={{ fontSize: 11 }}>{i.endpoint || '—'}</span> },
        ]}
        onRow={(i: any) => navigate(i.retest_finding_id ? `/findings/${i.retest_finding_id}` : `/findings/${i.source_finding_id}`)}
      />
    </Panel>
  );
}

export function JobDetailView({ id }: { id: string }) {
  const { navigate, toast } = useApp();
  const job = useAsync(() => api<{ job: Job }>(`/api/v1/jobs/${id}`), [id]);
  const findings = useAsync(() => api<{ findings: Finding[] }>(`/api/v1/findings?job_id=${id}&limit=500`), [id]);
  const j: any = (job.data as any)?.job;
  const act = async (path: string, label: string) => {
    try { await api(path, { method: 'POST', body: {} }); toast(label); job.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const doRetest = async () => {
    try {
      const r = await api<{ job: any }>(`/api/v1/jobs/${id}/retest`, { method: 'POST', body: {} });
      toast('Retest queued — verifying fixes');
      navigate(`/jobs/${r.job.id}`);
    } catch (e: any) { toast(e.message, 'err'); }
  };
  if (job.loading) return <div className="loading"><span className="spinner" /> Loading job…</div>;
  if (job.error) return <Err error={job.error} />;

  return (
    <>
      <PageHead
        title={`Job ${j.id.slice(0, 18)}…`}
        desc={`Service ${j.service_key} · lifecycle ${j.state}`}
        actions={<>
          {['RUNNING', 'QUEUED', 'ANALYZING', 'VALIDATING', 'REQUESTED'].includes(j.state) && <button className="danger" onClick={() => act(`/api/v1/jobs/${id}/cancel`, 'Cancel requested')}>Cancel</button>}
          {['FAILED', 'CANCELLED'].includes(j.state) && <button onClick={() => act(`/api/v1/jobs/${id}/retry`, 'Retry requested')}>Retry</button>}
          {['COMPLETED', 'PARTIALLY_COMPLETED'].includes(j.state) && j.asset_id && <button className="primary" onClick={doRetest}>Retest — verify fixes</button>}
          <button className="ghost" onClick={() => navigate('/jobs')}>Back</button>
        </>}
      />
      <div className="grid cols-3">
        <Panel title="Execution">
          <KV rows={[
            ['State', <StateBadge s={j.state} />],
            ['Progress', <Progress pct={j.progress || 0} />],
            ['Created', fmt.dt(j.created_at)],
            ['Started', fmt.dt(j.started_at)],
            ['Finished', fmt.dt(j.finished_at)],
            ['Attempts', String(j.attempts ?? '—')],
          ]} />
        </Panel>
        <Panel title="Quality check">
          <KV rows={[
            ['Engines run', fmt.num(j.qc?.engines_run)],
            ['Engines failed', fmt.num(j.qc?.engines_failed)],
            ['Findings accepted', fmt.num(j.qc?.findings_accepted)],
            ['Findings rejected', fmt.num(j.qc?.findings_rejected)],
            ['Evidence records', fmt.num(j.qc?.evidence_records)],
            ['Requests made', fmt.num((j.qc as any)?.requests_made)],
          ]} />
        </Panel>
        <Panel title="Usage & result">
          <KV rows={[
            ['Credits committed', fmt.num((j.usage as any)?.credits_committed)],
            ['Credits estimated', fmt.num((j.usage as any)?.credits_estimate)],
            ['Findings', fmt.num((j.result_summary as any)?.findings_count)],
            ['Pages fetched', fmt.num((j.result_summary as any)?.pages_fetched)],
            ['Asset', j.asset_id ? <a href={`#/assets`}>{j.asset_id.slice(0, 12)}…</a> : '—'],
          ]} />
        </Panel>
      </div>
      {j.error && <div className="notice err" style={{ marginTop: 14 }}><b>Error:</b> {j.error}</div>}
      {(j.result_summary as any)?.retest?.retest_run_id && <div style={{ marginTop: 14 }}><RetestPanel runId={(j.result_summary as any).retest.retest_run_id} /></div>}
      <Panel title={`Findings (${findings.data?.findings.length ?? 0})`} pad={false} className="">
        <DataTable
          rows={findings.data?.findings}
          loading={findings.loading}
          empty="No findings recorded for this job."
          cols={[
            { key: 'fid', label: 'FID', render: (f) => <span className="mono">{f.fid}</span> },
            { key: 'sev', label: 'Severity', render: (f) => <SevBadge sev={f.severity} /> },
            { key: 'title', label: 'Title' },
            { key: 'check', label: 'Check', render: (f) => <span className="mono">{f.check_id}</span> },
            { key: 'conf', label: 'Confidence', render: (f) => <Badge tone="plain">{f.confidence}</Badge> },
            { key: 'ver', label: 'Verification', render: (f) => <Badge tone={f.verification === 'fixed' ? 'ok' : f.verification === 'reproduced' ? 'err' : 'plain'}>{f.verification}</Badge> },
          ]}
          onRow={(f) => navigate(`/findings/${f.id}`)}
        />
      </Panel>
    </>
  );
}

/* --------------------------------- Assets -------------------------------- */
export function AssetsView() {
  const { toast } = useApp();
  const assets = useAsync(() => api<{ assets: Asset[]; total: number }>('/api/v1/assets?limit=200'), []);
  const [editing, setEditing] = useState<Asset | 'new' | null>(null);
  const save = async (a: Partial<Asset> & { authorization?: any }) => {
    try {
      if (editing === 'new') await api('/api/v1/assets', { method: 'POST', body: a });
      else await api(`/api/v1/assets/${(editing as Asset).id}`, { method: 'PATCH', body: a });
      toast('Asset saved'); setEditing(null); assets.refresh();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <>
      <PageHead title="Assets" desc="Targets you are authorized to assess. Security services require a verified authorization record with explicit scope."
        actions={<button className="primary" onClick={() => setEditing('new')}>Add asset</button>} />
      <Err error={assets.error} />
      <Panel pad={false}>
        <DataTable
          rows={assets.data?.assets}
          loading={assets.loading}
          empty="No assets. Add your first authorized target."
          cols={[
            { key: 'identifier', label: 'Identifier', render: (a) => <span className="mono">{a.identifier}</span> },
            { key: 'title', label: 'Title' },
            { key: 'kind', label: 'Kind', render: (a) => <Badge tone="plain">{a.kind}</Badge> },
            { key: 'auth', label: 'Authorization', render: (a) => a.authorization?.status ? <StateBadge s={a.authorization.status} /> : <Badge tone="err">none</Badge> },
            { key: 'scope', label: 'Scope', render: (a) => <span className="mono" style={{ fontSize: 11 }}>{(a.authorization?.scope_domains || []).join(', ') || '—'}</span> },
            { key: 'status', label: 'Status', render: (a) => <StateBadge s={a.status} /> },
          ]}
          onRow={(a) => setEditing(a)}
        />
      </Panel>
      {editing && <AssetEditor asset={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSave={save} />}
    </>
  );
}

function AssetEditor({ asset, onClose, onSave }: { asset: Asset | null; onClose: () => void; onSave: (a: any) => void }) {
  const [id, setId] = useState(asset?.identifier || '');
  const [kind, setKind] = useState(asset?.kind || 'web_host');
  const [title, setTitle] = useState(asset?.title || '');
  const [port, setPort] = useState('443');
  const [aStatus, setAStatus] = useState(asset?.authorization?.status || 'declared');
  const [domains, setDomains] = useState((asset?.authorization?.scope_domains || []).join(', '));
  const [authorizedBy, setAuthorizedBy] = useState(asset?.authorization?.authorized_by || '');
  const [exclusions, setExclusions] = useState((asset?.authorization?.exclusions || []).join(', '));
  const [allowPrivate, setAllowPrivate] = useState(!!asset?.authorization?.allow_private);
  return (
    <Modal title={asset ? `Edit asset — ${asset.identifier}` : 'Add authorized asset'} onClose={onClose}
      footer={<>
        <button className="ghost" onClick={onClose}>Cancel</button>
        <button className="primary" onClick={() => onSave({
          identifier: id, kind, title, port: Number(port) || 443,
          authorization: {
            status: aStatus, scope_domains: domains.split(',').map((s) => s.trim()).filter(Boolean),
            authorized_by: authorizedBy || 'Asset owner', exclusions: exclusions.split(',').map((s) => s.trim()).filter(Boolean),
            allow_private: allowPrivate,
          },
        })}>{asset ? 'Save changes' : 'Create asset'}</button>
      </>}>
      <div className="form-row">
        <Field label="Identifier" help="Hostname, URL or IP range you are authorized to test."><input value={id} onChange={(e) => setId(e.target.value)} placeholder="https://app.example.com" /></Field>
        <Field label="Kind">
          <select value={kind} onChange={(e) => setKind(e.target.value)}>{['web_host', 'api', 'domain', 'ip_range'].map((k) => <option key={k}>{k}</option>)}</select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Title"><input value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
        <Field label="Port"><input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" /></Field>
      </div>
      <div className="section-label">Authorization record (required for security services)</div>
      <div className="form-row">
        <Field label="Authorization status">
          <select value={aStatus} onChange={(e) => setAStatus(e.target.value)}>{['declared', 'verified', 'expired', 'revoked'].map((s) => <option key={s}>{s}</option>)}</select>
        </Field>
        <Field label="Authorized by"><input value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} placeholder="Name / role of authorizing party" /></Field>
      </div>
      <Field label="Scope domains" help="Comma-separated. Security engines refuse targets outside this scope."><input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="app.example.com, example.com" /></Field>
      <Field label="Exclusions" help="Paths or hosts to skip entirely (e.g. /admin, staging.example.com)."><input value={exclusions} onChange={(e) => setExclusions(e.target.value)} /></Field>
      <Field label="" help="Private/loopback targets are refused unless explicitly allowed here.">
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontWeight: 400 }}>
          <input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} style={{ width: 'auto' }} />
          Allow private/loopback addresses (test targets only)
        </label>
      </Field>
    </Modal>
  );
}

/* -------------------------------- Findings ------------------------------- */
export function FindingsView({ filterSev }: { filterSev?: string }) {
  const { navigate } = useApp();
  const [sev, setSev] = useState(filterSev || 'ALL');
  const [status, setStatus] = useState('open');
  const [q, setQ] = useState('');
  const findings = useAsync(() => api<{ findings: Finding[]; total: number }>(`/api/v1/findings?limit=500${sev !== 'ALL' ? `&severity=${sev}` : ''}${status !== 'ALL' ? `&status=${status}` : ''}`), [sev, status]);
  const rows = (findings.data?.findings || []).filter((f) => !q || `${f.title} ${f.check_id} ${f.fid} ${f.endpoint || ''}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <PageHead title="Findings" desc="Structured, evidence-backed findings. Facts, inference and recommendations are kept separate by design." />
      <div className="toolbar">
        <Chips options={[{ key: 'ALL', label: 'All' }, { key: 'critical', label: 'Critical' }, { key: 'high', label: 'High' }, { key: 'medium', label: 'Medium' }, { key: 'low', label: 'Low' }, { key: 'info', label: 'Info' }]} value={sev} onPick={setSev} />
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 'auto' }}>
          {['open', 'ALL', 'remediated', 'false_positive', 'accepted_risk', 'retest_pending'].map((s) => <option key={s} value={s}>{s === 'ALL' ? 'any status' : s}</option>)}
        </select>
        <input placeholder="Search title, check, endpoint…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 240 }} />
        <div className="grow" />
        <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>{rows.length} shown</span>
      </div>
      <Err error={findings.error} />
      <Panel pad={false}>
        <DataTable
          rows={rows}
          loading={findings.loading}
          empty="No findings match this filter."
          cols={[
            { key: 'fid', label: 'FID', render: (f) => <span className="mono">{f.fid}</span> },
            { key: 'sev', label: 'Sev', render: (f) => <SevBadge sev={f.severity} /> },
            { key: 'title', label: 'Title', render: (f) => <span>{f.title} {f.endpoint && <span style={{ color: 'var(--text-faint)' }}>· {fmt.trunc(f.endpoint, 30)}</span>}</span> },
            { key: 'cat', label: 'Category', render: (f) => f.category_label || f.category },
            { key: 'cwe', label: 'CWE', render: (f) => f.cwe ? <span className="mono">{f.cwe}</span> : '—' },
            { key: 'conf', label: 'Confidence', render: (f) => <Badge tone="plain">{f.confidence}</Badge> },
            { key: 'status', label: 'Status', render: (f) => <StateBadge s={f.status} /> },
            { key: 'ev', label: 'Evidence', className: 'num', render: (f: any) => fmt.num(f.evidence_count) },
            { key: 'det', label: 'Detected', render: (f) => fmt.dt(f.detected_at) },
          ]}
          onRow={(f) => navigate(`/findings/${f.id}`)}
        />
      </Panel>
    </>
  );
}

export function FindingDetailView({ id }: { id: string }) {
  const { navigate, toast } = useApp();
  const detail = useAsync(() => api<{ finding: Finding; evidence: Evidence[] }>(`/api/v1/findings/${id}`), [id]);
  const f = detail.data?.finding as any;
  const [status, setStatus] = useState<string | null>(null);
  const setFStatus = async (s: string) => {
    try { await api(`/api/v1/findings/${id}`, { method: 'PATCH', body: { status: s } }); setStatus(s); toast(`Marked ${s.replace(/_/g, ' ')}`); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  if (detail.loading) return <div className="loading"><span className="spinner" /> Loading finding…</div>;
  if (detail.error) return <Err error={detail.error} />;
  const st = status || f.status;
  return (
    <>
      <PageHead title={f.title} desc={`${f.fid} · ${f.check_id}${f.cwe ? ` · ${f.cwe}` : ''}${f.owasp ? ` · OWASP ${f.owasp}` : ''}`}
        actions={<>
          <SevBadge sev={f.severity} />
          <select value={st} onChange={(e) => void setFStatus(e.target.value)} style={{ width: 150 }}>
            {['open', 'remediated', 'false_positive', 'accepted_risk', 'retest_pending'].map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>
          <button className="ghost" onClick={() => navigate('/findings')}>Back</button>
        </>} />
      <div className="grid cols-2">
        <Panel title="Classification">
          <KV rows={[
            ['Severity', <SevBadge sev={f.severity} />],
            ['Confidence', <Badge tone="plain">{f.confidence}</Badge>],
            ['Category', f.category_label || f.category],
            ['Target', <span className="mono">{f.target || '—'}</span>],
            ['Endpoint', <span className="mono">{f.endpoint || '—'}</span>],
            ['Parameter', <span className="mono">{f.parameter || '—'}</span>],
            ['Status', <StateBadge s={st} />],
            ['Verification', f.verification],
            ['Detected', fmt.dt(f.detected_at)],
            ['Last seen', fmt.dt(f.last_seen_at)],
            ['Job', <a href={`#/jobs/${f.job_id}`}>{f.job_id.slice(0, 14)}…</a>],
          ]} />
        </Panel>
        <Panel title="Provenance">
          <KV rows={[
            ['Engine', <span className="mono">{f.provenance?.engine || '—'}</span>],
            ['Tool', <span className="mono">{f.provenance?.tool || '—'}</span>],
            ['Kind', <Badge tone={f.provenance?.kind === 'measured' ? 'ok' : 'plain'}>{f.provenance?.kind || '—'}</Badge>],
            ['CWE', f.cwe || '—'],
            ['OWASP', f.owasp || '—'],
            ...(f.reproduction ? ([['Reproduction', <CodeBlock text={String(f.reproduction)} />]] as [string, React.ReactNode][]) : []),
          ]} />
        </Panel>
      </div>
      <Panel title="Analysis — facts, inference, recommendation">
        <FactBlocks facts={f.facts || []} inference={f.inference || []} recommendation={f.recommendation} />
      </Panel>
      <Panel title={`Evidence (${detail.data?.evidence.length || 0})`}>
        {(detail.data?.evidence || []).map((ev) => (
          <div key={ev.id} style={{ marginBottom: 10 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
              <Badge tone="accent">{ev.kind}</Badge>
              <span>{ev.description}</span>
              <div className="spacer" />
              <span className="mono" style={{ fontSize: 10.5, color: 'var(--text-faint)' }} title={`sha256 ${ev.sha256}`}>{ev.sha256?.slice(0, 16)}…</span>
            </div>
            <CodeBlock text={JSON.stringify(ev.content, null, 1)} />
          </div>
        ))}
        {!detail.data?.evidence.length && <div className="empty">No evidence records attached.</div>}
      </Panel>
    </>
  );
}

/* -------------------------------- Evidence ------------------------------- */
export function EvidenceView() {
  const [sel, setSel] = useState<Evidence | null>(null);
  const ev = useAsync(() => api<{ evidence: Evidence[]; total: number }>('/api/v1/evidence?limit=200'), []);
  const openDetail = async (e: Evidence) => {
    try { const full = await api<{ evidence: Evidence }>(`/api/v1/evidence/${e.id}`); setSel(full.evidence); }
    catch { setSel(e); }
  };
  const rows = (ev.data?.evidence || []);
  return (
    <>
      <PageHead title="Evidence" desc="Captured observations backing every finding — hashed at capture time, immutable in storage." />
      <Err error={ev.error} />
      <Panel pad={false}>
        <DataTable
          rows={rows}
          loading={ev.loading}
          empty="No evidence captured yet."
          rowKey={(e) => e.id}
          cols={[
            { key: 'id', label: 'Evidence', render: (e) => <span className="mono">{e.id.slice(0, 16)}…</span> },
            { key: 'kind', label: 'Kind', render: (e) => <Badge tone="accent">{e.kind}</Badge> },
            { key: 'description', label: 'Description' },
            { key: 'sha', label: 'sha256', render: (e) => <span className="mono" style={{ fontSize: 10.5 }}>{e.sha256?.slice(0, 20)}…</span> },
            { key: 'job', label: 'Job', render: (e) => e.job_id ? <a href={`#/jobs/${e.job_id}`}>{e.job_id.slice(0, 12)}…</a> : '—' },
            { key: 'at', label: 'Captured', render: (e) => fmt.dt(e.captured_at) },
          ]}
          onRow={setSel}
        />
      </Panel>
      {sel && (
        <Modal title={`${sel.kind} — ${sel.description}`} wide onClose={() => setSel(null)}>
          <KV rows={[
            ['Evidence id', <span className="mono">{sel.id}</span>],
            ['sha256', <span className="mono">{sel.sha256}</span>],
            ['Captured', fmt.dt(sel.captured_at)],
            ['Source engine', sel.source || '—'],
          ]} />
          <div className="section-label">Content</div>
          <CodeBlock text={JSON.stringify(sel.content, null, 2)} />
        </Modal>
      )}
    </>
  );
}

/* -------------------------------- Security ------------------------------- */
export function SecurityView() {
  const { navigate } = useApp();
  const findings = useAsync(() => api<{ findings: Finding[] }>('/api/v1/findings?limit=500'), []);
  const [cat, setCat] = useState('ALL');
  const secCats = ['auth', 'authz', 'session', 'val', 'config', 'transmission', 'dos', 'biz', 'crypt', 'upload', 'payment', 'html5'];
  const rows = (findings.data?.findings || []).filter((f: any) => secCats.includes(f.category || f.category_label?.toLowerCase() || '') || secCats.includes((f as any).category));
  const byCat: Record<string, number> = {};
  for (const f of rows) { const c = (f as any).category; byCat[c] = (byCat[c] || 0) + 1; }
  return (
    <>
      <PageHead title="Security" desc="Authorized security assessment findings across all testing categories." actions={<button onClick={() => navigate('/marketplace')}>Launch assessment</button>} />
      <div className="grid cols-4">
        {secCats.slice(0, 8).map((c) => (
          <Stat key={c} k={c} v={byCat[c] || 0} d="findings" tone={(byCat[c] || 0) > 0 ? 'warn' : undefined} />
        ))}
      </div>
      <div className="grid cols-4" style={{ marginTop: 14 }}>
        {secCats.slice(8).map((c) => <Stat key={c} k={c} v={byCat[c] || 0} d="findings" tone={(byCat[c] || 0) > 0 ? 'warn' : undefined} />)}
      </div>
      <Panel title="Security findings by category" pad={false}>
        <DataTable
          rows={rows.filter((f) => cat === 'ALL' || (f as any).category === cat)}
          loading={findings.loading}
          empty="No security findings recorded yet."
          cols={[
            { key: 'fid', label: 'FID', render: (f) => <span className="mono">{f.fid}</span> },
            { key: 'sev', label: 'Sev', render: (f) => <SevBadge sev={f.severity} /> },
            { key: 'title', label: 'Title' },
            { key: 'cat', label: 'Category', render: (f: any) => f.category },
            { key: 'cwe', label: 'CWE', render: (f) => f.cwe ? <span className="mono">{f.cwe}</span> : '—' },
            { key: 'det', label: 'Detected', render: (f) => fmt.dt(f.detected_at) },
          ]}
          onRow={(f) => navigate(`/findings/${f.id}`)}
        />
      </Panel>
      <div className="chips" style={{ marginTop: 10 }}>
        <button className={`chip ${cat === 'ALL' ? 'active' : ''}`} onClick={() => setCat('ALL')}>all</button>
        {secCats.map((c) => <button key={c} className={`chip ${cat === c ? 'active' : ''}`} onClick={() => setCat(c)}>{c}</button>)}
      </div>
    </>
  );
}

/* ------------------------------- Monitoring ------------------------------ */
const MONITOR_TYPES = [
  { key: 'http', label: 'Website (HTTP)' }, { key: 'keyword', label: 'Keyword presence' }, { key: 'content_hash', label: 'DOM/visual (content hash)' },
  { key: 'api', label: 'API endpoint' }, { key: 'tls_cert', label: 'SSL certificate' }, { key: 'dns', label: 'DNS resolution' }, { key: 'port', label: 'Port' },
];

export function MonitoringView() {
  const { toast } = useApp();
  const monitors = useAsync(() => api<{ monitors: Monitor[]; total: number }>('/api/v1/monitors'), []);
  const [creating, setCreating] = useState(false);
  const [checksFor, setChecksFor] = useState<Monitor | null>(null);
  const checks = useAsync(() => checksFor ? api<{ checks: MonitorCheck[] }>(`/api/v1/monitors/${checksFor.id}/checks`) : Promise.resolve({ checks: [] as MonitorCheck[] }), [checksFor]);
  const test = async (m: Monitor) => {
    try { const r = await api<{ check: MonitorCheck }>(`/api/v1/monitors/${m.id}/test`, { method: 'POST', body: {} }); toast(`Check ran: ${r.check.status}${r.check.latency_ms ? ` (${r.check.latency_ms} ms)` : ''}`, r.check.status === 'up' ? 'ok' : 'err'); monitors.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const del = async (m: Monitor) => { try { await api(`/api/v1/monitors/${m.id}`, { method: 'DELETE' }); toast('Monitor removed'); monitors.refresh(); } catch (e: any) { toast(e.message, 'err'); } };
  return (
    <>
      <PageHead title="Monitoring" desc="Continuous checks: website, API, SSL certificate, DNS, port and content integrity."
        actions={<button className="primary" onClick={() => setCreating(true)}>New monitor</button>} />
      <Err error={monitors.error} />
      <Panel pad={false}>
        <DataTable
          rows={monitors.data?.monitors}
          loading={monitors.loading}
          empty="No monitors yet. Create one to start continuous checking."
          cols={[
            { key: 'label', label: 'Monitor', render: (m) => <span>{m.label || fmt.trunc(m.url, 40)}</span> },
            { key: 'type', label: 'Type', render: (m) => <Badge tone="plain">{m.type}</Badge> },
            { key: 'url', label: 'Target', render: (m) => <span className="mono" style={{ fontSize: 11 }}>{fmt.trunc(m.url, 46)}</span> },
            { key: 'enabled', label: 'Enabled', render: (m) => <StateBadge s={m.enabled ? 'active' : 'paused'} /> },
            { key: 'last', label: 'Last check', render: (m: any) => fmt.dt(m.last_check_at) },
            { key: 'act', label: '', render: (m) => (
              <span style={{ display: 'flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                <button className="sm" onClick={() => void test(m)}>Test</button>
                <button className="sm" onClick={() => setChecksFor(m)}>History</button>
                <button className="sm danger" onClick={() => void del(m)}>Remove</button>
              </span>
            ) },
          ]}
        />
      </Panel>
      {creating && <MonitorCreator onClose={() => setCreating(false)} onDone={() => { setCreating(false); monitors.refresh(); }} />}
      {checksFor && (
        <Modal title={`Check history — ${(checksFor as any).name || checksFor.url}`} wide onClose={() => setChecksFor(null)}>
          <DataTable
            rows={checks.data?.checks}
            loading={checks.loading}
            empty="No checks recorded yet."
            rowKey={(c, i) => String((c as any).id || i)}
            cols={[
              { key: 'ts', label: 'When', render: (c) => fmt.dt((c as any).ts || (c as any).checked_at) },
              { key: 'status', label: 'Result', render: (c) => <StateBadge s={c.status} /> },
              { key: 'lat', label: 'Latency', className: 'num', render: (c) => c.latency_ms != null ? `${c.latency_ms} ms` : '—' },
              { key: 'detail', label: 'Detail', render: (c) => fmt.trunc(typeof c.detail === 'string' ? c.detail : JSON.stringify(c.detail || {}), 70) },
            ]}
          />
        </Modal>
      )}
    </>
  );
}

function MonitorCreator({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { toast } = useApp();
  const assets = useAsync(() => api<{ assets: Asset[] }>('/api/v1/assets'), []);
  const [type, setType] = useState('http');
  const [name, setName] = useState('');
  const [url, setUrl] = useState('https://');
  const [assetId, setAssetId] = useState('');
  const [intervalSec, setIntervalSec] = useState('300');
  const [keyword, setKeyword] = useState('');
  const create = async () => {
    try {
      await api('/api/v1/monitors', {
        method: 'POST',
        body: { name, type, url, asset_id: assetId, interval_seconds: Number(intervalSec) || 300, ...(keyword ? { config: { keyword } } : {}) },
      });
      toast('Monitor created'); onDone();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <Modal title="New monitor" onClose={onClose} footer={<><button className="ghost" onClick={onClose}>Cancel</button><button className="primary" onClick={create} disabled={name.trim().length < 2 || !assetId || !assets.data?.assets?.length}>Create</button></>}>
      <div className="form-row">
        <Field label="Name" help="2–80 characters."><input value={name} onChange={(e) => setName(e.target.value)} placeholder="Production homepage" /></Field>
        <Field label="Type">
          <select value={type} onChange={(e) => setType(e.target.value)}>{MONITOR_TYPES.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}</select>
        </Field>
      </div>
      <Field label="Target URL" help="For port monitors use host:port in the URL."><input value={url} onChange={(e) => setUrl(e.target.value)} /></Field>
      <div className="form-row">
        <Field label="Interval (seconds)" help="30–86400."><input value={intervalSec} onChange={(e) => setIntervalSec(e.target.value)} inputMode="numeric" /></Field>
        <Field label="Linked asset" help="Monitors belong to an authorized asset.">
          <select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
            <option value="">select asset…</option>
            {(assets.data?.assets || []).map((a) => <option key={a.id} value={a.id}>{a.identifier}</option>)}
          </select>
        </Field>
      </div>
      {type === 'keyword' && <Field label="Keyword" help="Alert when this text disappears from the page."><input value={keyword} onChange={(e) => setKeyword(e.target.value)} /></Field>}
    </Modal>
  );
}

export { MONITOR_TYPES };
