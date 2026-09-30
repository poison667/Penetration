/** Business views: marketplace, requests, reports, billing, notifications, support. */
import React, { useState, useEffect } from 'react';
import { api, fmt, Service, Plan, Asset, Job, Report, Invoice, Notification, Ticket, Webhook, WebhookDelivery, EmailChannel } from '../api';
import { useApp } from '../state';
import { Panel, PageHead, Stat, DataTable, StateBadge, Badge, Field, Modal, KV, useAsync, Err, EmptyGate } from '../ui';

/* ------------------------------ Marketplace ------------------------------ */
export function MarketplaceView() {
  const { navigate, toast } = useApp();
  const catalog = useAsync(() => api<{ services: Service[]; plans: Plan[] }>('/api/v1/catalog'), []);
  const assets = useAsync(() => api<{ assets: Asset[] }>('/api/v1/assets'), []);
  const [svc, setSvc] = useState<Service | null>(null);
  const [assetId, setAssetId] = useState('');
  const [params, setParams] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const openRequest = (s: Service) => { setSvc(s); setParams({}); setAssetId(assets.data?.assets[0]?.id || ''); };
  const submit = async () => {
    if (!svc || !assetId) return;
    setBusy(true);
    try {
      const j = await api<{ job_id?: string; job?: { id: string } }>('/api/v1/requests', { method: 'POST', body: { service: svc.key, asset_id: assetId, params } });
      toast('Service requested — job queued');
      setSvc(null);
      navigate(`/jobs/${j.job_id || j.job?.id}`);
    } catch (e: any) { toast(e.message, 'err'); setBusy(false); }
  };
  const cats = [...new Set((catalog.data?.services || []).map((s) => s.category))];
  const catLabels: Record<string, string> = { audit: 'Audit & analysis', security: 'Security assessment', monitoring: 'Monitoring', data: 'Data workbench', ai: 'AI', report: 'Reporting' };

  return (
    <>
      <PageHead title="Marketplace" desc="Every service is a real pipeline run against your authorized assets — priced in credits." />
      <Err error={catalog.error} />
      {cats.map((c) => (
        <Panel key={c} title={catLabels[c] || c} pad={false}>
          <DataTable
            rows={catalog.data?.services.filter((s) => s.category === c)}
            loading={catalog.loading}
            empty="—"
            cols={[
              { key: 'name', label: 'Service', render: (s) => <div><b>{s.name}</b><div style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>{s.description}</div></div> },
              { key: 'credits', label: 'Credits', className: 'num', render: (s: any) => fmt.num(s.credits ?? s.credits_per_run) },
              { key: 'engines', label: 'Engines', render: (s: any) => s.engines ? <span className="mono" style={{ fontSize: 11 }}>{s.engines.length} engine{s.engines.length > 1 ? 's' : ''}</span> : '—' },
              { key: 'act', label: '', render: (s) => <button className="sm primary" onClick={() => openRequest(s)}>Request</button> },
            ]}
          />
        </Panel>
      ))}
      {svc && (
        <Modal title={`Request — ${svc.name}`} onClose={() => setSvc(null)}
          footer={<><button className="ghost" onClick={() => setSvc(null)}>Cancel</button>
            <button className="primary" disabled={!assetId || busy} onClick={submit}>{busy ? <span className="spinner" style={{ borderTopColor: '#fff' }} /> : 'Request service'}</button></>}>
          {assets.data?.assets.length ? (
            <>
              <Field label="Target asset" help="Security services require an authorization record on the asset.">
                <select value={assetId} onChange={(e) => setAssetId(e.target.value)}>
                  {assets.data.assets.map((a) => <option key={a.id} value={a.id}>{a.identifier}{a.authorization?.status === 'verified' ? '  ✓ authorized' : `  (${a.authorization?.status || 'no authorization'})`}</option>)}
                </select>
              </Field>
              {svc.params.map((p) => (
                <Field key={p.key} label={`${p.label}${p.optional ? ' (optional)' : ''}`} help={p.help || undefined}>
                  {p.options ? (
                    <select value={params[p.key] ?? String(p.default ?? p.options[0]?.value ?? '')} onChange={(e) => setParams({ ...params, [p.key]: e.target.value })}>
                      {p.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  ) : (
                    <input value={params[p.key] ?? String(p.default ?? '')} onChange={(e) => setParams({ ...params, [p.key]: e.target.value })} placeholder={p.type} />
                  )}
                </Field>
              ))}
              <div className="notice">Cost: <b>{svc.credits} credits</b> held on request, committed on completion.</div>
            </>
          ) : (
            <EmptyGate>You need at least one asset before requesting services. <a href="#/assets">Add an asset</a>.</EmptyGate>
          )}
        </Modal>
      )}
    </>
  );
}

/* ------------------------------- Requests -------------------------------- */
export function RequestsView() {
  const { navigate, toast } = useApp();
  const reqs = useAsync(() => api<{ requests: any[]; total: number }>('/api/v1/requests?limit=200'), []);
  return (
    <>
      <PageHead title="Service requests" desc="Requests are validated, priced, queued and executed as jobs." />
      <Err error={reqs.error} />
      <Panel pad={false}>
        <DataTable
          rows={reqs.data?.requests}
          loading={reqs.loading}
          empty="No service requests yet — start from the marketplace."
          cols={[
            { key: 'id', label: 'Request', render: (r: any) => <span className="mono">{r.id.slice(0, 14)}…</span> },
            { key: 'service', label: 'Service', render: (r: any) => <span className="mono">{r.service_key}</span> },
            { key: 'state', label: 'State', render: (r: any) => <StateBadge s={r.state || 'REQUESTED'} /> },
            { key: 'est', label: 'Est. credits', className: 'num', render: (r: any) => fmt.num(r.credits_estimate ?? r.estimated_credits) },
            { key: 'created', label: 'Created', render: (r: any) => fmt.dt(r.created_at) },
            { key: 'job', label: 'Job', render: (r: any) => r.job_id ? <a href={`#/jobs/${r.job_id}`}>view job</a> : '—' },
            { key: 'act', label: '', render: (r: any) => !r.job_id && ['REQUESTED', 'VALIDATING'].includes(r.state || '') ? (
              <button className="sm danger" onClick={async () => { try { await api(`/api/v1/requests/${r.id}/cancel`, { method: 'POST', body: {} }); toast('Request cancelled'); reqs.refresh(); } catch (e: any) { toast(e.message, 'err'); } }}>Cancel</button>
            ) : null },
          ]}
          onRow={(r: any) => r.job_id && navigate(`/jobs/${r.job_id}`)}
        />
      </Panel>
    </>
  );
}

/* -------------------------------- Reports -------------------------------- */
export function ReportsView() {
  const { toast } = useApp();
  const reports = useAsync(() => api<{ reports: Report[]; total: number }>('/api/v1/reports?limit=200'), []);
  const [gen, setGen] = useState(false);
  const [kind, setKind] = useState('service_report');
  const [format, setFormat] = useState('pdf');
  const [jobId, setJobId] = useState('');
  const jobs = useAsync(() => api<{ jobs: Job[] }>('/api/v1/jobs?state=COMPLETED&limit=50'), []);
  const generate = async () => {
    try {
      await api('/api/v1/reports', { method: 'POST', body: { kind, format, ...(jobId ? { job_id: jobId } : {}) } });
      toast('Report generated'); setGen(false); reports.refresh();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <>
      <PageHead title="Reports" desc="Executive-ready deliverables with methodology, evidence, integrity hash and history deltas."
        actions={<button className="primary" onClick={() => setGen(true)}>Generate report</button>} />
      <Err error={reports.error} />
      <Panel pad={false}>
        <DataTable
          rows={reports.data?.reports}
          loading={reports.loading}
          empty="No reports yet."
          cols={[
            { key: 'kind', label: 'Kind', render: (r) => r.kind.replace(/_/g, ' ') },
            { key: 'format', label: 'Format', render: (r) => <Badge tone="plain">{r.format.toUpperCase()}</Badge> },
            { key: 'n', label: 'Findings', className: 'num', render: (r: any) => fmt.num(r.findings_count) },
            { key: 'sha', label: 'Integrity (sha256)', render: (r) => <span className="mono" style={{ fontSize: 10.5 }}>{r.sha256?.slice(0, 24)}…</span> },
            { key: 'prev', label: 'Comparison', render: (r: any) => r.previous_report_id ? <Badge tone="accent">delta vs {r.previous_report_id.slice(0, 10)}…</Badge> : '—' },
            { key: 'created', label: 'Created', render: (r) => fmt.dt(r.created_at) },
            { key: 'act', label: '', render: (r) => <a href={`/api/v1/reports/${r.id}/download`} onClick={(e) => e.stopPropagation()} target="_blank" rel="noreferrer">Download</a> },
          ]}
        />
      </Panel>
      {gen && (
        <Modal title="Generate report" onClose={() => setGen(false)} footer={<><button className="ghost" onClick={() => setGen(false)}>Cancel</button><button className="primary" onClick={generate}>Generate</button></>}>
          <Field label="Report kind">
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              {['service_report', 'asset_summary', 'executive_summary'].map((k) => <option key={k} value={k}>{k.replace(/_/g, ' ')}</option>)}
            </select>
          </Field>
          <Field label="Format">
            <select value={format} onChange={(e) => setFormat(e.target.value)}>{['pdf', 'html', 'csv', 'xlsx', 'json'].map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}</select>
          </Field>
          <Field label="Source job (optional)" help="Leave empty for the latest completed job.">
            <select value={jobId} onChange={(e) => setJobId(e.target.value)}>
              <option value="">latest completed</option>
              {(jobs.data?.jobs || []).map((j) => <option key={j.id} value={j.id}>{j.service_key} — {fmt.dt(j.created_at)}</option>)}
            </select>
          </Field>
          <div className="notice">Reports embed a sha256 integrity hash and, when a previous report exists, a comparison of added/resolved findings.</div>
        </Modal>
      )}
    </>
  );
}

/* -------------------------------- Billing -------------------------------- */
export function BillingView() {
  const { toast, refreshSession } = useApp();
  const billing = useAsync(() => api<{ subscription: any; balance: number; ledger: any[]; plans: Plan[]; ledger_entries?: number }>('/api/v1/billing'), []);
  const invoices = useAsync(() => api<{ invoices: Invoice[] }>('/api/v1/billing/invoices'), []);
  const subscribe = async (plan: string) => {
    try { await api('/api/v1/billing/subscribe', { method: 'POST', body: { plan } }); toast(`Subscribed to ${plan}`); billing.refresh(); refreshSession(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const b = billing.data;
  return (
    <>
      <PageHead title="Billing & credits" desc="Credit ledger with hold/commit lifecycle. Every job's usage is traceable to ledger entries." />
      <Err error={billing.error} />
      <div className="grid cols-3">
        <Stat k="Credit balance" v={fmt.num(b?.balance)} d="available now" />
        <Stat k="Plan" v={b?.subscription?.plan_key || 'free'} d={b?.subscription?.status || 'no active subscription'} tone={b?.subscription ? 'ok' : undefined} />
        <Stat k="Ledger entries" v={fmt.num(b?.ledger_entries ?? b?.ledger?.length)} d="all-time movements" />
      </div>
      <Panel title="Plans" pad={false}>
        <DataTable
          rows={b?.plans}
          loading={billing.loading}
          empty="—"
          cols={[
            { key: 'name', label: 'Plan', render: (p: any) => <b>{p.name}</b> },
            { key: 'price', label: 'Price / month', className: 'num', render: (p: any) => p.price_monthly ? `$${(p.price_monthly / 100).toFixed(2)}` : 'Free' },
            { key: 'credits', label: 'Monthly credits', className: 'num', render: (p: any) => fmt.num(p.credits_monthly) },
            { key: 'feat', label: 'Includes', render: (p: any) => {
              const f = p.features;
              const text = Array.isArray(f) ? f.join(' · ')
                : f && typeof f === 'object' ? Object.entries(f).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${String(v)}`).join(' · ')
                : String(f || '—');
              return <span style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{text}</span>;
            } },
            { key: 'act', label: '', render: (p: any) => b?.subscription?.plan_key === p.key ? <Badge tone="ok">current</Badge> : <button className="sm" onClick={() => void subscribe(p.key)}>Select</button> },
          ]}
        />
      </Panel>
      <Panel title="Credit ledger (latest 100)" pad={false}>
        <DataTable
          rows={b?.ledger}
          loading={billing.loading}
          empty="No ledger movements yet."
          rowKey={(l: any, i) => l.id || String(i)}
          cols={[
            { key: 'ts', label: 'When', render: (l: any) => fmt.dt(l.created_at) },
            { key: 'type', label: 'Type', render: (l: any) => <Badge tone={l.amount > 0 ? 'ok' : 'plain'}>{l.entry_type || l.type}</Badge> },
            { key: 'amount', label: 'Amount', className: 'num', render: (l: any) => <span style={{ color: l.amount > 0 ? 'var(--ok)' : 'var(--text)' }}>{l.amount > 0 ? '+' : ''}{fmt.num(l.amount)}</span> },
            { key: 'after', label: 'Balance after', className: 'num', render: (l: any) => fmt.num(l.balance_after) },
            { key: 'src', label: 'Source', render: (l: any) => <span style={{ fontSize: 11.5 }}>{l.source || l.note || '—'}{l.job_id ? ` · ${l.job_id.slice(0, 10)}…` : ''}</span> },
          ]}
        />
      </Panel>
      <Panel title="Invoices" pad={false}>
        <DataTable
          rows={invoices.data?.invoices}
          loading={invoices.loading}
          empty="No invoices yet."
          cols={[
            { key: 'id', label: 'Invoice', render: (i: any) => <span className="mono">{i.id.slice(0, 16)}…</span> },
            { key: 'created', label: 'Date', render: (i) => fmt.dt(i.created_at) },
            { key: 'total', label: 'Total (credits)', className: 'num', render: (i) => fmt.num(i.total) },
          ]}
        />
      </Panel>
    </>
  );
}

/* ----------------------------- Notifications ----------------------------- */
export function NotificationsView() {
  const { toast } = useApp();
  const notes = useAsync(() => api<{ notifications: Notification[] }>('/api/v1/notifications?limit=200'), []);
  const markAll = async () => { try { await api('/api/v1/notifications/read-all', { method: 'POST', body: {} }); toast('All marked read'); notes.refresh(); } catch (e: any) { toast(e.message, 'err'); } };
  const markOne = async (n: Notification) => { try { await api(`/api/v1/notifications/${n.id}/read`, { method: 'POST', body: {} }); notes.refresh(); } catch { /* */ } };
  return (
    <>
      <PageHead title="Notifications" desc="In-app notifications plus external delivery channels (signed webhooks, SMTP email)."
        actions={<button onClick={markAll}>Mark all read</button>} />
      <Err error={notes.error} />
      <Panel pad={false}>
        <DataTable
          rows={notes.data?.notifications}
          loading={notes.loading}
          empty="No notifications."
          cols={[
            { key: 'title', label: 'Notification', render: (n) => <span style={{ fontWeight: n.read_at ? 400 : 650 }}>{n.title}{n.body ? <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}> — {n.body}</span> : null}</span> },
            { key: 'read', label: 'Status', render: (n) => n.read_at ? <Badge tone="plain">read</Badge> : <Badge tone="accent">unread</Badge> },
            { key: 'created', label: 'When', render: (n) => fmt.dt(n.created_at) },
            { key: 'act', label: '', render: (n) => !n.read_at ? <button className="sm" onClick={() => void markOne(n)}>Mark read</button> : null },
          ]}
        />
      </Panel>
      <DeliveryChannelsView />
    </>
  );
}

/* ---------------------- External delivery channels ----------------------- */
export function DeliveryChannelsView() {
  const { toast } = useApp();
  const hooks = useAsync(() => api<{ webhooks: Webhook[] }>('/api/v1/webhooks'), []);
  const email = useAsync(() => api<{ email_channel: EmailChannel | null }>('/api/v1/settings/email'), []);
  const [creating, setCreating] = useState(false);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState('*');
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [created, setCreated] = useState<Webhook | null>(null);
  const [deliveriesFor, setDeliveriesFor] = useState<Webhook | null>(null);
  const deliveries = useAsync(() => deliveriesFor ? api<{ deliveries: WebhookDelivery[] }>(`/api/v1/webhooks/${deliveriesFor.id}/deliveries`) : Promise.resolve(null), [deliveriesFor]);
  const [mail, setMail] = useState<EmailChannel | null>(null);
  useEffect(() => { if (email.data?.email_channel) setMail(email.data.email_channel); }, [email.data]);

  const createHook = async () => {
    try {
      const res = await api<{ webhook: Webhook }>('/api/v1/webhooks', { method: 'POST', body: { url, events: events.split(',').map((e) => e.trim()).filter(Boolean).length ? events.split(',').map((e) => e.trim()).filter(Boolean) : undefined, allow_private: allowPrivate } });
      setCreating(false); setUrl(''); setEvents('*'); setAllowPrivate(false);
      setCreated(res.webhook); hooks.refresh();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  const testHook = async (w: Webhook) => {
    try { await api(`/api/v1/webhooks/${w.id}/test`, { method: 'POST', body: {} }); toast('Test delivery queued — check the deliveries log'); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const deleteHook = async (w: Webhook) => {
    try { await api(`/api/v1/webhooks/${w.id}`, { method: 'DELETE' }); toast('Webhook removed'); hooks.refresh(); } catch (e: any) { toast(e.message, 'err'); }
  };
  const saveMail = async () => {
    if (!mail) return;
    try {
      await api('/api/v1/settings/email', { method: 'PUT', body: { smtp_host: mail.smtp_host, smtp_port: Number(mail.smtp_port), from: mail.from, to: mail.to, events: mail.events, enabled: mail.enabled } });
      toast('Email channel saved'); email.refresh();
    } catch (e: any) { toast(e.message, 'err'); }
  };
  const testMail = async () => {
    try { await api('/api/v1/settings/email/test', { method: 'POST', body: {} }); toast('Test email queued'); } catch (e: any) { toast(e.message, 'err'); }
  };

  return (
    <>
      <PageHead title="Delivery channels" desc="Notifications fan out to registered channels: webhooks are HMAC-SHA256 signed (x-meridian-signature), email uses your SMTP relay."
        actions={<button onClick={() => setCreating(true)}>Add webhook</button>} />
      <Panel pad={false}>
        <DataTable
          rows={hooks.data?.webhooks}
          loading={hooks.loading}
          empty="No webhooks yet — register an endpoint to receive signed event deliveries."
          cols={[
            { key: 'url', label: 'Endpoint', render: (w) => <span className="mono">{w.url}</span> },
            { key: 'events', label: 'Events', render: (w) => <span className="mono">{(w.events || []).join(', ')}</span> },
            { key: 'enabled', label: 'State', render: (w) => w.enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="plain">disabled</Badge> },
            { key: 'last', label: 'Last delivery', render: (w) => <>{w.last_status ? <StateBadge s={w.last_status.toUpperCase()} /> : <span style={{ color: 'var(--text-dim)' }}>never</span>}{w.last_delivery_at ? <span style={{ color: 'var(--text-dim)' }}> · {fmt.dt(w.last_delivery_at)}</span> : null}</> },
            { key: 'act', label: '', render: (w) => <span style={{ whiteSpace: 'nowrap' }}>
              <button className="sm" onClick={() => void testHook(w)}>Test</button>{' '}
              <button className="sm" onClick={() => setDeliveriesFor(w)}>Deliveries</button>{' '}
              <button className="sm" onClick={() => void deleteHook(w)}>Remove</button>
            </span> },
          ]}
        />
      </Panel>

      <Panel title="Email channel (SMTP)">
        {!mail ? (
          <div style={{ color: 'var(--text-dim)' }}>No email channel configured. Add your SMTP relay details to receive notifications by email. SMS delivery remains a documented limitation (external carrier credentials required).</div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <Field label="SMTP host"><input value={mail.smtp_host} onChange={(e) => setMail({ ...mail, smtp_host: e.target.value })} placeholder="smtp.example.com" /></Field>
            <Field label="Port"><input value={mail.smtp_port} onChange={(e) => setMail({ ...mail, smtp_port: Number(e.target.value) })} placeholder="587" /></Field>
            <Field label="From"><input value={mail.from} onChange={(e) => setMail({ ...mail, from: e.target.value })} placeholder="alerts@example.com" /></Field>
            <Field label="To (comma-separated)"><input value={mail.to} onChange={(e) => setMail({ ...mail, to: e.target.value })} placeholder="team@example.com" /></Field>
            <Field label="Events" help="Filters: * for all, or prefixes like job. monitor."><input value={(mail.events || []).join(', ')} onChange={(e) => setMail({ ...mail, events: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} /></Field>
            <Field label="Enabled"><label style={{ display: 'flex', gap: 6, alignItems: 'center' }}><input type="checkbox" checked={mail.enabled} onChange={(e) => setMail({ ...mail, enabled: e.target.checked })} /> deliver notifications</label></Field>
            <div style={{ display: 'flex', gap: 8, alignItems: 'end' }}>
              <button onClick={() => void saveMail()}>Save</button>
              <button onClick={() => void testMail()} disabled={!mail.enabled}>Send test</button>
            </div>
          </div>
        )}
      </Panel>

      {creating && (
        <Modal title="Register webhook endpoint" onClose={() => setCreating(false)} footer={<>
          <button className="primary" onClick={() => void createHook()}>Create</button>
          <button onClick={() => setCreating(false)}>Cancel</button>
        </>}>
          <Field label="Endpoint URL" help="Meridian POSTs a signed JSON payload on each matching notification.">
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/meridian-hook" />
          </Field>
          <Field label="Events" help="Comma-separated filters: * for all, or prefixes like job. monitor. finding.">
            <input value={events} onChange={(e) => setEvents(e.target.value)} placeholder="job., monitor." />
          </Field>
          <Field label="Private targets">
            <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} />
              allow loopback/private addresses (explicit opt-in — treat private targets like any authorized target)
            </label>
          </Field>
        </Modal>
      )}

      {created && (
        <Modal title="Webhook registered" onClose={() => setCreated(null)} footer={<button className="primary" onClick={() => setCreated(null)}>I stored the secret</button>}>
          <p>Endpoint <span className="mono">{created.url}</span> is registered. Verify deliveries with this HMAC-SHA256 signing secret — it is shown <b>only once</b>:</p>
          <pre className="mono" style={{ padding: 10, borderRadius: 6, background: 'var(--bg-alt, #f4f4f5)', wordBreak: 'break-all' }}>{created.secret}</pre>
          <p style={{ color: 'var(--text-dim)', fontSize: 12 }}>Signature header: x-meridian-signature: sha256=HMAC(secret, `${'{timestamp}'}.${'{body}'}`).</p>
        </Modal>
      )}

      {deliveriesFor && (
        <Modal title={`Deliveries — ${deliveriesFor.url}`} onClose={() => setDeliveriesFor(null)} wide>
          <DataTable
            rows={deliveries.data?.deliveries}
            loading={deliveries.loading}
            empty="No delivery attempts yet."
            cols={[
              { key: 'created', label: 'Queued', render: (d) => fmt.dt(d.created_at) },
              { key: 'event', label: 'Event', render: (d) => <span className="mono">{d.event || '—'}</span> },
              { key: 'status', label: 'Status', render: (d) => <StateBadge s={(d.status || 'PENDING').toUpperCase()} /> },
              { key: 'attempts', label: 'Attempts', className: 'num', render: (d) => `${d.attempts}/${d.max_attempts}` },
              { key: 'http', label: 'HTTP', render: (d) => d.response_status ?? '—' },
              { key: 'next', label: 'Next attempt', render: (d) => d.next_attempt_at && d.status === 'pending' ? fmt.dt(d.next_attempt_at) : '—' },
              { key: 'err', label: 'Error', render: (d) => d.last_error ? <span style={{ color: 'var(--danger, #b00)' }}>{d.last_error}</span> : '—' },
            ]}
          />
        </Modal>
      )}
    </>
  );
}

/* -------------------------------- Support -------------------------------- */
export function SupportView() {
  const { toast } = useApp();
  const tickets = useAsync(() => api<{ tickets: Ticket[] }>('/api/v1/tickets'), []);
  const [open, setOpen] = useState<Ticket | null>(null);
  const [creating, setCreating] = useState(false);
  const [subject, setSubject] = useState('');
  const [priority, setPriority] = useState('normal');
  const [message, setMessage] = useState('');
  const [reply, setReply] = useState('');
  const detail = useAsync(() => open ? api<Ticket>(`/api/v1/tickets/${open.id}`) : Promise.resolve(null), [open]);
  const create = async () => {
    try { await api('/api/v1/tickets', { method: 'POST', body: { subject, priority, message } }); toast('Ticket created'); setCreating(false); setSubject(''); setMessage(''); tickets.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const sendReply = async () => {
    if (!open || !reply.trim()) return;
    try { await api(`/api/v1/tickets/${open.id}/messages`, { method: 'POST', body: { message: reply } }); setReply(''); detail.refresh(); } catch (e: any) { toast(e.message, 'err'); }
  };
  const diagnostics = async () => {
    try {
      const res = await fetch('/api/v1/support/diagnostics', { method: 'POST', headers: { authorization: `Bearer ${localStorage.getItem('meridian.at')}` } });
      if (!res.ok) throw new Error('diagnostics failed');
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'meridian-diagnostics.json'; a.click();
      toast('Diagnostics bundle downloaded');
    } catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <>
      <PageHead title="Support" desc="Tickets, threads and platform diagnostics."
        actions={<><button onClick={diagnostics}>Download diagnostics</button><button className="primary" onClick={() => setCreating(true)}>New ticket</button></>} />
      <Err error={tickets.error} />
      <Panel pad={false}>
        <DataTable
          rows={tickets.data?.tickets}
          loading={tickets.loading}
          empty="No tickets."
          cols={[
            { key: 'subject', label: 'Subject' },
            { key: 'prio', label: 'Priority', render: (t: any) => <Badge tone={t.priority === 'urgent' ? 'err' : t.priority === 'high' ? 'warn' : 'plain'}>{t.priority}</Badge> },
            { key: 'status', label: 'Status', render: (t) => <StateBadge s={t.status} /> },
            { key: 'created', label: 'Created', render: (t) => fmt.dt(t.created_at) },
          ]}
          onRow={setOpen}
        />
      </Panel>
      {creating && (
        <Modal title="New support ticket" onClose={() => setCreating(false)} footer={<><button className="ghost" onClick={() => setCreating(false)}>Cancel</button><button className="primary" onClick={create} disabled={!subject || !message}>Create</button></>}>
          <Field label="Subject"><input value={subject} onChange={(e) => setSubject(e.target.value)} /></Field>
          <Field label="Priority"><select value={priority} onChange={(e) => setPriority(e.target.value)}>{['low', 'normal', 'high', 'urgent'].map((p) => <option key={p}>{p}</option>)}</select></Field>
          <Field label="Message"><textarea value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Describe the issue…" /></Field>
        </Modal>
      )}
      {open && (
        <Modal title={open.subject} wide onClose={() => setOpen(null)}>
          <KV rows={[['Ticket', <span className="mono">{open.id}</span>], ['Status', <StateBadge s={open.status} />], ['Priority', open.priority], ['Created', fmt.dt(open.created_at)]]} />
          <div className="section-label">Thread</div>
          {(detail.data as any)?.messages?.length ? (detail.data as any).messages.map((m: any) => (
            <div key={m.id} className="fact-block" style={{ borderLeftColor: 'var(--border-strong)' }}>
              <div style={{ fontSize: 11.5, color: 'var(--text-faint)', marginBottom: 3 }}>{m.author || m.author_type || 'user'} · {fmt.dt(m.created_at)}</div>
              <div>{m.body}</div>
            </div>
          )) : <div className="empty">No messages.</div>}
          <div className="field" style={{ marginTop: 12 }}>
            <label>Reply</label>
            <textarea value={reply} onChange={(e) => setReply(e.target.value)} placeholder="Write a reply…" />
            <button className="primary sm" style={{ marginTop: 8 }} onClick={sendReply} disabled={!reply.trim()}>Send</button>
          </div>
        </Modal>
      )}
    </>
  );
}
