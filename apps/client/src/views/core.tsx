/** Account & governance views: settings, IAM, audit, admin. */
import React, { useState } from 'react';
import { api, fmt, ApiKey, AuditEntry, User } from '../api';
import { useApp } from '../state';
import { Panel, PageHead, DataTable, StateBadge, Badge, Field, Modal, KV, CodeBlock, useAsync, Err } from '../ui';

/* -------------------------------- Settings ------------------------------- */
export function SettingsView() {
  const { session, refreshSession, toast, theme, toggleTheme } = useApp();
  const keys = useAsync(() => api<{ keys: ApiKey[] }>('/api/v1/api-keys'), []);
  const [mfaModal, setMfaModal] = useState<{ secret: string; otpauth: string } | null>(null);
  const [code, setCode] = useState('');
  const [keyModal, setKeyModal] = useState<{ token: string } | null>(null);

  const startMfa = async () => {
    try { const j = await api<{ secret: string; otpauth_url: string }>('/api/v1/auth/mfa/setup', { method: 'POST', body: {} }); setMfaModal({ secret: j.secret, otpauth: j.otpauth_url }); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const enableMfa = async () => {
    try { await api('/api/v1/auth/mfa/enable', { method: 'POST', body: { code } }); toast('MFA enabled'); setMfaModal(null); setCode(''); refreshSession(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const disableMfa = async () => {
    try { await api('/api/v1/auth/mfa/disable', { method: 'POST', body: {} }); toast('MFA disabled'); refreshSession(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const createKey = async () => {
    try { const j = await api<{ token?: string; key?: string; prefix?: string }>('/api/v1/api-keys', { method: 'POST', body: { name: 'API key', scopes: ['read'] } }); setKeyModal({ token: (j as any).token || (j as any).key || '' }); keys.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };

  return (
    <>
      <PageHead title="Settings" desc="Account security, API access and appearance." />
      <div className="grid cols-2">
        <Panel title="Account">
          <KV rows={[
            ['Name', session?.user.name || '—'],
            ['Email', session?.user.email || '—'],
            ['Role', session?.user.role || '—'],
            ['Tenant', session?.tenant?.name || '—'],
            ['Two-factor auth', session?.user.mfa_enabled ? <Badge tone="ok">enabled</Badge> : <Badge tone="warn">disabled</Badge>],
          ]} />
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            {session?.user.mfa_enabled
              ? <button className="danger" onClick={disableMfa}>Disable MFA</button>
              : <button className="primary" onClick={startMfa}>Enable MFA (TOTP)</button>}
            <button onClick={toggleTheme}>Switch to {theme === 'light' ? 'dark' : 'light'} theme</button>
          </div>
        </Panel>
        <Panel title="API keys" actions={<button className="sm" onClick={createKey}>New key</button>}>
          <DataTable
            rows={keys.data?.keys}
            loading={keys.loading}
            empty="No API keys. Create one for programmatic access."
            cols={[
              { key: 'name', label: 'Name' },
              { key: 'prefix', label: 'Prefix', render: (k) => <span className="mono">{k.prefix}…</span> },
              { key: 'scopes', label: 'Scopes', render: (k) => k.scopes.join(', ') },
              { key: 'used', label: 'Last used', render: (k) => k.last_used_at ? fmt.dt(k.last_used_at) : 'never' },
              { key: 'act', label: '', render: (k) => <button className="sm danger" onClick={async () => { try { await api(`/api/v1/api-keys/${k.id}`, { method: 'DELETE' }); toast('Key revoked'); keys.refresh(); } catch (e: any) { toast(e.message, 'err'); } }}>Revoke</button> },
            ]}
          />
        </Panel>
      </div>
      {mfaModal && (
        <Modal title="Enable two-factor authentication" onClose={() => setMfaModal(null)}
          footer={<><button className="ghost" onClick={() => setMfaModal(null)}>Cancel</button><button className="primary" onClick={enableMfa} disabled={code.length < 6}>Confirm & enable</button></>}>
          <div className="notice">Add this secret to your authenticator app, then confirm with a 6-digit code. QR rendering is not included — copy the secret or otpauth URI.</div>
          <div className="section-label">Secret (base32)</div>
          <CodeBlock text={mfaModal.secret} />
          <div className="section-label">otpauth URI</div>
          <CodeBlock text={mfaModal.otpauth} />
          <Field label="Authenticator code"><input value={code} onChange={(e) => setCode(e.target.value)} maxLength={6} inputMode="numeric" placeholder="123456" /></Field>
        </Modal>
      )}
      {keyModal && (
        <Modal title="API key created" onClose={() => setKeyModal(null)}>
          <div className="notice warn">Copy this token now — it is not shown again.</div>
          <CodeBlock text={keyModal.token} />
        </Modal>
      )}
    </>
  );
}

/* ---------------------------------- IAM ---------------------------------- */
export function IamView() {
  const { toast } = useApp();
  const users = useAsync(() => api<{ users: User[]; total: number }>('/api/v1/users'), []);
  const [inviting, setInviting] = useState(false);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('viewer');
  const [password, setPassword] = useState('');
  const invite = async () => {
    try { await api('/api/v1/users', { method: 'POST', body: { email, name, role, password } }); toast('User created'); setInviting(false); setEmail(''); setName(''); setPassword(''); users.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const setRoleFor = async (u: User, r: string) => {
    try { await api(`/api/v1/users/${u.id}`, { method: 'PATCH', body: { role: r } }); toast(`${u.email} → ${r}`); users.refresh(); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  return (
    <>
      <PageHead title="IAM & users" desc="Role-based access control. Roles carry granular permissions enforced on every route."
        actions={<button className="primary" onClick={() => setInviting(true)}>Add user</button>} />
      <Err error={users.error} />
      <Panel pad={false}>
        <DataTable
          rows={users.data?.users}
          loading={users.loading}
          empty="No users."
          cols={[
            { key: 'name', label: 'User', render: (u) => <div><b>{u.name}</b><div style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>{u.email}</div></div> },
            { key: 'role', label: 'Role', render: (u) => (
              <select value={u.role} onChange={(e) => void setRoleFor(u, e.target.value)} onClick={(e) => e.stopPropagation()} style={{ width: 130 }}>
                {['owner', 'admin', 'auditor', 'analyst', 'operator', 'viewer'].map((r) => <option key={r}>{r}</option>)}
              </select>
            ) },
            { key: 'mfa', label: 'MFA', render: (u: any) => u.mfa_enabled ? <Badge tone="ok">on</Badge> : <Badge tone="plain">off</Badge> },
            { key: 'status', label: 'Status', render: (u) => <StateBadge s={u.status} /> },
            { key: 'login', label: 'Last login', render: (u: any) => fmt.dt(u.last_login_at) },
          ]}
        />
      </Panel>
      {inviting && (
        <Modal title="Add user" onClose={() => setInviting(false)} footer={<><button className="ghost" onClick={() => setInviting(false)}>Cancel</button><button className="primary" onClick={invite} disabled={!email || !name || password.length < 10}>Create</button></>}>
          <Field label="Email"><input value={email} onChange={(e) => setEmail(e.target.value)} type="email" /></Field>
          <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Initial password" help="Minimum 10 characters. The user should change it after first login."><input value={password} onChange={(e) => setPassword(e.target.value)} type="password" /></Field>
          <Field label="Role" help="admin: everything except tenant ownership · auditor: read+reports · analyst: findings+data · operator: jobs+automation · viewer: read-only">
            <select value={role} onChange={(e) => setRole(e.target.value)}>{['admin', 'auditor', 'analyst', 'operator', 'viewer'].map((r) => <option key={r}>{r}</option>)}</select>
          </Field>
        </Modal>
      )}
    </>
  );
}

/* --------------------------------- Audit --------------------------------- */
export function AuditView() {
  const { toast } = useApp();
  const audit = useAsync(() => api<{ entries: AuditEntry[]; total: number }>('/api/v1/audit?limit=200'), []);
  const verify = async () => {
    try { const j = await api<{ ok: boolean; entries?: number; broken_at?: number }>('/api/v1/audit/verify'); toast(j.ok ? `Chain intact (${j.entries ?? '?'} entries)` : `CHAIN BROKEN at seq ${j.broken_at}`, j.ok ? 'ok' : 'err'); }
    catch (e: any) { toast(e.message, 'err'); }
  };
  const rows: any[] = (audit.data as any)?.entries || (audit.data as any)?.audit || [];
  return (
    <>
      <PageHead title="Audit log" desc="Append-only, hash-chained per tenant. Any edit, reordering or deletion is detectable."
        actions={<button onClick={verify}>Verify chain</button>} />
      <Err error={audit.error} />
      <Panel pad={false}>
        <DataTable
          rows={rows}
          loading={audit.loading}
          empty="No audit entries."
          rowKey={(a, i) => String(a.id || a.seq || i)}
          cols={[
            { key: 'seq', label: '#', className: 'num', render: (a: any) => a.seq },
            { key: 'ts', label: 'When', render: (a: any) => fmt.dt(a.ts || a.created_at) },
            { key: 'action', label: 'Action', render: (a: any) => <span className="mono">{a.action}</span> },
            { key: 'actor', label: 'Actor', render: (a: any) => `${a.actor_type}:${(a.actor_id || '—').slice(0, 10)}…` },
            { key: 'resource', label: 'Resource', render: (a: any) => `${a.resource}${a.resource_id ? ` / ${a.resource_id.slice(0, 10)}…` : ''}` },
            { key: 'hash', label: 'Hash', render: (a: any) => <span className="mono" style={{ fontSize: 10 }} title={`prev: ${a.prev_hash}`}>{a.hash?.slice(0, 14)}…</span> },
          ]}
        />
      </Panel>
    </>
  );
}

/* --------------------------------- Admin --------------------------------- */
export function AdminView() {
  const sys = useAsync(() => api<any>('/api/v1/admin/system'), []);
  const tenants = useAsync(() => api<{ tenants: any[] }>('/api/v1/admin/tenants'), []);
  const jobs = useAsync(() => api<{ jobs: any[] }>('/api/v1/admin/jobs?limit=100'), []);
  return (
    <>
      <PageHead title="Administration" desc="Platform staff console — cross-tenant visibility, explicitly guarded." />
      <div className="grid cols-4">
        <Panel title="Version"><div style={{ fontSize: 18, fontWeight: 650 }}>{sys.data?.version || '—'}</div></Panel>
        <Panel title="Uptime"><div style={{ fontSize: 18, fontWeight: 650 }}>{sys.data?.uptime_s != null ? `${Math.floor(sys.data.uptime_s / 60)} min` : '—'}</div></Panel>
        <Panel title="Tenants"><div style={{ fontSize: 18, fontWeight: 650 }}>{fmt.num(tenants.data?.tenants?.length)}</div></Panel>
        <Panel title="Jobs (all tenants)"><div style={{ fontSize: 18, fontWeight: 650 }}>{fmt.num(jobs.data?.jobs?.length)}</div></Panel>
      </div>
      <Panel title="Tenants" pad={false}>
        <DataTable
          rows={tenants.data?.tenants}
          loading={tenants.loading}
          empty="—"
          cols={[
            { key: 'name', label: 'Tenant' },
            { key: 'plan', label: 'Plan', render: (t: any) => <Badge tone="plain">{t.plan || 'free'}</Badge> },
            { key: 'status', label: 'Status', render: (t: any) => <StateBadge s={t.status} /> },
            { key: 'created', label: 'Created', render: (t: any) => fmt.dt(t.created_at) },
          ]}
        />
      </Panel>
      <Panel title="Recent jobs (all tenants)" pad={false}>
        <DataTable
          rows={jobs.data?.jobs}
          loading={jobs.loading}
          empty="—"
          cols={[
            { key: 'id', label: 'Job', render: (j: any) => <span className="mono">{j.id.slice(0, 12)}…</span> },
            { key: 'tenant', label: 'Tenant', render: (j: any) => <span className="mono" style={{ fontSize: 11 }}>{j.tenant_id?.slice(0, 10)}…</span> },
            { key: 'service', label: 'Service', render: (j: any) => <span className="mono">{j.service_key}</span> },
            { key: 'state', label: 'State', render: (j: any) => <StateBadge s={j.state} /> },
            { key: 'created', label: 'Created', render: (j: any) => fmt.dt(j.created_at) },
          ]}
        />
      </Panel>
    </>
  );
}
