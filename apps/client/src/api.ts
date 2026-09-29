/** Typed API client — talks to the real Meridian REST API. No mocks. */

export interface User { id: string; email: string; name: string; role: string; status: string; mfa_enabled?: boolean; is_staff?: boolean; last_login_at?: string | null; }
export interface Tenant { id: string; name: string; status: string; created_at?: string; plan?: string; }
export interface Paged<T> { total: number }
export interface Job { id: string; state: string; service_key: string; asset_id: string | null; progress: number; created_at: string; started_at?: string | null; finished_at?: string | null; result_summary?: Record<string, unknown> | null; qc?: Record<string, unknown> | null; usage?: Record<string, unknown> | null; error?: string | null; params?: Record<string, unknown>; request_id?: string | null; }
export interface Finding { fid: string; id: string; check_id: string; title: string; category: string; category_label?: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: string; target?: string | null; endpoint?: string | null; parameter?: string | null; cwe?: string | null; owasp?: string | null; facts: string[]; inference: string[]; recommendation?: string; evidence_ids: string[]; status: string; verification: string; detected_at: string; last_seen_at?: string; job_id: string; provenance?: Record<string, unknown>; }
export interface Evidence { id: string; kind: string; description: string; sha256: string; captured_at: string; job_id?: string; finding_id?: string | null; content: unknown; source?: string; }
export interface Asset { id: string; identifier: string; kind: string; title?: string | null; status: string; created_at: string; authorization?: { status: string; scope_domains: string[]; authorized_by: string; exclusions?: string[]; ports?: number[]; allow_private?: boolean; authorization_evidence?: string | null } | null; }
export interface ServiceParam { key: string; label: string; type: string; optional: boolean; options?: { value: string; label: string }[] | null; default?: unknown; help?: string | null }
export interface Service { key: string; name: string; category: string; description?: string; credits: number; params: ServiceParam[]; profiles?: string[]; engines?: string[] }
export interface Plan { key: string; name: string; price_monthly: number; credits_monthly?: number; features?: string[] }
export interface Monitor { id: string; type: string; url: string; label?: string | null; enabled: boolean; interval_minutes?: number; last_check_at?: string | null; config?: Record<string, unknown>; }
export interface MonitorCheck { id?: string; monitor_id: string; ts?: string; checked_at?: string; status: string; latency_ms?: number; detail?: Record<string, unknown> | string | null }
export interface Report { id: string; kind: string; format: string; created_at: string; sha256: string; findings_count?: number; file_id?: string; previous_report_id?: string | null; job_id?: string | null; }
export interface Notification { id: string; title: string; body?: string | null; kind?: string; created_at: string; read_at?: string | null }
export interface Ticket { id: string; subject: string; status: string; priority: string; created_at: string; updated_at?: string; messages?: { id: string; author: string; body: string; created_at: string }[] }
export interface DataSource { id: string; name: string; kind: string; created_at: string; rows?: number; columns?: number; size_bytes?: number; file_id?: string }
export interface DataRun { id: string; source_id: string; operation: string; state: string; created_at: string; output_file_id?: string | null; stats?: Record<string, unknown> | null; error?: string | null }
export interface Kb { id: string; name: string; created_at: string; document_ids?: string[]; chunks?: number }
export interface Workflow { id: string; name: string; version: number; definition: Record<string, unknown>; updated_at?: string; created_at?: string }
export interface WorkflowRun { id: string; workflow_id: string; state: string; started_at?: string; finished_at?: string; step_states?: { step_id: string; state: string }[]; error?: string | null }
export interface Schedule { id: string; cron: string; next_run_at?: string; last_run_at?: string | null; enabled: boolean; workflow_id?: string | null; rule_id?: string | null }
export interface ApiKey { id: string; name: string; prefix: string; scopes: string[]; created_at: string; last_used_at?: string | null }
export interface Invoice { id: string; created_at: string; total: number; status?: string; lines?: { description: string; amount: number }[] }
export interface AuditEntry { seq: number; ts: string; action: string; actor_type: string; actor_id?: string; resource: string; resource_id?: string; detail?: Record<string, unknown>; prev_hash: string; hash: string }

const BASE = '';
let accessToken: string | null = localStorage.getItem('meridian.at');
let refreshToken: string | null = localStorage.getItem('meridian.rt');

export function tokens() { return { accessToken, refreshToken }; }
export function setTokens(at: string | null, rt?: string | null) {
  accessToken = at;
  if (rt !== undefined) refreshToken = rt;
  if (at) localStorage.setItem('meridian.at', at); else localStorage.removeItem('meridian.at');
  if (rt) localStorage.setItem('meridian.rt', rt); else if (rt !== undefined) localStorage.removeItem('meridian.rt');
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public details?: unknown) { super(message); }
}

async function refresh(): Promise<boolean> {
  if (!refreshToken) return false;
  try {
    const res = await fetch(`${BASE}/api/v1/auth/refresh`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const j = await res.json();
    setTokens(j.access_token, j.refresh_token);
    return true;
  } catch { return false; }
}

export async function api<T = unknown>(path: string, opts: { method?: string; body?: unknown; raw?: Blob } = {}): Promise<T> {
  const doFetch = () => fetch(`${BASE}${path}`, {
    method: opts.method || 'GET',
    headers: {
      ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let res = await doFetch();
  if (res.status === 401 && refreshToken && (await refresh())) res = await doFetch();
  if (!res.ok) {
    let code = 'error'; let msg = res.statusText; let details: unknown;
    try { const j = await res.json(); code = j?.error?.code || code; msg = j?.error?.message || msg; details = j?.error?.details; } catch { /* non-json */ }
    throw new ApiError(res.status, code, msg, details);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export async function upload<T = unknown>(path: string, file: File | Blob, fields: Record<string, string> = {}): Promise<T> {
  const fd = new FormData();
  fd.append('file', file);
  for (const [k, v] of Object.entries(fields)) fd.append(k, v);
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST', headers: { ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}) }, body: fd,
  });
  if (!res.ok) {
    let code = 'error'; let msg = res.statusText;
    try { const j = await res.json(); code = j?.error?.code || code; msg = j?.error?.message || msg; } catch { /* */ }
    throw new ApiError(res.status, code, msg);
  }
  return (await res.json()) as T;
}

export function downloadUrl(path: string) { return `${BASE}${path}`; }
export function authHeaders(): Record<string, string> { return accessToken ? { authorization: `Bearer ${accessToken}` } : {}; }

/** SSE stream URL (EventSource cannot set headers, so the token rides as a query param). */
export function eventsUrl(): string {
  return `${BASE}/events${accessToken ? `?access_token=${encodeURIComponent(accessToken)}` : ''}`;
}
export function currentAccessToken(): string | null { return accessToken; }

export const fmt = {
  dt(iso?: string | null): string {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  },
  bytes(n?: number | null): string {
    if (n === null || n === undefined) return '—';
    const u = ['B', 'KB', 'MB', 'GB'];
    let i = 0; let v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
  },
  num(n?: number | null): string { return n === null || n === undefined ? '—' : n.toLocaleString(); },
  trunc(s: string, n = 42): string { return s.length > n ? `${s.slice(0, n - 1)}…` : s; },
};
