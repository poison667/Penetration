import crypto from 'node:crypto';
import { badRequest, notFound, forbidden, unauthorized } from '#core/errors';
import { validate, V } from '#core/validate';
import { hashPassword, verifyPassword, generateTotpSecret, verifyTotp, otpauthUrl, sealSecret, openSecret, base32Encode } from '#sec/crypto';
import { createSession, rotateSession, authenticate, authenticateApiKey, requireAuth, verifyLoginCredentials } from './authn.js';
import { recordAudit } from '#app/audit';
import { serviceByKey, SERVICE_CATALOG, PLANS } from '#app/catalog';
import { balanceOf, grantCredits } from '#app/billing';
import { createServiceRequest } from '#worker/runner';
import { generateReport } from '#report/engine';
import { nowIso, sha256 } from '#core/util';
import { createRateLimiter } from './ratelimit.js';

/** Registers core routes: auth, users, api keys, assets, catalog, requests, jobs, findings, evidence, reports. */
export function registerCoreRoutes(router, app) {
  const { db, files } = app;
  const limiter = app.limiter || createRateLimiter();

  // ---------------- AUTH ----------------
  router.post('/api/v1/auth/register', async (ctx) => {
    if (!limiter.allow(`reg:${ctx.ip}`, 5, 1 / 600)) ctx.throw(429, 'too many registrations from this address');
    const body = validate({
      tenant_name: V.string({ min: 2, max: 80 }),
      email: V.email(),
      password: V.password(),
      name: V.string({ min: 1, max: 80 }),
    }, ctx.body);
    const existing = db.store.findOne('users', (u) => u.email === body.email);
    if (existing) throw badRequest('an account with this email already exists');
    const tenant = db.insert('tenants', { name: body.tenant_name, slug: body.tenant_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40), status: 'active', plan: 'free', created_at: nowIso() });
    const user = db.insert('users', { tenant_id: tenant.id, email: body.email, name: body.name, role: 'owner', status: 'active', password_hash: hashPassword(body.password), mfa_enabled: false, mfa_secret: null, is_staff: false });
    db.insert('subscriptions', { tenant_id: tenant.id, plan_key: 'free', status: 'active', current_period_start: nowIso(), current_period_end: null });
    grantCredits(db, tenant.id, 200, 'signup_grant', 'Initial signup credits (free plan)');
    recordAudit(db.store, { tenantId: tenant.id, actorType: 'user', actorId: user.id, action: 'tenant.created', resource: 'tenant', resourceId: tenant.id });
    const tokens = createSession(db, user, { userAgent: ctx.req.headers['user-agent'], ip: ctx.ip });
    ctx.respond(201, { tenant: { id: tenant.id, name: tenant.name }, user: publicUser(user), access_token: tokens.accessToken, refresh_token: tokens.refreshToken, expires_in: tokens.expiresIn });
  });

  router.post('/api/v1/auth/login', async (ctx) => {
    if (!limiter.allow(`login:${ctx.ip}`, 10, 0.2)) ctx.throw(429, 'too many login attempts — slow down');
    const body = validate({ email: V.email(), password: V.string({ min: 1, max: 512 }), totp: V.string.optional({ min: 0, max: 10 }) }, ctx.body);
    const user = verifyLoginCredentials(db, body.email, body.password);
    // uniform response timing/content to avoid user enumeration on our own platform
    if (!user) { await new Promise((r) => setTimeout(r, 150 + Math.random() * 100)); throw unauthorized('invalid credentials'); }
    if (user.mfa_enabled) {
      if (!body.totp) return ctx.respond(200, { mfa_required: true });
      const secret = openSecret(user.mfa_secret || '');
      if (!secret || !verifyTotp(secret, body.totp)) throw unauthorized('invalid credentials');
    }
    const tokens = createSession(db, user, { userAgent: ctx.req.headers['user-agent'], ip: ctx.ip });
    db.store.put('users', { ...user, last_login_at: nowIso() });
    recordAudit(db.store, { tenantId: user.tenant_id, actorType: 'user', actorId: user.id, action: 'auth.login', resource: 'user', resourceId: user.id, detail: { ip: ctx.ip } });
    setSessionCookie(ctx, tokens.accessToken);
    ctx.respond(200, { user: publicUser(user), access_token: tokens.accessToken, refresh_token: tokens.refreshToken, expires_in: tokens.expiresIn });
  });

  router.post('/api/v1/auth/refresh', async (ctx) => {
    const token = ctx.body?.refresh_token || getCookie(ctx.req.headers['cookie'], 'meridian_refresh');
    if (!token) throw unauthorized('missing refresh token');
    const rotated = rotateSession(db, token);
    setSessionCookie(ctx, rotated.accessToken);
    ctx.respond(200, { user: publicUser(rotated.user), access_token: rotated.accessToken, refresh_token: rotated.refreshToken, expires_in: rotated.expiresIn });
  });

  router.post('/api/v1/auth/logout', async (ctx) => {
    if (ctx.auth?.session) {
      db.store.put('sessions', { ...ctx.auth.session, revoked_at: nowIso() });
      recordAudit(db.store, { tenantId: ctx.auth.user.tenant_id, actorType: 'user', actorId: ctx.auth.user.id, action: 'auth.logout', resource: 'session', resourceId: ctx.auth.session.id });
    }
    clearSessionCookie(ctx);
    ctx.respond(200, { ok: true });
  });

  router.get('/api/v1/auth/me', async (ctx) => {
    requireAuth()(ctx);
    const tenant = db.byIdGlobal('tenants', ctx.auth.user.tenant_id);
    const { balance } = balanceOf(db, ctx.auth.user.tenant_id);
    ctx.respond(200, { user: publicUser(ctx.auth.user), tenant, credits: balance });
  });

  // MFA (TOTP)
  router.post('/api/v1/auth/mfa/setup', async (ctx) => {
    requireAuth()(ctx);
    const secret = generateTotpSecret();
    const secretB32 = base32Encode(secret);
    db.store.put('users', { ...ctx.auth.user, mfa_pending: sealSecret(secret) });
    ctx.respond(200, { secret: secretB32, otpauth_url: otpauthUrl(ctx.auth.user.email, secretB32), note: 'Store the secret in your authenticator app, then confirm with a code to enable MFA. QR rendering is not included in this build (copy the otpauth URI or secret manually).' });
  });
  router.post('/api/v1/auth/mfa/enable', async (ctx) => {
    requireAuth()(ctx);
    const body = validate({ code: V.string({ min: 6, max: 6 }) }, ctx.body);
    const user = db.byIdGlobal('users', ctx.auth.user.id);
    const secret = openSecret(user.mfa_pending || '');
    if (!secret) throw badRequest('run mfa/setup first');
    if (!verifyTotp(secret, body.code)) throw badRequest('invalid TOTP code');
    db.store.put('users', { ...user, mfa_enabled: true, mfa_secret: user.mfa_pending, mfa_pending: null });
    recordAudit(db.store, { tenantId: user.tenant_id, actorType: 'user', actorId: user.id, action: 'auth.mfa_enabled', resource: 'user', resourceId: user.id });
    ctx.respond(200, { ok: true, mfa_enabled: true });
  });
  router.post('/api/v1/auth/mfa/disable', async (ctx) => {
    requireAuth()(ctx);
    const body = validate({ password: V.string({ min: 1, max: 512 }), code: V.string({ min: 6, max: 6 }) }, ctx.body);
    const user = db.byIdGlobal('users', ctx.auth.user.id);
    if (!verifyPassword(body.password, user.password_hash)) throw unauthorized('invalid credentials');
    const secret = openSecret(user.mfa_secret || '');
    if (!secret || !verifyTotp(secret, body.code)) throw badRequest('invalid TOTP code');
    db.store.put('users', { ...user, mfa_enabled: false, mfa_secret: null });
    recordAudit(db.store, { tenantId: user.tenant_id, actorType: 'user', actorId: user.id, action: 'auth.mfa_disabled', resource: 'user', resourceId: user.id });
    ctx.respond(200, { ok: true, mfa_enabled: false });
  });

  // ---------------- USERS / IAM ----------------
  router.get('/api/v1/users', async (ctx) => {
    requireAuth(['users:read'])(ctx);
    const { rows, total } = db.list('users', ctx.tid, { limit: 200 });
    ctx.respond(200, { users: rows.map(publicUser), total });
  });
  router.post('/api/v1/users', async (ctx) => {
    requireAuth(['users:write'])(ctx);
    const body = validate({ email: V.email(), name: V.string({ min: 1, max: 80 }), role: V.enum(['admin', 'auditor', 'analyst', 'operator', 'viewer']), password: V.password() }, ctx.body);
    if (db.store.findOne('users', (u) => u.email === body.email)) throw badRequest('email already in use');
    const user = db.insert('users', { tenant_id: ctx.tid, email: body.email, name: body.name, role: body.role, status: 'active', password_hash: hashPassword(body.password), mfa_enabled: false });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'user.created', resource: 'user', resourceId: user.id, detail: { role: body.role } });
    ctx.respond(201, { user: publicUser(user) });
  });
  router.patch('/api/v1/users/:id', async (ctx) => {
    requireAuth(['users:write'])(ctx);
    const body = validate({ role: V.enum(['owner', 'admin', 'auditor', 'analyst', 'operator', 'viewer']).optional, status: V.enum(['active', 'suspended']).optional, name: V.string({ min: 1, max: 80 }).optional() }, ctx.body, { partial: true });
    const user = db.byId('users', ctx.tid, ctx.params.id);
    if (!user) throw notFound('user not found');
    if (user.id === ctx.auth.user.id && body.status === 'suspended') throw badRequest('cannot suspend your own account');
    const updated = db.update('users', ctx.tid, user.id, body);
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'user.updated', resource: 'user', resourceId: user.id, detail: body });
    ctx.respond(200, { user: publicUser(updated) });
  });
  router.delete('/api/v1/users/:id', async (ctx) => {
    requireAuth(['users:write'])(ctx);
    if (ctx.params.id === ctx.auth.user.id) throw badRequest('cannot delete your own account');
    const removed = db.remove('users', ctx.tid, ctx.params.id);
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'user.deleted', resource: 'user', resourceId: removed.id });
    ctx.respond(200, { ok: true });
  });

  // ---------------- API KEYS ----------------
  router.get('/api/v1/api-keys', async (ctx) => {
    requireAuth(['users:read'])(ctx);
    const keys = db.store.find('api_keys', (k) => k.tenant_id === ctx.tid && !k.revoked_at);
    ctx.respond(200, { keys: keys.map((k) => ({ id: k.id, name: k.name, prefix: k.prefix, scopes: k.scopes, created_at: k.created_at, last_used_at: k.last_used_at })) });
  });
  router.post('/api/v1/api-keys', async (ctx) => {
    requireAuth(['users:write'])(ctx);
    const body = validate({ name: V.string({ min: 1, max: 60 }), scopes: V.array(V.string({ min: 1, max: 40 }), { max: 20 }).optional() }, ctx.body);
    const raw = `mk_${crypto.randomBytes(24).toString('base64url')}`;
    const rec = db.insert('api_keys', { tenant_id: ctx.tid, user_id: ctx.auth.user.id, name: body.name, key_hash: sha256(raw), prefix: raw.slice(0, 10), scopes: body.scopes || ['*'], revoked_at: null, last_used_at: null });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'api_key.created', resource: 'api_key', resourceId: rec.id });
    ctx.respond(201, { id: rec.id, key: raw, note: 'store this key now — it is not retrievable later' });
  });
  router.delete('/api/v1/api-keys/:id', async (ctx) => {
    requireAuth(['users:write'])(ctx);
    const rec = db.byId('api_keys', ctx.tid, ctx.params.id);
    if (!rec) throw notFound('api key not found');
    db.store.put('api_keys', { ...rec, revoked_at: nowIso() });
    ctx.respond(200, { ok: true });
  });

  // ---------------- ASSETS (with authorization records) ----------------
  router.get('/api/v1/assets', async (ctx) => {
    requireAuth(['assets:read'])(ctx);
    const { rows, total } = db.list('assets', ctx.tid, { limit: 200 });
    ctx.respond(200, { assets: rows.map(redactAsset), total });
  });
  router.post('/api/v1/assets', async (ctx) => {
    requireAuth(['assets:write'])(ctx);
    const body = validate({
      identifier: V.string({ min: 3, max: 255 }),
      kind: V.enum(['web_host', 'api', 'domain', 'ip_range']),
      title: V.string.optional({ min: 0, max: 120 }),
      port: V.int({ min: 1, max: 65535 }),
      authorization: V.object({
        status: V.enum(['declared', 'verified', 'expired', 'revoked']),
        scope_domains: V.array(V.string({ min: 1, max: 200 }), { max: 20 }),
        authorized_by: V.string({ min: 2, max: 120 }),
        authorization_evidence: V.string.optional({ min: 0, max: 2000 }),
        exclusions: V.array(V.string({ max: 200 }), { max: 20 }).optional(),
        ports: V.array(V.int({ min: 1, max: 65535 }), { max: 30 }).optional(),
        allow_private: V.boolean().optional(),
      }),
    }, ctx.body);
    const asset = db.insert('assets', { tenant_id: ctx.tid, identifier: body.identifier, kind: body.kind, title: body.title || body.identifier, port: body.port || null, authorization: { ...body.authorization, exclusions: body.authorization.exclusions || [], ports: body.authorization.ports || [], allow_private: !!body.authorization.allow_private, authorized_at: nowIso() }, status: 'active', created_at: nowIso() });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'asset.created', resource: 'asset', resourceId: asset.id, detail: { identifier: asset.identifier, authz_status: body.authorization.status } });
    ctx.respond(201, { asset: redactAsset(asset) });
  });
  router.patch('/api/v1/assets/:id', async (ctx) => {
    requireAuth(['assets:write'])(ctx);
    const body = validate({
      title: V.string({ min: 1, max: 120 }), status: V.enum(['active', 'retired']),
      authorization: V.object({
        status: V.enum(['declared', 'verified', 'expired', 'revoked']),
        scope_domains: V.array(V.string({ min: 1, max: 200 }), { max: 20 }),
        authorized_by: V.string({ min: 2, max: 120 }),
        authorization_evidence: V.string.optional({ min: 0, max: 2000 }),
        exclusions: V.array(V.string({ max: 200 }), { max: 20 }).optional(),
        ports: V.array(V.int({ min: 1, max: 65535 }), { max: 30 }).optional(),
        allow_private: V.boolean().optional(),
      }),
    }, ctx.body, { partial: true });
    const asset = db.update('assets', ctx.tid, ctx.params.id, body.authorization ? { ...body, authorization: { ...body.authorization, authorized_at: nowIso() } } : body);
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'asset.updated', resource: 'asset', resourceId: asset.id, detail: body });
    ctx.respond(200, { asset: redactAsset(asset) });
  });
  router.delete('/api/v1/assets/:id', async (ctx) => {
    requireAuth(['assets:write'])(ctx);
    db.remove('assets', ctx.tid, ctx.params.id);
    ctx.respond(200, { ok: true });
  });

  // ---------------- CATALOG ----------------
  router.get('/api/v1/catalog', async (ctx) => {
    const auth = authenticate(db, ctx.req) || authenticateApiKey(db, ctx.req);
    if (!auth) throw unauthorized();
    ctx.respond(200, { services: SERVICE_CATALOG.map((s) => ({ ...s, params: s.params.map(({ key, label, type, optional, options, default: def, help }) => ({ key, label, type, optional: !!optional, options, default: def })) })), plans: PLANS });
  });

  // ---------------- SERVICE REQUESTS + JOBS ----------------
  router.get('/api/v1/requests', async (ctx) => {
    requireAuth(['requests:read'])(ctx);
    const { rows, total } = db.list('service_requests', ctx.tid, { limit: 100 });
    ctx.respond(200, { requests: rows, total });
  });
  router.post('/api/v1/requests', async (ctx) => {
    requireAuth(['requests:write'])(ctx);
    const body = validate({
      service: V.string({ min: 2, max: 40 }), asset_id: V.string({ min: 2, max: 60 }),
      params: V.record(V.any()).optional(),
    }, ctx.body);
    const { job } = createServiceRequest({ db, tenantId: ctx.tid, serviceKey: body.service, assetId: body.asset_id, params: body.params || {}, userId: ctx.auth.user.id });
    ctx.respond(202, { job_id: job.id, state: job.state, message: 'Request accepted — job queued for validation and execution' });
  });
  router.post('/api/v1/requests/:id/cancel', async (ctx) => {
    requireAuth(['requests:write'])(ctx);
    const req = db.byId('service_requests', ctx.tid, ctx.params.id);
    if (!req) throw notFound('request not found');
    const job = db.store.findOne('jobs', (j) => j.request_id === req.id);
    if (job && ['REQUESTED', 'VALIDATING', 'QUEUED', 'RETRYING'].includes(job.state)) {
      db.store.put('jobs', { ...job, state: 'CANCELLED', finished_at: nowIso() });
      ctx.respond(200, { ok: true, job_id: job.id, state: 'CANCELLED' });
    } else throw badRequest('job is not in a cancellable state');
  });

  router.get('/api/v1/jobs', async (ctx) => {
    requireAuth(['jobs:read'])(ctx);
    const where = {};
    for (const f of ['state', 'service_key', 'asset_id']) if (ctx.query.get(f)) where[f] = ctx.query.get(f);
    const { rows, total } = db.list('jobs', ctx.tid, { where: (j) => Object.entries(where).every(([k, v]) => j[k] === v), limit: Math.min(200, Number(ctx.query.get('limit') || 50)) });
    ctx.respond(200, { jobs: rows.map(jobSummary), total });
  });
  router.get('/api/v1/jobs/:id', async (ctx) => {
    requireAuth(['jobs:read'])(ctx);
    const job = db.byId('jobs', ctx.tid, ctx.params.id);
    if (!job) throw notFound('job not found');
    const logs = db.store.find('job_logs', (l) => l.job_id === job.id).sort((a, b) => (a.ts < b.ts ? -1 : 1)).slice(-500);
    const findings = db.store.byIndex('findings', 'tid_job', `${ctx.tid}|${job.id}`).map((f) => ({ fid: f.fid, title: f.title, severity: f.severity, check_id: f.check_id, id: f.id }));
    ctx.respond(200, { job, logs, findings });
  });
  router.post('/api/v1/jobs/:id/cancel', async (ctx) => {
    requireAuth(['jobs:write'])(ctx);
    const job = db.byId('jobs', ctx.tid, ctx.params.id);
    if (!job) throw notFound('job not found');
    if (['COMPLETED', 'FAILED', 'CANCELLED', 'PARTIALLY_COMPLETED'].includes(job.state)) throw badRequest('job already finished');
    db.store.put('jobs', { ...job, state: 'CANCELLED', finished_at: nowIso() });
    ctx.respond(200, { ok: true });
  });
  router.post('/api/v1/jobs/:id/retry', async (ctx) => {
    requireAuth(['jobs:write'])(ctx);
    const job = db.byId('jobs', ctx.tid, ctx.params.id);
    if (!job) throw notFound('job not found');
    if (!['FAILED', 'CANCELLED'].includes(job.state)) throw badRequest('only failed/cancelled jobs can be retried');
    db.store.put('jobs', { ...job, state: 'QUEUED', attempts: 0, error: null, finished_at: null });
    ctx.respond(200, { ok: true, state: 'QUEUED' });
  });

  // ---------------- FINDINGS + EVIDENCE ----------------
  router.get('/api/v1/findings', async (ctx) => {
    requireAuth(['findings:read'])(ctx);
    const severity = ctx.query.get('severity'); const status = ctx.query.get('status'); const asset = ctx.query.get('asset_id');
    const { rows, total } = db.list('findings', ctx.tid, {
      where: (f) => (!severity || f.severity === severity) && (!status || f.status === status) && (!asset || f.asset_id === asset),
      sort: 'detected_at', limit: Math.min(300, Number(ctx.query.get('limit') || 100)),
    });
    ctx.respond(200, { findings: rows.map(findingSummary), total });
  });
  router.get('/api/v1/evidence', async (ctx) => {
    requireAuth(['findings:read'])(ctx);
    const { rows, total } = db.list('evidence', ctx.tid, {
      limit: Math.min(300, Number(ctx.query.get('limit') || 100)),
    });
    // Summaries only — content can be large; GET /evidence/:id returns the full record.
    ctx.respond(200, {
      evidence: rows.map((e) => ({
        id: e.id, kind: e.kind, description: e.description, sha256: e.sha256,
        captured_at: e.captured_at, job_id: e.job_id, finding_id: e.finding_id, source: e.source,
      })),
      total,
    });
  });
  router.get('/api/v1/findings/:id', async (ctx) => {
    requireAuth(['findings:read'])(ctx);
    const f = db.byId('findings', ctx.tid, ctx.params.id);
    if (!f) throw notFound('finding not found');
    const evidence = f.evidence_ids.map((id) => db.byIdGlobal('evidence', id)).filter(Boolean);
    ctx.respond(200, { finding: f, evidence });
  });
  router.patch('/api/v1/findings/:id', async (ctx) => {
    requireAuth(['findings:write'])(ctx);
    const body = validate({ status: V.enum(['open', 'in_progress', 'remediated', 'false_positive', 'accepted_risk', 'retest_pending']).optional, verification: V.enum(['not_retested', 'retest_pending', 'verified_fixed', 'still_present']).optional, remediation_notes: V.string({ max: 4000 }).optional() }, ctx.body, { partial: true });
    const f = db.update('findings', ctx.tid, ctx.params.id, body);
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'finding.updated', resource: 'finding', resourceId: f.id, detail: body });
    ctx.respond(200, { finding: findingSummary(f) });
  });
  router.get('/api/v1/evidence/:id', async (ctx) => {
    requireAuth(['evidence:read'])(ctx);
    const ev = db.byId('evidence', ctx.tid, ctx.params.id);
    if (!ev) throw notFound('evidence not found');
    ctx.respond(200, { evidence: ev });
  });

  // ---------------- REPORTS ----------------
  router.get('/api/v1/reports', async (ctx) => {
    requireAuth(['reports:read'])(ctx);
    const { rows, total } = db.list('reports', ctx.tid, { limit: 100 });
    ctx.respond(200, { reports: rows.map((r) => ({ id: r.id, kind: r.kind, format: r.format, title: r.title, sha256: r.sha256, size_bytes: r.size_bytes, findings_count: r.findings_count, job_id: r.job_id, created_at: r.created_at, previous_report_id: r.previous_report_id })), total });
  });
  router.post('/api/v1/reports', async (ctx) => {
    requireAuth(['reports:write'])(ctx);
    const body = validate({
      kind: V.enum(['service_report', 'asset_summary', 'executive_summary']),
      format: V.enum(['pdf', 'html', 'csv', 'xlsx', 'json']),
      job_id: V.string({ max: 60 }), asset_id: V.string({ max: 60 }),
    }, ctx.body, { partial: true });
    const job = body.job_id ? db.byId('jobs', ctx.tid, body.job_id) : null;
    if (body.job_id && !job) throw notFound('job not found');
    const { report, model } = generateReport(db, files, { tenantId: ctx.tid, job, kind: body.kind || 'service_report', format: body.format || 'pdf', assetId: body.asset_id || job?.asset_id || null, createdBy: ctx.auth.user.id });
    recordAudit(db.store, { tenantId: ctx.tid, actorType: 'user', actorId: ctx.auth.user.id, action: 'report.generated', resource: 'report', resourceId: report.id, detail: { kind: report.kind, format: report.format } });
    ctx.respond(201, { report: { id: report.id, kind: report.kind, format: report.format, sha256: report.sha256, findings_count: report.findings_count, previous_report_id: report.previous_report_id, summary: model.summary } });
  });
  router.get('/api/v1/reports/:id/download', async (ctx) => {
    requireAuth(['reports:read'])(ctx);
    const r = db.byId('reports', ctx.tid, ctx.params.id);
    if (!r) throw notFound('report not found');
    const rec = files.get(ctx.tid, r.file_id);
    const content = files.read(ctx.tid, r.file_id);
    ctx.respondRaw(200, content, rec.mime, { 'content-disposition': `attachment; filename="${rec.name.replace(/[^\w.-]/g, '_')}"`, 'x-report-sha256': r.sha256 });
  });
}

export function publicUser(u) {
  return { id: u.id, tenant_id: u.tenant_id, email: u.email, name: u.name, role: u.role, status: u.status, mfa_enabled: !!u.mfa_enabled, is_staff: !!u.is_staff, last_login_at: u.last_login_at || null, created_at: u.created_at };
}
function redactAsset(a) {
  return { ...a, authorization: { ...a.authorization, authorization_evidence: a.authorization?.authorization_evidence ? `(recorded, ${(a.authorization.authorization_evidence || '').length} chars)` : null } };
}
function jobSummary(j) {
  return { id: j.id, service_key: j.service_key, asset_id: j.asset_id, state: j.state, progress: j.progress, attempts: j.attempts, error: j.error, findings_count: j.result_summary?.findings_count ?? null, created_at: j.created_at, started_at: j.started_at, finished_at: j.finished_at, qc: j.qc ? { engines_run: j.qc.engines_run, engines_failed: j.qc.engines_failed, evidence_records: j.qc.evidence_records } : null };
}
function findingSummary(f) {
  return { id: f.id, fid: f.fid, title: f.title, check_id: f.check_id, category: f.category_label || f.category, severity: f.severity, confidence: f.confidence, cwe: f.cwe, owasp: f.owasp, endpoint: f.endpoint, parameter: f.parameter, status: f.status, verification: f.verification, evidence_count: f.evidence_ids?.length || 0, detected_at: f.detected_at, asset_id: f.asset_id, job_id: f.job_id };
}
function setSessionCookie(ctx, token) {
  ctx.res.setHeader('set-cookie', `meridian_session=${token}; Path=/api/v1; HttpOnly; SameSite=Strict; Max-Age=7200`);
}
function clearSessionCookie(ctx) {
  ctx.res.setHeader('set-cookie', 'meridian_session=; Path=/api/v1; HttpOnly; SameSite=Strict; Max-Age=0');
}
function getCookie(header, name) {
  const m = new RegExp(`(?:^|;\\s*)${name}=([^;]+)`).exec(header || '');
  return m ? m[1] : null;
}
