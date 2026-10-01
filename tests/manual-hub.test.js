import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { FileStore } from '#app/files';
import { createServer } from '#api/server';
import { parseHar, createManualFinding, importHar } from '#app/manual';
import { generateReport } from '#report/engine';
import { hashPassword, setSecretKey } from '#sec/crypto';
import crypto from 'node:crypto';
import { startFixture } from '../fixtures/vuln-app/server.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * MANUAL-WORK HUB TESTS
 *
 * Unit: HAR parsing (normalization, base64 bodies, caps, rejection) and manual
 * finding validation.
 *
 * End-to-end: REAL HTTP API (auth enforced) → real fixture traffic captured as
 * a genuine HAR → import → manual finding with linked evidence → findings list
 * → asset report includes the manual finding alongside engine findings.
 */

setSecretKey(crypto.randomBytes(32));

test('unit: parseHar normalizes entries, decodes base64, caps sizes, rejects non-HAR', () => {
  assert.throws(() => parseHar({ foo: 1 }), /not a HAR document/);
  assert.throws(() => parseHar({ log: { entries: [{ request: { url: 'ftp://x' } }] } }), /no HTTP entries/);

  const har = {
    log: {
      entries: [
        {
          startedDateTime: '2026-10-02T10:00:00.000Z', time: 42.5,
          request: { method: 'get', url: 'http://t.local/a?x=1', httpVersion: 'HTTP/1.1', headers: [{ name: 'Accept', value: 'text/html' }], postData: { text: 'hello=world' } },
          response: { status: 200, headers: [{ name: 'Content-Type', value: 'text/html' }], content: { mimeType: 'text/html', text: '<html>ok</html>' } },
        },
        {
          request: { method: 'POST', url: 'https://t.local/b', headers: [] },
          response: { status: 401, headers: [], content: { mimeType: 'image/png', text: Buffer.from('fakepng').toString('base64'), encoding: 'base64' } },
        },
        { request: { method: 'GET', url: 'data:text/plain,skipme' }, response: { status: 0, headers: [], content: {} } }, // skipped: not http(s)
      ],
    },
  };
  const { entries, total_in_file } = parseHar(har);
  assert.equal(total_in_file, 3);
  assert.equal(entries.length, 2, 'non-HTTP entries must be skipped');
  assert.equal(entries[0].method, 'GET');
  assert.match(entries[0].request.headers, /Accept: text\/html/);
  assert.equal(entries[0].response.body, '<html>ok</html>');
  assert.equal(entries[0].request.body, 'hello=world');
  assert.equal(entries[1].response.status, 401);
  assert.equal(entries[1].response.body, 'fakepng', 'base64 HAR content must be decoded');

  // size caps
  const big = 'A'.repeat(100_000);
  const capped = parseHar({ log: { entries: [{ request: { method: 'GET', url: 'http://t.local/c' }, response: { status: 200, headers: [], content: { text: big } } }] } });
  assert.ok(capped.entries[0].response.body.length < 40_000, 'body must be truncated');
  assert.match(capped.entries[0].response.body, /truncated/);
});

test('unit: createManualFinding validation — evidence invariant, enums, fid + hash', () => {
  const dir = mkdtempSync(join(tmpdir(), 'meridian-man-unit-'));
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const tenant = db.insert('tenants', { name: 'Manual Unit (test data)', status: 'active', created_at: new Date().toISOString() });
    assert.throws(() => createManualFinding({ db, tenantId: tenant.id, body: { title: 'Valid title', description: '' } }), /description is required/);
    assert.throws(() => createManualFinding({ db, tenantId: tenant.id, body: { title: 'Valid title', description: 'observed', severity: 'super' } }), /severity/);
    assert.throws(() => createManualFinding({ db, tenantId: tenant.id, body: { title: 'Valid title', description: 'observed', check_id: 'CFG-001' } }), /MAN-00/);
    assert.throws(() => createManualFinding({ db, tenantId: tenant.id, body: { title: 'Valid title', description: 'observed', har_evidence_ids: ['ev_missing'] } }), /not found/);

    const f = createManualFinding({
      db, tenantId: tenant.id, userId: 'u_tester',
      body: {
        title: 'Reflected user input in search results', description: 'Typing <script> in the search box reflects it unescaped into the page.',
        severity: 'high', check_id: 'MAN-001', endpoint: '/search', parameter: 'q',
        recommendation: 'HTML-encode all user input before rendering.', cwe: '79',
        http_exchange: { request: { method: 'GET', url: 'http://t.local/search?q=%3Cscript%3E', headers: 'Accept: text/html', body: null }, response: { status: 200, headers: 'Content-Type: text/html', body: '<html>…<script>…</html>' } },
      },
    });
    assert.match(f.fid, /^MER-F-\d{6}$/);
    assert.equal(f.status, 'open');
    assert.equal(f.confidence, 'confirmed');
    assert.equal(f.category, 'manual');
    assert.equal(f.cwe, 'CWE-79');
    assert.equal(f.evidence_ids.length, 2, 'note + pasted HTTP exchange');
    assert.equal(f.provenance.kind, 'manual');
    assert.equal(f.provenance.entered_by, 'u_tester');
    assert.ok(f.hash.length === 64);
    const stored = db.store.byId('findings', f.id);
    assert.equal(stored.fid, f.fid);
    const ev = db.store.byId('evidence', f.evidence_ids[0]);
    assert.equal(ev.kind, 'manual_note');
    assert.equal(ev.sha256.length, 64);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('e2e: real API — HAR import → manual finding → findings list → report inclusion', async () => {
  const fixture = await startFixture({ httpPort: 0, tlsPort: 0 });
  const port = fixture[0].address().port;

  const dir = mkdtempSync(join(tmpdir(), 'meridian-man-e2e-'));
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const files = new FileStore(join(dir, 'files'), store);
    const tenant = db.insert('tenants', { name: 'Manual E2E (test data)', status: 'active', created_at: new Date().toISOString() });
    const owner = db.insert('users', { tenant_id: tenant.id, email: 'pentest@meridian.local', name: 'Pentester', role: 'owner', status: 'active', password_hash: hashPassword('Manual!Pass1A'), mfa_enabled: false });
    db.insert('subscriptions', { tenant_id: tenant.id, plan_key: 'pro', status: 'active' });
    const asset = db.insert('assets', {
      tenant_id: tenant.id, identifier: `http://127.0.0.1:${port}`, kind: 'web_host', title: 'Fixture (manual hub test)',
      authorization: { status: 'verified', scope_domains: ['127.0.0.1'], authorized_by: 'test', exclusions: [], ports: [port], allow_private: true },
      status: 'active', created_at: new Date().toISOString(),
    });

    // ---- capture REAL traffic as a genuine HAR document ----
    const toHarEntry = async (method, url, reqHeaders, res, body) => {
      const text = (await res.text()).slice(0, 2000);
      return {
        startedDateTime: new Date().toISOString(), time: 12,
        request: { method, url, httpVersion: 'HTTP/1.1', headers: reqHeaders, postData: body ? { text: body } : undefined },
        response: { status: res.status, headers: [...res.headers.entries()].map(([name, value]) => ({ name, value })), content: { mimeType: res.headers.get('content-type') || 'text/plain', text } },
      };
    };
    const r1 = await fetch(`http://127.0.0.1:${port}/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E`);
    const e1 = await toHarEntry('GET', r1.url, [{ name: 'Accept', value: 'text/html' }], r1, null);
    const r2 = await fetch(`http://127.0.0.1:${port}/login`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'username=root&password=root' });
    const e2 = await toHarEntry('POST', r2.url, [{ name: 'content-type', value: 'application/x-www-form-urlencoded' }], r2, 'username=root&password=root');
    const har = { log: { version: '1.2', creator: { name: 'test', version: '1' }, entries: [e1, e2] } };

    // ---- boot the real API server and do everything over HTTP ----
    const server = createServer({ db, files, config: { uiRoot: null } });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const B = `http://127.0.0.1:${server.address().port}`;
    const api = async (path, { method = 'GET', token, body } = {}) => {
      const res = await fetch(B + path, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
      let json = null; try { json = await res.json(); } catch {}
      return { status: res.status, json };
    };

    // auth enforcement
    assert.equal((await api('/api/v1/har-imports', { method: 'POST', body: { har } })).status, 401);
    const login = await api('/api/v1/auth/login', { method: 'POST', body: { email: 'pentest@meridian.local', password: 'Manual!Pass1A' } });
    const token = login.json.access_token;

    // invalid HAR rejected
    assert.equal((await api('/api/v1/har-imports', { method: 'POST', token, body: { har: { nope: 1 } } })).status, 400);

    // import the real HAR
    const imp = await api('/api/v1/har-imports', { method: 'POST', token, body: { asset_id: asset.id, har } });
    assert.equal(imp.status, 201);
    assert.equal(imp.json.import.stats.imported, 2);
    assert.equal(imp.json.evidence.length, 2);
    const harEvIds = imp.json.evidence.map((e) => e.id);
    assert.ok(imp.json.evidence.some((e) => /\/search/.test(e.url)));

    // manual finding linked to the imported evidence
    const mf = await api('/api/v1/findings/manual', {
      method: 'POST', token,
      body: {
        title: 'Reflected XSS in search parameter', description: 'The q parameter is reflected unescaped — confirmed by rendering the response from the imported exchange.',
        severity: 'high', check_id: 'MAN-001', asset_id: asset.id, endpoint: '/search', parameter: 'q', cwe: '79',
        har_evidence_ids: harEvIds,
      },
    });
    assert.equal(mf.status, 201);
    assert.match(mf.json.finding.fid, /^MER-F-\d{6}$/);
    assert.equal(mf.json.finding.evidence_count, 3, 'note + 2 linked HAR exchanges');

    // validation over HTTP
    assert.equal((await api('/api/v1/findings/manual', { method: 'POST', token, body: { title: 'nope' } })).status, 400);

    // appears in the findings list next to engine findings
    const list = await api('/api/v1/findings?limit=200', { token });
    assert.ok(list.json.findings.some((f) => f.fid === mf.json.finding.fid));

    // triage (PATCH) works on manual findings
    const patched = await api(`/api/v1/findings/${mf.json.finding.id}`, { method: 'PATCH', token, body: { status: 'in_progress', remediation_notes: 'Ticket APP-123 opened with the dev team.' } });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.finding.status, 'in_progress');

    // detail view carries evidence
    const detail = await api(`/api/v1/findings/${mf.json.finding.id}`, { token });
    assert.equal(detail.json.evidence.length, 3);
    assert.ok(detail.json.evidence.some((e) => e.kind === 'har_exchange'));

    // asset summary report includes the manual finding
    const rep = await api('/api/v1/reports', { method: 'POST', token, body: { kind: 'asset_summary', format: 'json', asset_id: asset.id } });
    assert.equal(rep.status, 201);
    const dl = await fetch(`${B}/api/v1/reports/${rep.json.report.id}/download`, { headers: { authorization: `Bearer ${token}` } });
    const model = JSON.parse(await dl.text());
    assert.ok(model.findings.some((f) => f.fid === mf.json.finding.fid), 'manual finding must appear in the asset report');
    assert.ok(model.findings.some((f) => f.check_id === 'MAN-001'));

    await new Promise((r) => server.close(r));
  } finally {
    for (const s of fixture) await new Promise((r) => s.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});
