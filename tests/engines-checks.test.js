import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CHECKS, CHECK_CATEGORIES, getCheck, checksByCategory } from '#checks';
import fs from 'node:fs';
import path from 'node:path';

test('the catalogue defines all 176 checks with unique ids', () => {
  assert.equal(CHECKS.length, 176);
  const ids = new Set(CHECKS.map((c) => c.id));
  assert.equal(ids.size, CHECKS.length, 'duplicate check ids');
});

test('every check carries the mandatory metadata (id/cat/sev/kind/title/remediation)', () => {
  for (const c of CHECKS) {
    assert.match(c.id, /^[A-Z0-9]+-\d{3}$/, `bad id format: ${c.id}`);
    assert.ok(CHECK_CATEGORIES[c.cat] !== undefined || Object.keys(CHECK_CATEGORIES).includes(c.cat), `unknown category: ${c.cat} for ${c.id}`);
    assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(c.sev), `bad severity on ${c.id}`);
    assert.ok(['passive', 'safe', 'active', 'assisted', 'intrusive'].includes(c.kind), `bad kind on ${c.id}`);
    assert.equal(typeof c.t, 'string');
    assert.ok(c.t.length > 3, `empty title on ${c.id}`);
    assert.equal(typeof c.rem, 'string');
    assert.ok(c.rem.length > 3, `empty remediation on ${c.id}`);
  }
});

test('check families match the security requirement categories', () => {
  const families = [...new Set(CHECKS.map((c) => c.id.split('-')[0]))].sort();
  assert.deepEqual(families, ['A11Y', 'ATH', 'AUT', 'BIZ', 'CFG', 'CRP', 'DOS', 'H5', 'PAY', 'PRF', 'REC', 'SEO', 'SES', 'TLS', 'UPL', 'VAL']);
});

test('every catalogued check is wired into at least one engine', () => {
  let engineSrc = '';
  for (const d of ['src/engines/web', 'src/engines/sec']) {
    for (const f of fs.readdirSync(d)) if (f.endsWith('.js')) engineSrc += fs.readFileSync(path.join(d, f), 'utf8');
  }
  const unwired = CHECKS.filter((c) => !engineSrc.includes(`'${c.id}'`));
  assert.deepEqual(unwired.map((c) => c.id), [], 'these checks have no engine reporting them');
});

test('getCheck and checksByCategory lookups agree with the catalogue', () => {
  assert.equal(getCheck('VAL-001').id, 'VAL-001');
  assert.throws(() => getCheck('NOPE-999'), /unknown check id/);
  const val = checksByCategory('val');
  assert.ok(val.length > 20);
  assert.ok(val.every((c) => c.cat === 'val'));
});

test('high/critical checks document CWE or OWASP mappings where applicable', () => {
  const mapped = CHECKS.filter((c) => ['high', 'critical'].includes(c.sev) && (c.cwe || c.owasp));
  assert.ok(mapped.length >= 20, `expected substantial CWE/OWASP coverage, got ${mapped.length}`);
  for (const c of mapped) {
    // cwe is stored as the numeric CWE id (e.g. 79) or null
    if (c.cwe) assert.ok(Number.isInteger(Number(c.cwe)) && Number(c.cwe) > 0, `bad CWE on ${c.id}: ${c.cwe}`);
  }
});
