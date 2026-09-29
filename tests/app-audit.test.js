import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recordAudit, verifyAuditChain } from '#app/audit';
import { openStore } from '#store/store';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-audit-'));

test('a fresh chain verifies as intact', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    for (let i = 0; i < 6; i++) recordAudit(s, { tenantId: 't1', action: `act.${i}`, resource: 'x', resourceId: `r${i}` });
    const v = verifyAuditChain(s);
    assert.equal(v.ok, true);
    assert.equal(v.entries, 6);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('per-tenant chains are independent', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    for (let i = 0; i < 3; i++) recordAudit(s, { tenantId: 't1', action: `a.${i}`, resource: 'x' });
    for (let i = 0; i < 2; i++) recordAudit(s, { tenantId: 't2', action: `b.${i}`, resource: 'y' });
    const v = verifyAuditChain(s); // all tenants
    assert.equal(v.ok, true);
    assert.equal(v.entries, 5);
    assert.deepEqual(v.chains.t1, { ok: true, entries: 3 });
    assert.deepEqual(v.chains.t2, { ok: true, entries: 2 });
    const v1 = verifyAuditChain(s, 't1');
    assert.equal(v1.ok, true);
    assert.equal(v1.entries, 3);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('tampering with an entry is detected at exactly that entry', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    for (let i = 0; i < 5; i++) recordAudit(s, { tenantId: 't1', action: `act.${i}`, resource: 'x' });
    const victim = s.find('audit', (a) => a.action === 'act.2')[0];
    s.put('audit', { ...victim, action: 'TAMPERED' });
    const v = verifyAuditChain(s);
    assert.equal(v.ok, false);
    assert.equal(v.broken_at, victim.id);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('deleting an entry is detected (no silent gaps)', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    for (let i = 0; i < 4; i++) recordAudit(s, { tenantId: 't1', action: `act.${i}`, resource: 'x' });
    const victim = s.find('audit', (a) => a.seq === 2)[0];
    s.del('audit', victim.id);
    const v = verifyAuditChain(s);
    assert.equal(v.ok, false);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('chain survives close + reopen from disk (durable tamper evidence)', () => {
  const dir = tmp();
  try {
    {
      const s = openStore(dir);
      for (let i = 0; i < 5; i++) recordAudit(s, { tenantId: 't9', action: `a.${i}`, resource: 'x' });
      s.close();
    }
    const s2 = openStore(dir);
    const ok = verifyAuditChain(s2);
    assert.equal(ok.ok, true);
    // tamper after reload is still caught
    const victim = s2.find('audit', (a) => a.tenant_id === 't9')[1];
    s2.put('audit', { ...victim, detail: { forged: true } });
    assert.equal(verifyAuditChain(s2).ok, false);
    s2.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('entries carry explicit monotonic sequence numbers', () => {
  const dir = tmp();
  try {
    const s = openStore(dir);
    for (let i = 0; i < 4; i++) recordAudit(s, { tenantId: 't1', action: 'x', resource: 'r' });
    const seqs = s.find('audit', (a) => a.tenant_id === 't1').map((a) => a.seq).sort((a, b) => a - b);
    assert.deepEqual(seqs, [1, 2, 3, 4]);
    s.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
