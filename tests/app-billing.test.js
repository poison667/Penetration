import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { balanceOf, grantCredits, holdCredits, commitCredits, releaseAll, estimateCost, applyMonthlyGrant, buildInvoice } from '#app/billing';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-billing-'));
const openDb = (dir) => new Db(openStore(dir));

test('grantCredits accrues into balanceOf', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    grantCredits(db, 't1', 1000, 'test', 'initial');
    grantCredits(db, 't1', 500, 'test', 'topup');
    assert.equal(balanceOf(db, 't1').balance, 1500);
    assert.equal(balanceOf(db, 't2').balance, 0);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('holdCredits reserves funds and blocks overdraft', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    grantCredits(db, 't1', 100, 'test');
    holdCredits(db, 't1', 'job1', 30);
    assert.equal(balanceOf(db, 't1').balance, 70);
    assert.throws(() => holdCredits(db, 't1', 'job2', 80), /insufficient/i);
    holdCredits(db, 't1', 'job2', 70); // exactly the rest is fine
    assert.equal(balanceOf(db, 't1').balance, 0);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('commitCredits settles actual usage below the hold', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    grantCredits(db, 't1', 1000, 'test');
    holdCredits(db, 't1', 'job1', 100);
    commitCredits(db, 't1', 'job1', 100, 42); // used only 42
    assert.equal(balanceOf(db, 't1').balance, 958); // 1000 - 42
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('releaseAll frees an entire hold (job failure path)', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    grantCredits(db, 't1', 500, 'test');
    holdCredits(db, 't1', 'job1', 200);
    releaseAll(db, 't1', 'job1');
    assert.equal(balanceOf(db, 't1').balance, 500);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('ledger is append-only and records balance_after per entry', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    grantCredits(db, 't1', 100, 'test');
    holdCredits(db, 't1', 'j1', 40);
    commitCredits(db, 't1', 'j1', 40, 25);
    const entries = db.store.find('credit_ledger', (l) => l.tenant_id === 't1');
    assert.ok(entries.length >= 3);
    assert.ok(entries.every((e) => Number.isFinite(e.balance_after)));
    const last = entries[entries.length - 1];
    assert.equal(last.balance_after, balanceOf(db, 't1').balance);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('applyMonthlyGrant is idempotent per period', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    db.insert('subscriptions', { tenant_id: 't1', plan_key: 'pro', status: 'active' });
    applyMonthlyGrant(db, 't1', '2026-09');
    const after1 = balanceOf(db, 't1').balance;
    assert.ok(after1 > 0);
    applyMonthlyGrant(db, 't1', '2026-09'); // duplicate tick — must not double-grant
    assert.equal(balanceOf(db, 't1').balance, after1);
    applyMonthlyGrant(db, 't1', '2026-10'); // next month — grants again
    assert.ok(balanceOf(db, 't1').balance > after1);
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('buildInvoice summarizes committed usage in a period', () => {
  const dir = tmp();
  try {
    const db = openDb(dir);
    grantCredits(db, 't1', 1000, 'test');
    holdCredits(db, 't1', 'j1', 100);
    commitCredits(db, 't1', 'j1', 100, 80);
    holdCredits(db, 't1', 'j2', 100);
    commitCredits(db, 't1', 'j2', 100, 120);
    const inv = buildInvoice(db, 't1', { periodStart: '2000-01-01', periodEnd: '2999-01-01' });
    assert.ok(inv.id);
    assert.equal(inv.lines[1].credits_used, 2); // two job commitments in period
    assert.equal(inv.status, 'issued');
    db.store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('estimateCost prices a service deterministically', () => {
  const cost1 = estimateCost({ key: 'web_audit' }, {});
  const cost2 = estimateCost({ key: 'web_audit' }, {});
  assert.equal(cost1, cost2);
  assert.ok(cost1 >= 0);
});
