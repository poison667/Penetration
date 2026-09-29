import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Db } from '#app/db';
import { openStore } from '#store/store';
import { validateWorkflowDefinition, saveWorkflow, runWorkflow } from '#auto/workflow';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const tmp = () => mkdtempSync(join(tmpdir(), 'meridian-wf-'));

test('validateWorkflowDefinition enforces step ids, uniqueness and known types', () => {
  validateWorkflowDefinition({ steps: [{ id: 's1', type: 'notify' }] });
  assert.throws(() => validateWorkflowDefinition({ steps: [{ type: 'notify' }] }), /string id/);
  assert.throws(() => validateWorkflowDefinition({ steps: [{ id: 'a', type: 'notify' }, { id: 'a', type: 'notify' }] }), /duplicate/);
  assert.throws(() => validateWorkflowDefinition({ steps: [{ id: 'a', type: 'nonsense' }] }), /unknown step type/);
  assert.throws(() => validateWorkflowDefinition({}), /non-empty array/);
  assert.throws(() => validateWorkflowDefinition({ steps: [] }), /non-empty array/);
});

test('saveWorkflow versions definitions and keeps history', () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const v1 = saveWorkflow(db, 't1', { name: 'flow', definition: { steps: [{ id: 's1', type: 'notify', title: 'v1' }] } });
    assert.equal(v1.version, 1);
    const v2 = saveWorkflow(db, 't1', { id: v1.id, name: 'flow', definition: { steps: [{ id: 's1', type: 'notify', title: 'v2' }] } });
    assert.equal(v2.version, 2);
    const unchanged = saveWorkflow(db, 't1', { id: v1.id, name: 'flow', definition: v2.definition });
    assert.equal(unchanged.version, 2); // no change → no new version
    const versions = db.store.find('workflow_versions', (v) => v.workflow_id === v1.id);
    assert.equal(versions.length, 2);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('runWorkflow executes a notify step and records step states', async () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const wf = saveWorkflow(db, 't1', { name: 'notify-flow', definition: { steps: [{ id: 'notify1', type: 'notify', title: 'Pipeline alert', body: 'workflow executed' }] } });
    const run = await runWorkflow(db, 't1', wf.id, { event: { type: 'manual', detail: { user: 'tester' } } });
    assert.equal(run.state, 'completed');
    assert.equal(run.step_states.length, 1);
    assert.equal(run.step_states[0].step_id, 'notify1');
    assert.equal(run.step_states[0].state, 'succeeded');
    // the notification really landed
    const notes = db.store.find('notifications', (n) => n.tenant_id === 't1');
    assert.ok(notes.some((n) => n.title === 'Pipeline alert'), 'expected a notification from the workflow');
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('runWorkflow handles failures without losing state', async () => {
  const dir = tmp();
  try {
    const store = openStore(dir);
    const db = new Db(store);
    const wf = saveWorkflow(db, 't1', { name: 'failing', definition: { steps: [{ id: 'bad', type: 'api_call', url: 'http://127.0.0.1:1/unreachable', fail_on_error: true }] } });
    const run = await runWorkflow(db, 't1', wf.id, { event: { type: 'manual' } });
    assert.equal(run.state, 'failed');
    assert.ok(run.error);
    store.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
