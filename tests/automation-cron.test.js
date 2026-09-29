import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCron, nextRun } from '#auto/cron';

test('parseCron accepts standard 5-field expressions', () => {
  for (const ok of ['* * * * *', '0 6 * * 1', '30 4 1,15 * 5', '*/15 * * * *', '0 0 */2 * *']) {
    const c = parseCron(ok);
    assert.ok(c, `should parse: ${ok}`);
  }
});

test('parseCron rejects malformed expressions', () => {
  for (const bad of ['', '* * * *', '61 * * * *', '* 24 * * *', 'a b c d e', '* * * * * * *']) {
    assert.throws(() => parseCron(bad), Error, `should reject: ${bad}`);
  }
});

test('nextRun: every-minute cron fires within the next minute', () => {
  const c = parseCron('* * * * *');
  const now = new Date('2026-09-29T10:30:15Z');
  const next = nextRun(c, now);
  assert.equal(next.toISOString(), '2026-09-29T10:31:00.000Z');
});

test('nextRun: daily at 06:00 UTC', () => {
  const c = parseCron('0 6 * * *');
  const next = nextRun(c, new Date('2026-09-29T10:00:00Z'));
  assert.equal(next.toISOString(), '2026-09-30T06:00:00.000Z');
});

test('nextRun: weekly Monday 06:00', () => {
  const c = parseCron('0 6 * * 1');
  const next = nextRun(c, new Date('2026-09-29T12:00:00Z')); // Tuesday
  assert.equal(next.toISOString(), '2026-10-05T06:00:00.000Z'); // next Monday
  assert.equal(next.getUTCDay(), 1);
});

test('nextRun: step values (*/15 minutes)', () => {
  const c = parseCron('*/15 * * * *');
  const next = nextRun(c, new Date('2026-09-29T10:07:00Z'));
  assert.equal(next.toISOString(), '2026-09-29T10:15:00.000Z');
});

test('nextRun: day-of-month list', () => {
  const c = parseCron('0 0 1,15 * *');
  const next = nextRun(c, new Date('2026-09-29T00:00:00Z'));
  assert.equal(next.toISOString(), '2026-10-01T00:00:00.000Z');
});
