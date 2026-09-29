import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { sha256, hmacSha256, base32Encode, base32Decode, newId, randomToken, nowIso, clamp, canonicalJson, truncateStr, pick, omit, isPlainObject, deepGet, formatBytes, mean, median, percentile, stddev } from '#core/util';

test('sha256 produces stable hex digests', () => {
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('hmacSha256 matches RFC 4231 test case 2', () => {
  // key "Jefe", data "what do ya want for nothing?"
  assert.equal(
    hmacSha256('Jefe', 'what do ya want for nothing?'),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  );
});

test('base32 encode/decode roundtrips (RFC 4648)', () => {
  for (const buf of [Buffer.from(''), Buffer.from('f'), Buffer.from('fo'), Buffer.from('foo'), Buffer.from('foob'), Buffer.from('fooba'), Buffer.from('foobar'), crypto.randomBytes(20)]) {
    assert.ok(base32Decode(base32Encode(buf)).equals(buf), `roundtrip failed for ${buf.length} bytes`);
  }
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI'); // unpadded RFC 4648
});

test('newId prefixes and uniqueness', () => {
  const a = newId('job');
  const b = newId('job');
  assert.ok(a.startsWith('job_'));
  assert.notEqual(a, b);
});

test('randomToken has requested entropy and charset', () => {
  const t = randomToken(32);
  assert.equal(t.length, 43); // 32 bytes base64url
  assert.match(t, /^[A-Za-z0-9_-]+$/);
});

test('nowIso returns parseable ISO timestamps', () => {
  const t = nowIso();
  assert.ok(!Number.isNaN(Date.parse(t)));
});

test('clamp bounds values', () => {
  assert.equal(clamp(5, 0, 3), 3);
  assert.equal(clamp(-2, 0, 3), 0);
  assert.equal(clamp(2, 0, 3), 2);
});

test('canonicalJson sorts keys deterministically', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), canonicalJson({ a: { c: 3, d: 2 }, b: 1 }));
  assert.notEqual(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 1, a: 2 }));
});

test('truncateStr cuts content and marks the truncation', () => {
  const out = truncateStr('abcdef', 3);
  assert.ok(out.startsWith('abc'));
  assert.ok(out.includes('truncated'));
  assert.equal(truncateStr('ab'), 'ab');
});

test('pick/omit select and drop keys', () => {
  assert.deepEqual(pick({ a: 1, b: 2, c: 3 }, ['a', 'c']), { a: 1, c: 3 });
  assert.deepEqual(omit({ a: 1, b: 2, c: 3 }, ['b']), { a: 1, c: 3 });
});

test('isPlainObject distinguishes object kinds', () => {
  assert.equal(isPlainObject({}), true);
  assert.equal(isPlainObject([]), false);
  assert.equal(isPlainObject(null), false);
  assert.equal(isPlainObject('x'), false);
});

test('deepGet walks dot paths', () => {
  assert.equal(deepGet({ a: { b: { c: 7 } } }, 'a.b.c'), 7);
  assert.equal(deepGet({ a: 1 }, 'a.z'), undefined);
});

test('formatBytes renders human sizes', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(2048), '2.0 KB');
  assert.equal(formatBytes(1024 * 1024 * 5), '5.00 MB');
});

test('statistics helpers: mean, median, percentile, stddev', () => {
  assert.equal(mean([1, 2, 3, 4]), 2.5);
  assert.equal(mean([]), 0);
  assert.equal(median([5, 1, 3]), 3);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(percentile([1, 2, 3, 4, 5], 50), 3);
  assert.equal(percentile([1, 2, 3, 4, 5], 0), 1);
  assert.equal(percentile([1, 2, 3, 4, 5], 100), 5);
  assert.ok(Math.abs(stddev([2, 4, 4, 4, 5, 5, 7, 9]) - 2.138089935) < 1e-6); // sample stddev (n-1)
});
