import { test } from 'node:test';
import assert from 'node:assert/strict';
import { V, validate } from '#core/validate';
import { AppError } from '#core/errors';

test('V.string validates length bounds and trims', () => {
  assert.equal(validate({ s: V.string({ min: 2, max: 4 }) }, { s: '  ab  ' }).s, 'ab');
  assert.throws(() => validate({ s: V.string({ min: 5 }) }, { s: 'ab' }), AppError);
  assert.throws(() => validate({ s: V.string({ max: 1 }) }, { s: 'ab' }), AppError);
});

test('V.email normalizes and rejects malformed addresses', () => {
  assert.equal(validate({ e: V.email() }, { e: ' A@B.CO ' }).e, 'a@b.co');
  for (const bad of ['nope', 'a@b', 'a b@c.de', '@x.de']) {
    assert.throws(() => validate({ e: V.email() }, { e: bad }), AppError, `should reject ${bad}`);
  }
});

test('V.password enforces composition policy', () => {
  assert.equal(validate({ p: V.password() }, { p: 'GoodPassw0rd' }).p, 'GoodPassw0rd');
  for (const bad of ['short1A', 'alllowercase1', 'ALLUPPER1', 'NoDigitsHere', 'GoodPass1']) {
    assert.throws(() => validate({ p: V.password() }, { p: bad }), AppError, `should reject ${bad}`);
  }
});

test('V.int / V.number coerce strings and bound ranges', () => {
  assert.equal(validate({ n: V.int({ min: 0, max: 10 }) }, { n: '5' }).n, 5);
  assert.throws(() => validate({ n: V.int() }, { n: 1.5 }), AppError);
  assert.throws(() => validate({ n: V.int({ min: 0 }) }, { n: -1 }), AppError);
  assert.equal(validate({ n: V.number() }, { n: '1.5' }).n, 1.5);
});

test('V.boolean coerces strings', () => {
  assert.equal(validate({ b: V.boolean() }, { b: 'true' }).b, true);
  assert.equal(validate({ b: V.boolean() }, { b: false }).b, false);
  assert.throws(() => validate({ b: V.boolean() }, { b: 'yes' }), AppError);
});

test('V.enum restricts values', () => {
  assert.equal(validate({ e: V.enum(['a', 'b']) }, { e: 'a' }).e, 'a');
  assert.throws(() => validate({ e: V.enum(['a', 'b']) }, { e: 'c' }), AppError);
});

test('V.url rejects private hosts unless allowPrivate', () => {
  assert.throws(() => validate({ u: V.url() }, { u: 'http://127.0.0.1/' }), AppError);
  assert.throws(() => validate({ u: V.url() }, { u: 'http://192.168.0.1/' }), AppError);
  assert.equal(validate({ u: V.url({ allowPrivate: true }) }, { u: 'http://127.0.0.1:8081/' }).u, 'http://127.0.0.1:8081/');
  assert.throws(() => validate({ u: V.url() }, { u: 'ftp://example.com/' }), AppError);
});

test('V.array validates items and length', () => {
  const out = validate({ a: V.array(V.int(), { max: 3 }) }, { a: ['1', 2] });
  assert.deepEqual(out.a, [1, 2]);
  assert.throws(() => validate({ a: V.array(V.int()) }, { a: [1, 'x'] }), AppError);
  assert.throws(() => validate({ a: V.array(V.int(), { max: 1 }) }, { a: [1, 2] }), AppError);
});

test('optional style 1: factory-level V.string.optional({...})', () => {
  const out = validate({ s: V.string.optional({ min: 0, max: 5 }) }, {});
  assert.equal('s' in out, false);
  validate({ s: V.string.optional({ min: 0 }) }, { s: 'ok' });
});

test('optional style 2: instance chain V.string({...}).optional()', () => {
  validate({ s: V.string({ min: 1 }).optional() }, {});
  validate({ a: V.array(V.string(), { max: 2 }).optional() }, {});
  validate({ b: V.boolean().optional() }, {});
  validate({ e: V.enum(['x']).optional() }, { e: 'x' });
});

test('optional style 3: bare reference V.enum([...]).optional', () => {
  validate({ e: V.enum(['x', 'y']).optional }, {});
  assert.throws(() => validate({ e: V.enum(['x', 'y']).optional }, { e: 'z' }), AppError);
});

test('optional fields still validate when present', () => {
  assert.throws(() => validate({ s: V.string({ min: 2 }).optional() }, { s: 'a' }), AppError);
});

test('V.object nested schemas with optional fields', () => {
  const out = validate({ o: V.object({ a: V.string.optional(), b: V.string() }) }, { o: { b: 'x' } });
  assert.deepEqual(out.o, { b: 'x' });
});

test('V.record validates every value', () => {
  const out = validate({ r: V.record(V.any()) }, { r: { x: 1, y: 'z' } });
  assert.deepEqual(out.r, { x: 1, y: 'z' });
});

test('validate collects all errors, not just the first', () => {
  try {
    validate({ a: V.string(), b: V.string() }, {});
    assert.fail('should have thrown');
  } catch (e) {
    assert.equal(e.details.length, 2);
    assert.deepEqual(e.details.map((d) => d.field), ['a', 'b']);
  }
});

test('partial mode only validates provided keys', () => {
  const out = validate({ a: V.string(), b: V.string() }, { b: 'x' }, { partial: true });
  assert.deepEqual(out, { b: 'x' });
});

test('V.isoDate parses and normalizes', () => {
  const out = validate({ d: V.isoDate() }, { d: '2026-01-02T03:04:05Z' });
  assert.equal(out.d, '2026-01-02T03:04:05.000Z');
  assert.throws(() => validate({ d: V.isoDate() }, { d: 'not-a-date' }), AppError);
});

test('non-object input is treated as missing fields, not a crash', () => {
  assert.throws(() => validate({ a: V.string() }, null), AppError);
  assert.throws(() => validate({ a: V.string() }, 'str'), AppError);
});
