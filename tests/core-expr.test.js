import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, compileExpression } from '#core/expr';

test('arithmetic precedence and parentheses', () => {
  assert.equal(evaluate('1 + 2 * 3'), 7);
  assert.equal(evaluate('(1 + 2) * 3'), 9);
  assert.equal(evaluate('10 % 3'), 1);
  assert.equal(evaluate('-5 + 2'), -3);
  assert.equal(evaluate('2 * -3'), -6);
});

test('comparisons with numeric coercion from strings', () => {
  assert.equal(evaluate('age > 30', { age: '34' }), true);
  assert.equal(evaluate('age > 30', { age: '29' }), false);
  assert.equal(evaluate('x == "a"', { x: 'a' }), true);
  assert.equal(evaluate('x != "a"', { x: 'b' }), true);
  assert.equal(evaluate('n >= 3 && n <= 5', { n: 4 }), true);
});

test('logical operators and negation', () => {
  assert.equal(evaluate('true && false'), false);
  assert.equal(evaluate('true || false'), true);
  assert.equal(evaluate('!false'), true);
  assert.equal(evaluate('!!value', { value: 'x' }), true);
});

test('literals: numbers, strings, booleans, null', () => {
  assert.equal(evaluate('42'), 42);
  assert.equal(evaluate('"hi"'), 'hi');
  assert.equal(evaluate('true'), true);
  assert.equal(evaluate('null'), null);
});

test('$-rooted paths resolve against the $ binding when present', () => {
  const row = { age: '34', name: 'alice', nested: { deep: { v: 9 } } };
  assert.equal(evaluate('$.age', { $: row }), '34');
  assert.equal(evaluate('$.nested.deep.v', { $: row }), 9);
  assert.equal(evaluate('$.age > 30', { $: row, row }), true);
  assert.equal(evaluate('$.missing'), null);
});

test('legacy $.field resolves from root when no $ binding exists', () => {
  // automation rule compatibility: context has fields at root
  assert.equal(evaluate('$.event.type == "down"', { event: { type: 'down' } }), true);
  assert.equal(evaluate('$.status == 200', { $: { status: 200 } }), true);
});

test('bare identifiers and row.xxx chains resolve from root', () => {
  assert.equal(evaluate('age > 30', { age: 34 }), true);
  assert.equal(evaluate('row.name == "alice"', { row: { name: 'alice' } }), true);
  assert.equal(evaluate('monitor.type == "http"', { monitor: { type: 'http' } }), true);
});

test('array length accessor', () => {
  assert.equal(evaluate('$.items.length == 3', { $: { items: [1, 2, 3] } }), true);
});

test('function library', () => {
  assert.equal(evaluate('length("abcd")'), 4);
  assert.equal(evaluate('upper("abc")'), 'ABC');
  assert.equal(evaluate('lower("ABC")'), 'abc');
  assert.equal(evaluate('contains("hello", "ell")'), true);
  assert.equal(evaluate('contains($.name, "lic")', { $: { name: 'alice' } }), true);
  assert.equal(evaluate('abs(0 - 5)'), 5);
  assert.equal(evaluate('round(2.6)'), 3);
  assert.equal(evaluate('min(3, 1, 2)'), 1);
  assert.equal(evaluate('max(3, 1, 2)'), 3);
  assert.equal(evaluate('starts("hello", "he")'), true);
  assert.equal(evaluate('ends("hello", "lo")'), true);
});

test('malformed expressions are rejected at compile time', () => {
  for (const bad of ['1 +', '(1', 'a b', 'foo(', '"unterminated']) {
    assert.throws(() => compileExpression(bad), Error, `should reject: ${bad}`);
  }
});

test('no code execution primitives are reachable (safe evaluator)', () => {
  // the evaluator must not be constructible into arbitrary JS execution
  assert.throws(() => compileExpression('process.exit(1)'));
  assert.equal(evaluate('1 + 1'), 2); // still healthy
});

test('compile-once / evaluate-many', () => {
  const expr = compileExpression('$.v * 2');
  assert.equal(evaluate('$.v * 2', { $: { v: 2 } }), 4);
  assert.ok(typeof expr === 'object');
});
