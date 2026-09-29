import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCsv, stringifyCsv } from '#data/csv';

test('parseCsv handles quoted fields, embedded delimiters and newlines', () => {
  const csv = 'id,name,note\n1,"Smith, John","line1\nline2"\n2,Plain,"say ""hi"""\n';
  const { headers, rows } = parseCsv(csv);
  assert.deepEqual(headers, ['id', 'name', 'note']);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].name, 'Smith, John');
  assert.equal(rows[0].note, 'line1\nline2');
  assert.equal(rows[1].note, 'say "hi"');
});

test('parseCsv sniffs semicolon and tab delimiters', () => {
  const semi = parseCsv('a;b\n1;2');
  assert.deepEqual(semi.headers, ['a', 'b']);
  const tab = parseCsv('a\tb\n1\t2');
  assert.deepEqual(tab.headers, ['a', 'b']);
});

test('parseCsv handles CRLF and trailing newline', () => {
  const { rows } = parseCsv('a,b\r\n1,2\r\n');
  assert.deepEqual(rows, [{ a: '1', b: '2' }]);
});

test('stringifyCsv quotes when needed and roundtrips', () => {
  const rows = [
    { a: 'plain', b: 'has,comma', c: 'has "quote"' },
    { a: 'multi\nline', b: '', c: null },
  ];
  const csv = stringifyCsv(rows);
  const back = parseCsv(csv);
  assert.deepEqual(back.rows, [
    { a: 'plain', b: 'has,comma', c: 'has "quote"' },
    { a: 'multi\nline', b: '', c: '' },
  ]);
});

test('empty input yields empty output without errors', () => {
  assert.equal(stringifyCsv([]), '');
  const { headers, rows } = parseCsv('');
  assert.deepEqual(headers, []);
  assert.deepEqual(rows, []);
});

test('delimiter option roundtrips for semicolon files', () => {
  const csv = stringifyCsv([{ x: '1', y: 'a;b' }], { delimiter: ';' });
  assert.ok(csv.includes('"a;b"'));
  const back = parseCsv(csv, { delimiter: ';' });
  assert.equal(back.rows[0].y, 'a;b');
});
