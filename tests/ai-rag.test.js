import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, chunkText, BM25Index } from '#ai/rag';

test('tokenize lowercases and strips punctuation', () => {
  assert.deepEqual(tokenize('Hello, World! hello'), ['hello', 'world', 'hello']);
  assert.deepEqual(tokenize(''), []);
});

test('chunkText splits long text with overlap and preserves content', () => {
  const long = Array.from({ length: 300 }, (_, i) => `word${i}`).join(' ');
  const chunks = chunkText(long, { chunkChars: 900, overlap: 120 });
  assert.ok(chunks.length >= 2);
  // every word must appear in at least one chunk
  const joined = chunks.join(' ');
  assert.ok(joined.includes('word0'));
  assert.ok(joined.includes('word299'));
  // overlap: the tail of chunk i appears at the head of chunk i+1
  const tail = chunks[0].slice(-100);
  assert.ok(chunks[1].includes(tail.slice(40)), 'expected overlap between consecutive chunks');
});

test('chunkText returns short text as a single chunk (content is never lost)', () => {
  assert.deepEqual(chunkText('short text'), ['short text']);
  assert.deepEqual(chunkText('tiny'), ['tiny']);
  assert.deepEqual(chunkText('   '), []);
});

test('BM25Index ranks relevant documents above irrelevant ones', () => {
  const docs = [
    { id: 'd1', text: 'Cross-site scripting allows attackers to inject scripts into web pages viewed by users.' },
    { id: 'd2', text: 'Database indexes improve query performance for large tables.' },
    { id: 'd3', text: 'Session fixation occurs when the session identifier is not rotated after authentication.' },
  ];
  const idx = new BM25Index();
  for (const d of docs) idx.add(d.id, d.text);
  const hits = idx.search('session fixation authentication', { limit: 3 });
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].id, 'd3');
  assert.ok(hits[0].score > 0);

  const xss = idx.search('cross-site scripting inject', { limit: 3 });
  assert.equal(xss[0].id, 'd1');
});

test('BM25Index handles terms absent from the corpus gracefully', () => {
  const idx = new BM25Index();
  idx.add('d1', 'alpha beta');
  assert.deepEqual(idx.search('zzzqqq', { limit: 5 }), []);
});

test('BM25Index empty corpus does not throw', () => {
  const idx = new BM25Index();
  assert.deepEqual(idx.search('anything', { limit: 5 }), []);
});
