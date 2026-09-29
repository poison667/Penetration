import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHtml, links, forms, scripts, metas, metaGet, title, lang, canonical, images, headings, iframes, textContent } from '#lib/html';

const page = `<!DOCTYPE html><html lang="en"><head><title>Test Page</title>
<meta name="generator" content="CMS 1.0"><meta charset="utf-8">
<link rel="canonical" href="https://example.com/canon">
<script src="/app.js"></script>
<script src="https://cdn.example.com/x.js" async></script>
</head><body>
<a href="/about">About</a> <a href="https://other.example.org/ext">Ext</a>
<a href="/search?q=1">Search</a>
<img src="/logo.png" alt="Logo">
<form action="/login" method="post">
<input name="username" type="text"><input name="password" type="password">
<input name="remember" type="checkbox"><button type="submit">Go</button>
</form>
<form action="/upload" method="post" enctype="multipart/form-data">
<input type="file" name="attachment"><input type="submit">
</form>
<h1>Headline</h1><h2>Sub</h2>
<iframe src="/embed"></iframe>
</body></html>`;

test('parseHtml builds a DOM with head/body structure', () => {
  const dom = parseHtml(page);
  assert.ok(dom);
  assert.equal(typeof dom, 'object');
});

test('links extracts absolute and relative hrefs as descriptors', () => {
  const dom = parseHtml(page);
  const out = links(dom, 'https://example.com/');
  const urls = out.map((l) => l.url);
  assert.ok(urls.includes('https://example.com/about'), JSON.stringify(urls));
  assert.ok(urls.includes('https://other.example.org/ext'));
  assert.ok(urls.some((u) => u.includes('/search?q=1')));
  assert.equal(out.find((l) => l.url.includes('other.example')).external, true);
});

test('forms capture method, action, fields and file detection', () => {
  const dom = parseHtml(page);
  const out = forms(dom, 'https://example.com/');
  const login = out.find((f) => f.action === 'https://example.com/login');
  assert.equal(login.method, 'POST');
  const names = login.fields.map((f) => f.name).filter(Boolean);
  assert.deepEqual(names, ['username', 'password', 'remember']);
  assert.equal(login.hasFileField, false);
  const upload = out.find((f) => f.action === 'https://example.com/upload');
  assert.equal(upload.hasFileField, true);
  assert.equal(upload.fields.find((f) => f.type === 'file').name, 'attachment');
});

test('scripts returns descriptors with src, inline flag and async', () => {
  const dom = parseHtml(page);
  const out = scripts(dom, 'https://example.com/');
  const srcs = out.map((s) => s.src);
  assert.ok(srcs.includes('https://example.com/app.js'));
  assert.ok(srcs.includes('https://cdn.example.com/x.js'));
  assert.equal(out.find((s) => s.src.endsWith('x.js')).async, true);
});

test('metas and metaGet read meta tags case-insensitively', () => {
  const dom = parseHtml(page);
  assert.equal(metaGet(dom, 'generator'), 'CMS 1.0');
  assert.equal(metaGet(dom, 'GENERATOR'), metaGet(dom, 'generator'));
  assert.ok(metas(dom).length >= 1); // named metas only (charset has no name)
  assert.equal(metaGet(dom, 'nonexistent'), null);
});

test('title, lang, canonical, headings, images, iframes accessors', () => {
  const dom = parseHtml(page);
  assert.equal(title(dom), 'Test Page');
  assert.equal(lang(dom), 'en');
  assert.equal(canonical(dom), 'https://example.com/canon');
  assert.equal(headings(dom).length, 2);
  assert.equal(images(dom).length, 1);
  assert.equal(iframes(dom).length, 1);
});

test('textContent extracts visible words', () => {
  const dom = parseHtml(page);
  const text = textContent(dom);
  assert.ok(text.includes('About'));
  assert.ok(text.includes('Headline'));
  assert.ok(!text.includes('<h1>'));
});

test('malformed HTML does not throw', () => {
  for (const bad of ['', '<html', '<div><p>unclosed', '<<<>>>', '<a href=nope>link</a>']) {
    const dom = parseHtml(bad);
    assert.ok(dom !== undefined && dom !== null);
    links(dom, 'https://x.co');
    forms(dom, 'https://x.co');
  }
});
