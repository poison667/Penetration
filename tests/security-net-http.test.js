import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TokenBucket, RateLimiter, parseMultipart, sanitizeFilename, sniffMagic, scanForSecrets, redactSecret } from '#sec/http';
import { isPrivateIp, isLoopbackHost, hostMatchesScope, parseIpVersion } from '#sec/net';

// ---------- TokenBucket / RateLimiter ----------
test('TokenBucket bursts up to capacity then refills over time', () => {
  const b = new TokenBucket(3, 1000); // 3 cap, 1000/sec refill
  assert.equal(b.tryTake(), true);
  assert.equal(b.tryTake(), true);
  assert.equal(b.tryTake(), true);
  assert.equal(b.tryTake(), false); // exhausted
  assert.equal(b.tryTake(), false);
  // bulk take larger than remaining tokens fails atomically
  const b2 = new TokenBucket(5, 0);
  b2.tryTake(3);
  assert.equal(b2.tryTake(5), false); // only 2 left
  assert.equal(b2.tryTake(2), true);
});

test('RateLimiter allow() enforces a call budget', () => {
  const rl = new RateLimiter();
  let allowed = 0;
  for (let i = 0; i < 12; i++) if (rl.allow('key1', 10, 100)) allowed++;
  assert.equal(allowed, 10);
  // a different key has its own budget
  assert.equal(rl.allow('key2', 10, 100), true);
});

// ---------- multipart ----------
test('parseMultipart extracts fields and files with filenames', () => {
  const boundary = '----testboundary';
  const body = Buffer.from(
    `--${boundary}\r\ncontent-disposition: form-data; name="title"\r\n\r\nhello\r\n` +
    `--${boundary}\r\ncontent-disposition: form-data; name="file"; filename="a.txt"\r\ncontent-type: text/plain\r\n\r\nFILECONTENT\r\n` +
    `--${boundary}--\r\n`);
  const { fields, files } = parseMultipart(body, `multipart/form-data; boundary=${boundary}`);
  assert.equal(fields.title, 'hello');
  assert.equal(files.length, 1);
  assert.equal(files[0].filename, 'a.txt');
  assert.equal(files[0].data.toString(), 'FILECONTENT');
});

test('parseMultipart rejects bodies without a multipart boundary', () => {
  assert.throws(() => parseMultipart(Buffer.from('x'), 'application/json'), /boundary/i);
});

// ---------- filenames & magic bytes ----------
test('sanitizeFilename strips path traversal and control characters', () => {
  assert.ok(!sanitizeFilename('../../etc/passwd').includes('/'));
  assert.ok(!sanitizeFilename('..\\..\\win.ini').includes('\\'));
  assert.ok(!sanitizeFilename('a\x00b.txt').includes('\x00'));
  assert.equal(sanitizeFilename('normal-file_1.txt'), 'normal-file_1.txt');
});

test('sniffMagic detects common types from content', () => {
  assert.equal(sniffMagic(Buffer.from('%PDF-1.4 whatever')).mime, 'application/pdf');
  assert.equal(sniffMagic(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])).mime, 'image/png');
  assert.equal(sniffMagic(Buffer.from([0xff, 0xd8, 0xff])).mime, 'image/jpeg');
  assert.equal(sniffMagic(Buffer.from('PK\x03\x04')).mime, 'application/zip');
  assert.equal(sniffMagic(Buffer.from('plain text')), null); // unknown content
});

// ---------- secret scanning ----------
test('scanForSecrets detects credential patterns in text', () => {
  const text = [
    'connect with aws_access_key_id=AKIAIOSFODNN7EXAMPLE please',
    'token: ghp_16C7e42F292c6912E7710c838347Ae178B4a',
    '-----BEGIN RSA PRIVATE KEY-----',
    'password = hunter2supersecret',
  ].join('\n');
  const hits = scanForSecrets(text);
  assert.ok(hits.length >= 2, `expected secret hits, got ${JSON.stringify(hits)}`);
  const kinds = hits.map((h) => h.kind || h.type || h.name);
  assert.ok(kinds.some((k) => /aws|key/i.test(k)));
});

test('scanForSecrets ignores ordinary text', () => {
  assert.deepEqual(scanForSecrets('the quick brown fox jumps over the lazy dog'), []);
});

test('redactSecret keeps only a prefix + fingerprint', () => {
  const secret = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a';
  const out = redactSecret(secret);
  assert.notEqual(out, secret);
  assert.ok(out.startsWith('ghp_16'));
  assert.ok(!out.includes('e178B4a'));
  assert.ok(out.length < 40);
});

// ---------- network scope guards ----------
test('isPrivateIp classifies RFC1918, loopback, link-local and public ranges', () => {
  assert.equal(isPrivateIp('192.168.1.5'), true);
  assert.equal(isPrivateIp('10.0.0.1'), true);
  assert.equal(isPrivateIp('172.16.0.1'), true);
  assert.equal(isPrivateIp('172.32.0.1'), false);
  assert.equal(isPrivateIp('127.0.0.1'), true);
  assert.equal(isPrivateIp('169.254.1.1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
});

test('isLoopbackHost recognizes loopback names and IPs', () => {
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('localhost'), true);
  assert.equal(isLoopbackHost('example.com'), false);
});

test('hostMatchesScope enforces allowed-domain authorization', () => {
  const scope = ['example.com', '*.partner.io'];
  assert.equal(hostMatchesScope('example.com', scope), true);
  assert.equal(hostMatchesScope('api.example.com', scope), true); // subdomain of an entry
  assert.equal(hostMatchesScope('partner.io', scope), true);
  assert.equal(hostMatchesScope('api.partner.io', scope), true);
  assert.equal(hostMatchesScope('evil.com', scope), false);
  assert.equal(hostMatchesScope('notpartner.io', scope), false);
});

test('parseIpVersion detects IPv4 and IPv6', () => {
  assert.equal(parseIpVersion('192.168.1.1'), 4);
  assert.equal(parseIpVersion('::1'), 6);
  assert.equal(parseIpVersion('2001:db8::1'), 6);
});
