import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, timingSafeEqualStr, generateTotpSecret, totpNow, verifyTotp, hotp, otpauthUrl, base32Encode, sealSecret, openSecret, loadOrCreateSecretKey, setSecretKey } from '#sec/crypto';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('hashPassword / verifyPassword roundtrip with scrypt', () => {
  const h = hashPassword('Demo!Passw0rd');
  assert.match(h, /^scrypt\$/);
  assert.equal(verifyPassword('Demo!Passw0rd', h), true);
  assert.equal(verifyPassword('WrongPass1', h), false);
  // unique salts per hash
  assert.notEqual(h, hashPassword('Demo!Passw0rd'));
});

test('verifyPassword rejects malformed stored hashes', () => {
  assert.equal(verifyPassword('x', 'not-a-hash'), false);
  assert.equal(verifyPassword('x', ''), false);
});

test('timingSafeEqualStr compares without early exit', () => {
  assert.equal(timingSafeEqualStr('abc', 'abc'), true);
  assert.equal(timingSafeEqualStr('abc', 'abd'), false);
  assert.equal(timingSafeEqualStr('abc', 'abcd'), false);
  assert.equal(timingSafeEqualStr('', ''), true);
});

test('HOTP matches RFC 4226 reference vectors (secret "12345678901234567890")', () => {
  // RFC 4226 Appendix D test vectors
  const key = Buffer.from('12345678901234567890', 'ascii');
  const vectors = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  vectors.forEach((expected, counter) => {
    assert.equal(hotp(key, counter), expected, `counter ${counter}`);
  });
});

test('TOTP verifies the current code and rejects replay/incorrect codes', () => {
  const secret = generateTotpSecret();
  assert.equal(secret.length, 20); // 160-bit
  const code = totpNow(secret);
  assert.match(code, /^\d{6}$/);
  assert.ok(verifyTotp(secret, code) !== null, 'valid code returns the matched counter');
  assert.equal(verifyTotp(secret, '000000') === null, code !== '000000');
  assert.equal(verifyTotp(secret, 'abc'), null);
  // ±1 step drift accepted
  const drifted = hotp(secret, Math.floor(Date.now() / 1000 / 30) - 1);
  assert.ok(verifyTotp(secret, drifted) !== null, '±1 step drift accepted');
  // replay protection: a code at/below the last-used counter is rejected forever
  const used = verifyTotp(secret, code);
  assert.ok(Number.isInteger(used));
  assert.equal(verifyTotp(secret, code, { lastCounter: used }), null, 'same code cannot be replayed');
  const older = totpNow(secret, { atMs: Date.now() - 60_000 });
  assert.equal(verifyTotp(secret, older, { lastCounter: used }), null, 'older-window codes rejected once a newer one was used');
  const nextStep = (Math.floor(Date.now() / 30_000) + 1) * 30_000; // deterministic: exactly one step ahead
  const newer = totpNow(secret, { atMs: nextStep + 1_000 });
  assert.ok(verifyTotp(secret, newer, { lastCounter: used }) !== null, 'next-window code accepted (within ±1 drift, above last-used counter)');
});

test('otpauthUrl produces a well-formed provisioning URI', () => {
  const url = otpauthUrl('a@b.co', base32Encode(Buffer.alloc(20, 7)));
  assert.match(url, /^otpauth:\/\/totp\/Meridian%3Aa%40b.co\?secret=/);
  assert.match(url, /issuer=Meridian&algorithm=SHA1&digits=6&period=30$/);
});

test('sealSecret / openSecret authenticated encryption roundtrip', () => {
  setSecretKey(crypto.createHash('sha256').update('test-key-material').digest()); // deterministic in-memory key
  const sealed = sealSecret('tenant-secret-material');
  assert.notEqual(sealed, 'tenant-secret-material');
  assert.equal(openSecret(sealed), 'tenant-secret-material');
  // tampered ciphertext fails
  const parts = sealed.split('.');
  const tampered = parts.slice(0, -1).join('.') + '.' + Buffer.from('deadbeef').toString('base64url');
  assert.equal(openSecret(tampered), null);
});

test('loadOrCreateSecretKey persists to disk and reloads deterministically', () => {
  const dir = mkdtempSync(join(tmpdir(), 'meridian-key-'));
  try {
    const k1 = loadOrCreateSecretKey(dir, fs);
    assert.ok(existsSync(join(dir, 'secret.key')));
    const k2 = loadOrCreateSecretKey(dir, fs);
    assert.ok(Buffer.compare(k1, k2) === 0, 'key must be stable across loads');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
