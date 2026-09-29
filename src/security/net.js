import net from 'node:net';
import dns from 'node:dns/promises';
import { badRequest } from '#core/errors';

/** IPv4/IPv6 classification for SSRF defense. */
export function parseIpVersion(ip) {
  if (net.isIPv4(ip)) return 4;
  if (net.isIPv6(ip)) return 6;
  return 0;
}
function v4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
function inCidr4(ip, cidr) {
  const [base, bits] = cidr.split('/');
  const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}
const PRIVATE_V4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4'];
const RESERVED_V6 = ['::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2001:db8::/32', '::ffff:0:0/96'];

export function isPrivateIp(ip) {
  const ver = parseIpVersion(ip);
  if (ver === 4) return PRIVATE_V4.some((c) => inCidr4(ip, c));
  if (ver === 6) {
    const lower = ip.toLowerCase();
    // IPv4-mapped ::ffff:a.b.c.d
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    const first = lower.split(':')[0];
    if (/^(fc|fd)/.test(first)) return true; // fc00::/7 unique local
    if (first === 'fe8' || /^(fe9|fea|feb)/.test(first)) return true; // link local
    if (lower === '::1' || lower === '::') return true;
    if (first.startsWith('ff')) return true; // multicast
    return false;
  }
  return true; // not an IP at all → treat conservatively
}
export function isLoopbackHost(host) {
  const h = String(host).toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '127.0.0.1' || h.startsWith('127.');
}

/**
 * Validate an outbound URL for engine fetches (SSRF defense).
 * - only http/https
 * - resolves DNS once and rejects private/reserved targets unless explicitly allowed
 *   (allowPrivate is only set for explicitly-authorized internal/dev targets)
 */
export async function assertFetchAllowed(url, { allowPrivate = false } = {}) {
  let u;
  try { u = new URL(url); } catch { throw badRequest(`invalid URL: ${url}`); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw badRequest('only http/https URLs are permitted');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isLoopbackHost(host)) {
    if (!allowPrivate) throw badRequest(`target host not permitted (loopback): ${host}`);
    return { url: u, host, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80) };
  }
  if (net.isIP(host)) {
    if (isPrivateIp(host) && !allowPrivate) throw badRequest(`target IP not permitted (private/reserved): ${host}`);
    return { url: u, host, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80) };
  }
  // resolve and check every address (mitigates multi-A-record SSRF bypass)
  try {
    const addrs = await dns.lookup(host, { all: true, verbatim: true });
    if (!addrs.length) throw new Error('no addresses');
    for (const a of addrs) {
      if (isPrivateIp(a.address) && !allowPrivate) throw badRequest(`target host resolves to private/reserved address: ${host} → ${a.address}`);
    }
    return { url: u, host, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80) };
  } catch (e) {
    if (e && e.code === 'ERR_INVALID_URL') throw e;
    throw badRequest(`DNS resolution failed for ${host}`);
  }
}

/** Same-origin-ish scope enforcement for authorized security testing. */
export function hostMatchesScope(hostname, scope) {
  if (!Array.isArray(scope) || !scope.length) return false;
  const h = hostname.toLowerCase();
  return scope.some((s) => {
    const pat = String(s).toLowerCase().replace(/^\*\./, '');
    if (pat.startsWith('*.')) return h.endsWith(pat.slice(1));
    return h === pat || h.endsWith(`.${pat}`);
  });
}
