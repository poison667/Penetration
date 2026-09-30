import { RateLimiter } from '#sec/http';

/**
 * Rate limiting is per-server-instance: each createServer() gets its own bucket
 * map so isolated test servers never share login/reg counters. In production a
 * single server instance means a single shared map (unchanged behavior).
 */
export function createRateLimiter() {
  return new RateLimiter();
}
