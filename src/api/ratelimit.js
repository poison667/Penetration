import { RateLimiter } from '#sec/http';

let globalLimiter = null;
export function rateLimiter() {
  if (!globalLimiter) globalLimiter = new RateLimiter();
  return globalLimiter;
}
