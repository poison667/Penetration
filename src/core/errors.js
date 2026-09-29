/** Application error with HTTP status, machine code and optional details. */
export class AppError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}
export const badRequest = (msg, details) => new AppError(400, 'bad_request', msg, details);
export const unauthorized = (msg = 'Authentication required') => new AppError(401, 'unauthorized', msg);
export const forbidden = (msg = 'Insufficient permissions') => new AppError(403, 'forbidden', msg);
export const notFound = (msg = 'Resource not found') => new AppError(404, 'not_found', msg);
export const conflict = (msg) => new AppError(409, 'conflict', msg);
export const tooMany = (msg = 'Rate limit exceeded') => new AppError(429, 'rate_limited', msg);
export const payloadTooLarge = (msg = 'Payload too large') => new AppError(413, 'payload_too_large', msg);
export const validationError = (errors) => new AppError(422, 'validation_failed', 'Validation failed', errors);
export const internal = (msg = 'Internal error') => new AppError(500, 'internal', msg);
export const serviceUnavailable = (msg = 'Service unavailable') => new AppError(503, 'unavailable', msg);

/** Wrap unknown thrown values into an AppError. */
export function toAppError(err) {
  if (err instanceof AppError) return err;
  const e = new AppError(500, 'internal', err && err.message ? String(err.message) : 'Internal error');
  if (err && err.stack) e.stack = err.stack;
  return e;
}
