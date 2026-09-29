import { validationError } from './errors.js';

/**
 * Tiny declarative validator library (zero dependencies).
 * Each validator: (value) => {ok:boolean, value?:coerced, error?:string}
 */
const isStr = (v) => typeof v === 'string';
const fail = (error) => ({ ok: false, error });

export const V = {
  any: () => (v) => ({ ok: true, value: v }),
  string({ min = 0, max = 100000, pattern, trim = true } = {}) {
    return (v) => {
      if (v == null) v = '';
      if (!isStr(v)) return fail('expected string');
      let s = trim ? v.trim() : v;
      if (s.length < min) return fail(`min length ${min}`);
      if (s.length > max) return fail(`max length ${max}`);
      if (pattern && !new RegExp(pattern).test(s)) return fail(`must match ${pattern}`);
      return { ok: true, value: s };
    };
  },
  email() {
    return (v) => {
      if (!isStr(v)) return fail('expected email');
      const s = v.trim().toLowerCase();
      if (!/^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(s)) return fail('invalid email address');
      return { ok: true, value: s };
    };
  },
  password() {
    return (v) => {
      if (!isStr(v)) return fail('expected password');
      if (v.length < 10) return fail('password must be at least 10 characters');
      if (v.length > 512) return fail('password too long');
      if (!/[a-z]/.test(v) || !/[A-Z]/.test(v) || !/[0-9]/.test(v)) return fail('password must contain lower, upper and digit');
      return { ok: true, value: v };
    };
  },
  int({ min = -Infinity, max = Infinity } = {}) {
    return (v) => {
      const n = typeof v === 'number' ? v : typeof v === 'string' && /^-?\d+$/.test(v.trim()) ? Number(v) : NaN;
      if (!Number.isInteger(n)) return fail('expected integer');
      if (n < min || n > max) return fail(`expected integer in [${min}, ${max}]`);
      return { ok: true, value: n };
    };
  },
  number({ min = -Infinity, max = Infinity } = {}) {
    return (v) => {
      const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' && !isNaN(Number(v)) ? Number(v) : NaN;
      if (typeof n !== 'number' || Number.isNaN(n)) return fail('expected number');
      if (n < min || n > max) return fail(`expected number in [${min}, ${max}]`);
      return { ok: true, value: n };
    };
  },
  boolean() {
    return (v) => {
      if (typeof v === 'boolean') return { ok: true, value: v };
      if (v === 'true') return { ok: true, value: true };
      if (v === 'false') return { ok: true, value: false };
      return fail('expected boolean');
    };
  },
  enum(options) {
    return (v) => (options.includes(v) ? { ok: true, value: v } : fail(`expected one of: ${options.join(', ')}`));
  },
  isoDate() {
    return (v) => {
      if (!isStr(v) || isNaN(Date.parse(v))) return fail('expected ISO date');
      return { ok: true, value: new Date(v).toISOString() };
    };
  },
  url({ allowPrivate = false, schemes = ['http:', 'https:'] } = {}) {
    return (v) => {
      if (!isStr(v)) return fail('expected URL');
      let u;
      try { u = new URL(v.trim()); } catch { return fail('invalid URL'); }
      if (!schemes.includes(u.protocol)) return fail(`scheme must be one of ${schemes.join('/')}`);
      if (!allowPrivate && /^(localhost|127\.|0\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|\[?::1\]?)/i.test(u.hostname)) {
        return fail('private/loopback hosts not allowed');
      }
      return { ok: true, value: u.toString() };
    };
  },
  array(itemValidator, { min = 0, max = 10000 } = {}) {
    return (v) => {
      if (!Array.isArray(v)) return fail('expected array');
      if (v.length < min || v.length > max) return fail(`array length must be in [${min}, ${max}]`);
      const out = [];
      for (let i = 0; i < v.length; i++) {
        const r = itemValidator(v[i]);
        if (!r.ok) return fail(`[${i}] ${r.error}`);
        out.push(r.value);
      }
      return { ok: true, value: out };
    };
  },
  object(schema, { allowUnknown = false } = {}) {
    return (v) => {
      if (v === null || typeof v !== 'object' || Array.isArray(v)) return fail('expected object');
      const out = {};
      for (const [k, validator] of Object.entries(schema)) {
        const present = Object.prototype.hasOwnProperty.call(v, k);
        if (!present) {
          if (validator.isOptional) continue;
          return fail(`missing field: ${k}`);
        }
        const r = validator(v[k]);
        if (!r.ok) return fail(`${k}: ${r.error}`);
        out[k] = r.value;
      }
      if (allowUnknown) for (const k of Object.keys(v)) if (!(k in out)) out[k] = v[k];
      return { ok: true, value: out };
    };
  },
  record(valueValidator) {
    return (v) => {
      if (v === null || typeof v !== 'object' || Array.isArray(v)) return fail('expected object');
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        const r = valueValidator(val);
        if (!r.ok) return fail(`${k}: ${r.error}`);
        out[k] = r.value;
      }
      return { ok: true, value: out };
    };
  },
  /** nullable wrapper */
  nullable(validator) {
    return (v) => (v === null || v === undefined ? { ok: true, value: null } : validator(v));
  },
  /** optional field marker (use as value in object schema) */
  optional: null,
};
/**
 * Attach optional-chaining to a validator factory.
 * Supports three call styles:
 *   V.string.optional({...})      — factory-level optional
 *   V.string({...}).optional()    — instance-level optional (chain)
 *   V.enum([...]).optional        — bare reference (validator with isOptional=true)
 */
function withOptional(factory) {
  const mk = (v, isOpt) => {
    if (isOpt) v.isOptional = true;
    const opt = (...a) => (a.length === 0 ? ((v.isOptional = true), v) : v(a[0]));
    opt.isOptional = true;
    v.optional = opt;
    return v;
  };
  const f = (...args) => mk(factory(...args), false);
  f.optional = (...args) => mk(factory(...args), true);
  return f;
}
for (const name of ['string', 'int', 'number', 'boolean', 'enum', 'isoDate', 'url', 'email', 'password', 'array', 'object', 'record', 'any', 'nullable']) {
  V[name] = withOptional(V[name]);
}

/**
 * Validate input against a schema object.
 * @returns {object} cleaned value
 * @throws AppError(422) with details
 */
export function validate(schema, input, { partial = false } = {}) {
  const errors = [];
  const out = {};
  const src = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const validators = partial
    ? Object.fromEntries(Object.entries(schema).filter(([k]) => Object.prototype.hasOwnProperty.call(src, k)))
    : schema;
  for (const [k, validator] of Object.entries(validators)) {
    const present = Object.prototype.hasOwnProperty.call(src, k);
    if (!present) {
      if (validator.isOptional || partial) continue;
      errors.push({ field: k, message: 'missing required field' });
      continue;
    }
    const r = validator(src[k]);
    if (!r.ok) errors.push({ field: k, message: r.error });
    else out[k] = r.value;
  }
  if (errors.length) throw validationError(errors);
  return out;
}
