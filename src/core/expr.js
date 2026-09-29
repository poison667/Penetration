/**
 * Safe expression evaluator (no eval/Function). Used for:
 *  - data transformation pipelines (derive/filter columns)
 *  - automation rule conditions (e.g. $.event.type == 'down' && $.monitor.type == 'http')
 * Grammar: literals (number/string/true/false/null), $-rooted paths ($.a.b[0].c),
 * unary ! -, arithmetic + - * / %, comparisons, == != <= >= < >, && ||, parentheses,
 * and a small function library (length, upper, lower, contains, abs, round, min, max, now).
 */

const FUNCS = {
  length: (x) => (x == null ? 0 : Array.isArray(x) || typeof x === 'string' ? x.length : Object.keys(x).length),
  upper: (s) => String(s ?? '').toUpperCase(),
  lower: (s) => String(s ?? '').toLowerCase(),
  contains: (hay, needle) => String(hay ?? '').includes(String(needle ?? '')),
  abs: Math.abs, round: Math.round, floor: Math.floor, ceil: Math.ceil,
  min: (...a) => Math.min(...a), max: (...a) => Math.max(...a),
  starts: (s, p) => String(s ?? '').startsWith(String(p ?? '')),
  ends: (s, p) => String(s ?? '').endsWith(String(p ?? '')),
};

export function compileExpression(source) {
  const tokens = tokenize(String(source));
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function parseExpr() { return parseOr(); }
  function parseOr() {
    let left = parseAnd();
    while (peek() && peek().type === 'op' && peek().value === '||') { next(); left = { type: 'or', left, right: parseAnd() }; }
    return left;
  }
  function parseAnd() {
    let left = parseEquality();
    while (peek() && peek().type === 'op' && peek().value === '&&') { next(); left = { type: 'and', left, right: parseEquality() }; }
    return left;
  }
  function parseEquality() {
    let left = parseCompare();
    while (peek() && peek().type === 'op' && ['==', '!=', '===', '!=='].includes(peek().value)) {
      const op = next().value;
      left = { type: 'binary', op, left, right: parseCompare() };
    }
    return left;
  }
  function parseCompare() {
    let left = parseAdditive();
    while (peek() && peek().type === 'op' && ['<', '<=', '>', '>='].includes(peek().value)) {
      const op = next().value;
      left = { type: 'binary', op, left, right: parseAdditive() };
    }
    return left;
  }
  function parseAdditive() {
    let left = parseMultiplicative();
    while (peek() && peek().type === 'op' && ['+', '-'].includes(peek().value)) {
      const op = next().value;
      left = { type: 'binary', op, left, right: parseMultiplicative() };
    }
    return left;
  }
  function parseMultiplicative() {
    let left = parseUnary();
    while (peek() && peek().type === 'op' && ['*', '/', '%'].includes(peek().value)) {
      const op = next().value;
      left = { type: 'binary', op, left, right: parseUnary() };
    }
    return left;
  }
  function parseUnary() {
    if (peek() && peek().type === 'op' && peek().value === '!') { next(); return { type: 'not', expr: parseUnary() }; }
    if (peek() && peek().type === 'op' && peek().value === '-') { next(); return { type: 'neg', expr: parseUnary() }; }
    return parsePrimary();
  }
  function parsePrimary() {
    const t = next();
    if (!t) throw new Error('unexpected end of expression');
    if (t.type === 'number') return { type: 'lit', value: t.value };
    if (t.type === 'string') return { type: 'lit', value: t.value };
    if (t.type === 'bool') return { type: 'lit', value: t.value };
    if (t.type === 'null') return { type: 'lit', value: null };
    if (t.type === 'path') {
      let node = { type: 'path', parts: t.value };
      while (peek() && peek().type === 'dot') {
        next();
        const prop = next();
        if (!prop || prop.type !== 'ident') throw new Error('expected property after "."');
        node.parts.push(prop.value);
      }
      return node;
    }
    if (t.type === 'ident') {
      if (peek() && peek().type === 'lparen') {
        next();
        const args = [];
        if (peek() && peek().type !== 'rparen') {
          args.push(parseExpr());
          while (peek() && peek().type === 'comma') { next(); args.push(parseExpr()); }
        }
        const close = next();
        if (!close || close.type !== 'rparen') throw new Error('expected )');
        return { type: 'call', name: t.value, args };
      }
      // bare identifier: treat as path from root (for simple contexts); allow .prop chaining
      const node = { type: 'path', parts: [t.value] };
      while (peek() && peek().type === 'dot') {
        next();
        const prop = next();
        if (!prop || prop.type !== 'ident') throw new Error('expected property after "."');
        node.parts.push(prop.value);
      }
      return node;
    }
    if (t.type === 'lparen') {
      const inner = parseExpr();
      const close = next();
      if (!close || close.type !== 'rparen') throw new Error('expected )');
      return inner;
    }
    throw new Error(`unexpected token: ${t.type}:${t.value}`);
  }

  const ast = parseExpr();
  if (pos !== tokens.length) throw new Error(`unexpected token after expression: ${tokens[pos]?.value}`);

  return { ast, source: String(source) };
}

function tokenize(src) {
  const tokens = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '$') { i++; const parts = ['$']; if (src[i] === '.') i++; continuePath(parts); tokens.push({ type: 'path', value: parts }); continue; }
    if (/[0-9]/.test(ch) || (ch === '.' && /[0-9]/.test(src[i + 1] || ''))) {
      let j = i; while (j < src.length && /[0-9.]/.test(src[j])) j++;
      tokens.push({ type: 'number', value: Number(src.slice(i, j)) }); i = j; continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1, out = '';
      while (j < src.length && src[j] !== ch) {
        if (src[j] === '\\' && j + 1 < src.length) { out += escapeChar(src[j + 1]); j += 2; }
        else { out += src[j]; j++; }
      }
      if (j >= src.length) throw new Error('unterminated string');
      tokens.push({ type: 'string', value: out }); i = j + 1; continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i; while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      if (word === 'true' || word === 'false') tokens.push({ type: 'bool', value: word === 'true' });
      else if (word === 'null') tokens.push({ type: 'null' });
      else tokens.push({ type: 'ident', value: word });
      i = j; continue;
    }
    let multi = null;
    for (const op of ['===', '!==', '==', '!=', '<=', '>=', '&&', '||']) {
      if (src.startsWith(op, i)) { multi = op; break; }
    }
    if (multi) { tokens.push({ type: 'op', value: multi }); i += multi.length; continue; }
    if ('+-*/%<>!'.includes(ch)) { tokens.push({ type: 'op', value: ch }); i++; continue; }
    if (ch === '(') { tokens.push({ type: 'lparen' }); i++; continue; }
    if (ch === ')') { tokens.push({ type: 'rparen' }); i++; continue; }
    if (ch === ',') { tokens.push({ type: 'comma' }); i++; continue; }
    if (ch === '.') { tokens.push({ type: 'dot' }); i++; continue; }
    throw new Error(`unexpected character in expression: "${ch}"`);
  }
  return tokens;

  function continuePath(parts) {
    let j = i;
    let name = '';
    while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) { name += src[j]; j++; }
    if (name) parts.push(name);
    i = j;
    while (src[i] === '.' || src[i] === '[') {
      if (src[i] === '.') {
        i++; let n = ''; while (i < src.length && /[A-Za-z0-9_]/.test(src[i])) { n += src[i]; i++; }
        if (n) parts.push(n);
      } else {
        i++; let n = ''; while (i < src.length && src[i] !== ']') { n += src[i]; i++; }
        i++; // ]
        parts.push(/^\d+$/.test(n) ? Number(n) : n);
      }
    }
  }
}
function op0(v) { return v; }
function escapeChar(c) { return { n: '\n', t: '\t', r: '\r' }[c] || c; }

export function evalExpression(compiled, context) {
  function ev(node) {
    switch (node.type) {
      case 'lit': return node.value;
      case 'path': {
        let cur = context;
        let parts = node.parts;
        if (parts[0] === '$' && context != null && typeof context === 'object' && Object.prototype.hasOwnProperty.call(context, '$')) {
          cur = context.$;
          parts = parts.slice(1);
        } else if (parts[0] === '$') {
          parts = parts.slice(1); // no $ binding in context: resolve from root (legacy behavior)
        }
        for (const part of parts) {
          if (cur == null) return null;
          if (Array.isArray(cur) && typeof part === 'number') cur = cur[part];
          else if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, part)) cur = cur[part];
          else if (Array.isArray(cur) && part === 'length') return cur.length;
          else return null;
        }
        return cur === undefined ? null : cur;
      }
      case 'not': return !truthy(ev(node.expr));
      case 'neg': return -toNum(ev(node.expr));
      case 'and': { const l = ev(node.left); return truthy(l) ? ev(node.right) : l; }
      case 'or': { const l = ev(node.left); return truthy(l) ? l : ev(node.right); }
      case 'binary': {
        const l = ev(node.left), r = ev(node.right);
        switch (node.op) {
          case '+': return typeof l === 'string' || typeof r === 'string' ? String(l ?? '') + String(r ?? '') : toNum(l) + toNum(r);
          case '-': return toNum(l) - toNum(r);
          case '*': return toNum(l) * toNum(r);
          case '/': return toNum(r) === 0 ? null : toNum(l) / toNum(r);
          case '%': return toNum(r) === 0 ? null : toNum(l) % toNum(r);
          case '<': return comparable(l, r) ? l < r : toNum(l) < toNum(r);
          case '<=': return comparable(l, r) ? l <= r : toNum(l) <= toNum(r);
          case '>': return comparable(l, r) ? l > r : toNum(l) > toNum(r);
          case '>=': return comparable(l, r) ? l >= r : toNum(l) >= toNum(r);
          case '==': return looseEq(l, r);
          case '!=': return !looseEq(l, r);
          case '===': return l === r;
          case '!==': return l !== r;
        }
        return null;
      }
      case 'call': {
        const fn = FUNCS[node.name];
        if (!fn) throw new Error(`unknown function: ${node.name}`);
        return fn(...node.args.map(ev));
      }
    }
    return null;
  }
  return ev(compiled.ast);
}

export function evaluate(source, context) {
  return evalExpression(compileExpression(source), context || {});
}
const truthy = (v) => !!v;
const toNum = (v) => (v === null || v === '' || v === undefined ? 0 : typeof v === 'number' ? v : typeof v === 'boolean' ? (v ? 1 : 0) : Number.isNaN(Number(v)) ? 0 : Number(v));
const comparable = (l, r) => (typeof l === 'number' && typeof r === 'number') || (typeof l === 'string' && typeof r === 'string');
const looseEq = (l, r) => (l == null && r == null ? true : l == null || r == null ? false : typeof l === typeof r ? l === r : String(l) === String(r) || toNum(l) === toNum(r) && l !== '' && r !== '');
