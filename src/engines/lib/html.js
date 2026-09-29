/**
 * Tolerant HTML parser (no dependencies) producing a lightweight DOM tree.
 * Handles void elements, raw-text elements (script/style/textarea/title),
 * comments, doctypes, CDATA, single/unquoted attributes, unclosed tags and
 * mis-nested closers (stack-based recovery). Named + numeric entities decoded.
 */
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
const RAWTEXT = new Set(['script', 'style', 'textarea', 'title', 'xmp', 'noscript']);
const BLOCK = new Set(['address', 'article', 'aside', 'blockquote', 'body', 'br', 'div', 'dl', 'dt', 'dd', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'html', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'ul']);

const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–', lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201C', rdquo: '\u201D', bull: '•', dagger: '†', deg: '°', plusmn: '±', sup2: '²', sup3: '³', frac12: '½', times: '×', divide: '÷', euro: '€', pound: '£', yen: '¥', cent: '¢', sect: '§', para: '¶', middot: '·', laquo: '«', raquo: '»', rarr: '→', larr: '←', uarr: '↑', darr: '↓', harr: '↔', infin: '∞', ne: '≠', le: '≤', ge: '≥', alpha: 'α', beta: 'β', gamma: 'γ', delta: 'δ', omega: 'ω', sigma: 'σ', mu: 'μ' };

export function decodeEntities(s) {
  if (!s || s.indexOf('&') === -1) return s;
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (m, g) => {
    if (g[0] === '#') {
      const code = g[1] === 'x' || g[1] === 'X' ? parseInt(g.slice(2), 16) : parseInt(g.slice(1), 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return m;
      return String.fromCodePoint(code);
    }
    const named = NAMED_ENTITIES[g.toLowerCase()];
    return named !== undefined ? named : m;
  });
}

export function parseHtml(html) {
  const src = String(html ?? '');
  const root = { type: 'root', tag: '#root', attrs: {}, children: [], parent: null };
  const stack = [root];
  let i = 0;
  const top = () => stack[stack.length - 1];
  const append = (node) => { node.parent = top(); top().children.push(node); };

  while (i < src.length) {
    const lt = src.indexOf('<', i);
    if (lt === -1) { pushText(src.slice(i)); break; }
    if (lt > i) pushText(src.slice(i, lt));
    i = lt;
    if (src.startsWith('<!--', i)) {
      const end = src.indexOf('-->', i + 4);
      const raw = end === -1 ? src.slice(i + 4) : src.slice(i + 4, end);
      append({ type: 'comment', tag: '#comment', attrs: {}, children: [], text: raw, parent: null });
      i = end === -1 ? src.length : end + 3;
      continue;
    }
    if (src.startsWith('<![CDATA[', i)) {
      const end = src.indexOf(']]>', i + 9);
      pushText(end === -1 ? src.slice(i + 9) : src.slice(i + 9, end));
      i = end === -1 ? src.length : end + 3;
      continue;
    }
    if (src.startsWith('<!', i) || src.startsWith('<?', i)) {
      const end = src.indexOf('>', i);
      i = end === -1 ? src.length : end + 1;
      continue;
    }
    if (src.startsWith('</', i)) {
      const end = src.indexOf('>', i + 2);
      const tag = src.slice(i + 2, end === -1 ? src.length : end).trim().toLowerCase().split(/\s/)[0];
      if (tag) {
        for (let d = stack.length - 1; d > 0; d--) {
          if (stack[d].tag === tag) { stack.length = d; break; }
        }
      }
      i = end === -1 ? src.length : end + 1;
      continue;
    }
    // open tag
    const gt = findTagEnd(src, i);
    const tagSrc = src.slice(i + 1, gt === -1 ? src.length : gt);
    i = gt === -1 ? src.length : gt + 1;
    const { tag, attrs, selfClose } = parseTag(tagSrc);
    if (!tag || !/^[a-zA-Z][a-zA-Z0-9:._-]*$/.test(tag)) continue;
    const el = { type: 'element', tag: tag.toLowerCase(), attrs, children: [], parent: null };
    append(el);
    if (selfClose || VOID.has(el.tag)) continue;
    if (RAWTEXT.has(el.tag)) {
      const closeRe = new RegExp(`</${el.tag}\\s*>`, 'i');
      const rest = src.slice(i);
      const m = closeRe.exec(rest);
      const raw = m ? rest.slice(0, m.index) : rest;
      if (raw) el.children.push({ type: 'text', tag: '#text', text: raw, parent: el });
      if (el.tag !== 'script' && el.tag !== 'style' && el.tag !== 'noscript') {
        // textarea/title: decode entities for text semantics
        el.children = [{ type: 'text', tag: '#text', text: decodeEntities(raw), parent: el }];
      }
      i = m ? i + m.index + m[0].length : src.length;
      continue;
    }
    stack.push(el);
  }
  return root;

  function pushText(text) {
    if (!text) return;
    const last = top().children[top().children.length - 1];
    const decoded = decodeEntities(text);
    if (last && last.type === 'text') last.text += decoded;
    else append({ type: 'text', tag: '#text', text: decoded, parent: null });
  }
}
function findTagEnd(src, from) {
  let q = null;
  for (let j = from + 1; j < src.length; j++) {
    const ch = src[j];
    if (q) { if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; continue; }
    if (ch === '>') return j;
  }
  return -1;
}
function parseTag(src) {
  const nameM = /^[a-zA-Z][a-zA-Z0-9:._-]*/.exec(src);
  if (!nameM) return { tag: null, attrs: {}, selfClose: false };
  const tag = nameM[0];
  const attrs = {};
  const re = /([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*)))?/g;
  let m;
  re.lastIndex = nameM[0].length;
  while ((m = re.exec(src)) !== null) {
    if (!m[1]) continue;
    const name = m[1].toLowerCase();
    const value = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined && m[4] !== '' ? m[4] : '';
    attrs[name] = decodeEntities(value);
  }
  const selfClose = /\/\s*$/.test(src);
  return { tag, attrs, selfClose };
}

// ---------- query helpers ----------
export function walk(node, visit) {
  if (!node) return;
  visit(node);
  for (const c of node.children || []) walk(c, visit);
}
export function findAll(root, pred) {
  const out = [];
  walk(root, (n) => { if (n.type === 'element' && pred(n)) out.push(n); });
  return out;
}
export const byTag = (root, tag) => findAll(root, (n) => n.tag === tag.toLowerCase());
export const attr = (el, name) => (el && el.attrs[name.toLowerCase()]) ?? null;
export function textContent(node, { skipRaw = true } = {}) {
  let out = '';
  walk(node, (n) => {
    if (n.type === 'text') {
      if (skipRaw && n.parent && (n.parent.tag === 'script' || n.parent.tag === 'style')) return;
      out += n.text;
    }
  });
  return out;
}
export function innerText(node) {
  let out = '';
  walk(node, (n) => {
    if (n.type === 'text') {
      if (n.parent && (n.parent.tag === 'script' || n.parent.tag === 'style' || n.parent.tag === 'noscript')) return;
      out += n.text;
      if (n.parent && BLOCK.has(n.parent.tag)) out += '\n';
    }
  });
  return out.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}
export function htmlToText(html) { return innerText(parseHtml(html)); }

export function metas(root) {
  const out = [];
  for (const m of byTag(root, 'meta')) {
    const key = attr(m, 'name') || attr(m, 'property') || attr(m, 'http-equiv');
    if (key) out.push({ key: key.toLowerCase(), content: attr(m, 'content') ?? '' });
  }
  return out;
}
export function metaGet(root, key) {
  const k = key.toLowerCase();
  const m = metas(root).find((x) => x.key === k);
  return m ? m.content : null;
}
export function links(root, baseUrl) {
  const out = [];
  for (const a of byTag(root, 'a')) {
    const href = attr(a, 'href');
    if (!href) continue;
    try {
      const u = new URL(href, baseUrl || 'http://relative.invalid');
      out.push({ url: u.toString(), text: innerText(a).slice(0, 120), rel: attr(a, 'rel'), target: attr(a, 'target'), external: baseUrl ? new URL(baseUrl).host !== u.host : false });
    } catch { /* skip invalid */ }
  }
  return out;
}
export function scripts(root, baseUrl) {
  return byTag(root, 'script').map((s) => {
    const src = attr(s, 'src');
    let abs = null;
    if (src && baseUrl) { try { abs = new URL(src, baseUrl).toString(); } catch { abs = null; } }
    else if (src) abs = src;
    return { src: abs, inline: !src ? textContent(s).length : 0, inlineText: !src ? textContent(s) : null, async: attr(s, 'async') != null, type: attr(s, 'type') };
  });
}
export function forms(root, baseUrl) {
  return byTag(root, 'form').map((f) => {
    const fields = [];
    for (const el of f.children || []) { /* depth-1 handled below via walk */ }
    walk(f, (n) => {
      if (n.type !== 'element') return;
      if (['input', 'select', 'textarea', 'button'].includes(n.tag)) {
        fields.push({ tag: n.tag, name: attr(n, 'name'), type: attr(n, 'type') || (n.tag === 'button' ? 'submit' : n.tag === 'textarea' ? 'textarea' : 'text'), id: attr(n, 'id'), value: attr(n, 'value'), required: attr(n, 'required') != null, maxlength: attr(n, 'maxlength'), autocomplete: attr(n, 'autocomplete'), placeholder: attr(n, 'placeholder') });
      }
    });
    let action = attr(f, 'action') || '';
    if (action && baseUrl) { try { action = new URL(action, baseUrl).toString(); } catch { /* keep */ } }
    return { action, method: (attr(f, 'method') || 'get').toUpperCase(), enctype: attr(f, 'enctype') || 'application/x-www-form-urlencoded', fields, hasFileField: fields.some((x) => x.type === 'file') };
  });
}
export function headings(root) {
  const out = [];
  walk(root, (n) => { if (n.type === 'element' && /^h[1-6]$/.test(n.tag)) out.push({ level: Number(n.tag[1]), text: innerText(n).slice(0, 200) }); });
  return out;
}
export function images(root) {
  return byTag(root, 'img').map((i) => ({ src: attr(i, 'src'), alt: attr(i, 'alt'), width: attr(i, 'width'), height: attr(i, 'height'), loading: attr(i, 'loading') }));
}
export function title(root) {
  const t = byTag(root, 'title')[0];
  return t ? innerText(t).trim() : null;
}
export function lang(root) {
  const html = byTag(root, 'html')[0];
  return html ? attr(html, 'lang') : null;
}
export function canonical(root) {
  for (const l of byTag(root, 'link')) if ((attr(l, 'rel') || '').toLowerCase() === 'canonical') return attr(l, 'href');
  return null;
}
export function iframes(root) {
  return byTag(root, 'iframe').map((f) => ({ src: attr(f, 'src'), title: attr(f, 'title'), sandbox: attr(f, 'sandbox') }));
}
