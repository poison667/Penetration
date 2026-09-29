/**
 * Retrieval-augmented generation core: chunking + BM25 index.
 * Answers are composed ONLY from retrieved chunks — every statement carries a
 * citation; when retrieval confidence is low, the system says so instead of
 * inventing content.
 */
const STOPWORDS = new Set('a an and are as at be by for from has have i in is it its of on or that the to was were will with you your this these those our we they he she them his her not but if then than so such can could should would may might must about into over under again further once here there when where why how all any both each few more most other some no nor only own same too very'.split(' '));

export function tokenize(text) {
  return String(text ?? '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((t) => t.length > 1 && !STOPWORDS.has(t));
}

/** Sentence-aware chunking (~chunkChars chars). */
export function chunkText(text, { chunkChars = 900, overlap = 120 } = {}) {
  const clean = String(text ?? '').replace(/\s+/g, ' ').trim();
  if (!clean) return [];
  let sentences = clean.match(/[^.!?]+[.!?]+|[^.!?]+$/g) || []; // second alternative keeps unpunctuated text
  // unpunctuated or single-sentence content longer than a chunk: hard-split on word boundaries
  const expanded = [];
  for (const s of sentences) {
    if (s.length <= chunkChars) { expanded.push(s); continue; }
    const words = s.split(' ');
    let piece = '';
    for (const w of words) {
      if ((piece + ' ' + w).length > chunkChars && piece) { expanded.push(piece); piece = piece.slice(Math.max(0, piece.length - overlap)); }
      piece = piece ? piece + ' ' + w : w;
    }
    if (piece.trim()) expanded.push(piece.trim());
  }
  sentences = expanded;
  const chunks = [];
  let cur = '';
  for (const s of sentences) {
    if ((cur + s).length > chunkChars && cur) {
      chunks.push(cur.trim());
      cur = cur.slice(Math.max(0, cur.length - overlap));
    }
    cur += s + ' ';
  }
  if (cur.trim()) chunks.push(cur.trim());
  // never lose short-but-real content: keep the sole chunk regardless of length filters
  if (!chunks.length && clean) return [clean];
  return chunks.length === 1 ? chunks : chunks.filter((c) => c.length > 10);
}

export class BM25Index {
  constructor({ k1 = 1.5, b = 0.75 } = {}) {
    this.k1 = k1; this.b = b;
    this.docs = []; // {id, tokens, len, tf}
    this.df = new Map();
    this.totalLen = 0;
  }
  add(id, text) {
    const tokens = tokenize(text);
    const tf = new Map();
    for (const t of tokens) tf.set(t, (tf.get(t) || 0) + 1);
    for (const t of tf.keys()) this.df.set(t, (this.df.get(t) || 0) + 1);
    this.docs.push({ id, tokens, len: tokens.length, tf });
    this.totalLen += tokens.length;
  }
  search(query, { limit = 8 } = {}) {
    const qTokens = tokenize(query);
    const N = this.docs.length || 1;
    const avgLen = this.totalLen / N || 1;
    const scores = this.docs.map((doc) => {
      let score = 0;
      for (const t of qTokens) {
        const f = doc.tf.get(t);
        if (!f) continue;
        const df = this.df.get(t) || 0;
        const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
        score += idf * (f * (this.k1 + 1)) / (f + this.k1 * (1 - this.b + this.b * doc.len / avgLen));
      }
      return { id: doc.id, score };
    }).filter((s) => s.score > 0);
    scores.sort((a, b) => b.score - a.score);
    return scores.slice(0, limit);
  }
}
