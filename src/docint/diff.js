/** Document comparison: line-level LCS diff + word statistics. */
export function lineDiff(aLines, bLines) {
  const n = aLines.length, m = bLines.length;
  // LCS dynamic programming (cap sizes for safety)
  const MAX = 5000;
  if (n > MAX || m > MAX) {
    return { type: 'line_lcs_truncated', hunks: [], note: `documents exceed ${MAX} lines; truncated comparison` };
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = aLines[i] === bLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const ops = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (aLines[i] === bLines[j]) { ops.push({ op: 'equal', a: i, b: j, text: aLines[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ op: 'delete', a: i, text: aLines[i] }); i++; }
    else { ops.push({ op: 'insert', b: j, text: bLines[j] }); j++; }
  }
  while (i < n) { ops.push({ op: 'delete', a: i, text: aLines[i] }); i++; }
  while (j < m) { ops.push({ op: 'insert', b: j, text: bLines[j] }); j++; }
  return { type: 'line_lcs', ops };
}

export function compareDocuments(docA, docB) {
  const aLines = String(docA || '').split('\n');
  const bLines = String(docB || '').split('\n');
  const diff = lineDiff(aLines, bLines);
  const hunks = [];
  let current = null;
  for (const op of diff.ops) {
    const kind = op.op === 'equal' ? 'equal' : 'change';
    if (kind === 'change' && (!current || current.kind !== 'change')) { current = { kind: 'change', ops: [] }; hunks.push(current); }
    if (kind === 'change') current.ops.push(op);
    else current = { kind: 'equal', count: (current?.kind === 'equal' ? current.count : 0) + 1 };
  }
  const wordsA = String(docA || '').split(/\s+/).filter(Boolean).length;
  const wordsB = String(docB || '').split(/\s+/).filter(Boolean).length;
  const inserts = diff.ops.filter((o) => o.op === 'insert').length;
  const deletes = diff.ops.filter((o) => o.op === 'delete').length;
  const equal = diff.ops.filter((o) => o.op === 'equal').length;
  const similarity = (equal + Math.min(inserts, deletes)) / Math.max(1, equal + inserts + deletes);
  return {
    stats: { lines_a: aLines.length, lines_b: bLines.length, words_a: wordsA, words_b: wordsB, lines_inserted: inserts, lines_deleted: deletes, lines_equal: equal, similarity: +similarity.toFixed(4) },
    hunks: hunks.map((h) => ({ kind: h.kind, changes: h.ops.slice(0, 50) })),
    diff,
  };
}
