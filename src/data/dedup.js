/**
 * Deduplication: exact, normalized and fuzzy (Levenshtein with blocking).
 * Fuzzy uses a sorted-character blocking key to avoid O(n²) comparisons.
 */
export function normalizeValue(v) {
  return String(v ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

export function levenshtein(a, b, max = 3) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev = new Array(b.length + 1);
  const cur = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    let best = cur[0];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    for (let j = 0; j <= b.length; j++) prev[j] = cur[j];
  }
  return prev[b.length];
}

/**
 * @param rows data rows
 * @param keyColumns columns identifying a record
 * @param mode exact | normalized | fuzzy
 * @returns {rows: kept, duplicates: [{kept_index, duplicate_index, key, distance}], stats}
 */
export function dedupe(rows, keyColumns, { mode = 'exact', threshold = 2 } = {}) {
  // keyColumns may be null (no keys → derive from row shape), a comma string, or an array.
  const normalized = keyColumns == null ? []
    : typeof keyColumns === 'string' ? keyColumns.split(',').map((c) => c.trim()).filter(Boolean)
    : keyColumns;
  const keys = normalized.length ? normalized : Object.keys(rows[0] || {}).slice(0, 2);
  const seen = new Map(); // key -> index kept
  const kept = [];
  const duplicates = [];
  const blocks = new Map(); // blocking key -> [indices]

  const keyOf = (row) => keys.map((k) => String(row[k] ?? '')).join('||');
  const blockOf = (row) => [...keyOf(row)].sort().join('').slice(0, 4) + keyOf(row).slice(0, 2);

  rows.forEach((row, idx) => {
    const key = keyOf(row);
    if (mode === 'exact') {
      if (seen.has(key)) { duplicates.push({ kept_index: seen.get(key), duplicate_index: idx, key, distance: 0 }); return; }
      seen.set(key, idx);
      kept.push(row);
      return;
    }
    const norm = mode === 'normalized' ? normalizeValue(key) : key;
    if (mode === 'normalized') {
      if (seen.has(norm)) { duplicates.push({ kept_index: seen.get(norm), duplicate_index: idx, key, distance: 0 }); return; }
      seen.set(norm, idx); kept.push(row); return;
    }
    // fuzzy: compare within blocks
    const bk = blockOf(row);
    const candidates = blocks.get(bk) || [];
    for (const { normKey, keptIdx } of candidates) {
      const d = levenshtein(normKey, normalizeValue(key), threshold + 1);
      if (d <= threshold) {
        duplicates.push({ kept_index: keptIdx, duplicate_index: idx, key, distance: d });
        return;
      }
    }
    candidates.push({ normKey: normalizeValue(key), keptIdx: kept.length });
    blocks.set(bk, candidates);
    seen.set(key, idx);
    kept.push(row);
  });

  return { rows: kept, duplicates, stats: { input_rows: rows.length, output_rows: kept.length, duplicates_found: duplicates.length, mode, key_columns: keys, threshold: mode === 'fuzzy' ? threshold : null } };
}
