/** Data cleansing pipeline: deterministic rules with a per-row change log. */
export const CLEANSE_RULES = {
  trim: (v) => ({ v: String(v ?? '').trim(), changed: String(v ?? '') !== String(v ?? '').trim() }),
  lowercase: (v) => ({ v: String(v ?? '').toLowerCase(), changed: String(v ?? '') !== String(v ?? '').toLowerCase() }),
  uppercase: (v) => ({ v: String(v ?? '').toUpperCase(), changed: String(v ?? '') !== String(v ?? '').toUpperCase() }),
  strip_whitespace: (v) => { const n = String(v ?? '').replace(/\s+/g, ''); return { v: n, changed: n !== String(v ?? '') }; },
  strip_non_numeric: (v) => { const n = String(v ?? '').replace(/[^0-9.\-]/g, ''); return { v: n, changed: n !== String(v ?? '') }; },
  strip_html: (v) => { const n = String(v ?? '').replace(/<[^>]*>/g, ''); return { v: n, changed: n !== String(v ?? '') }; },
  regex_replace: (v, { find, replace }) => { const n = String(v ?? '').replace(new RegExp(find, 'g'), replace ?? ''); return { v: n, changed: n !== String(v ?? '') }; },
  fill_null: (v, { value }) => (v == null || String(v).trim() === '' ? { v: value ?? '', changed: true } : { v, changed: false }),
  truncate: (v, { length }) => { const n = String(v ?? '').slice(0, length ?? 100); return { v: n, changed: n !== String(v ?? '') }; },
};

/** @param rules: [{column, rule, params}] */
export function cleanse(rows, rules) {
  const changes = [];
  const cleaned = rows.map((row, rowIndex) => {
    const out = { ...row };
    for (const r of rules) {
      const fn = CLEANSE_RULES[r.rule];
      if (!fn) continue;
      if (r.column === '*') {
        for (const col of Object.keys(out)) {
          const res = fn(out[col], r.params || {});
          if (res.changed) { changes.push({ row: rowIndex, column: col, rule: r.rule, before: out[col], after: res.v }); out[col] = res.v; }
        }
      } else if (Object.prototype.hasOwnProperty.call(out, r.column)) {
        const res = fn(out[r.column], r.params || {});
        if (res.changed) { changes.push({ row: rowIndex, column: r.column, rule: r.rule, before: out[r.column], after: res.v }); out[r.column] = res.v; }
      }
    }
    return out;
  });
  return { rows: cleaned, changes, stats: { rows: cleaned.length, cells_changed: changes.length, rules_applied: rules.length } };
}
