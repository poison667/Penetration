import { median, stddev } from '#core/util';

/** Data profiling: type inference + per-column statistics. */
export function inferType(values) {
  const checks = [
    { type: 'integer', test: (v) => /^-?\d{1,15}$/.test(v.trim()) },
    { type: 'float', test: (v) => /^-?\d{1,15}\.\d+$/.test(v.trim()) },
    { type: 'date', test: (v) => /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/.test(v.trim()) && !Number.isNaN(Date.parse(v)) },
    { type: 'boolean', test: (v) => /^(true|false|yes|no|0|1)$/i.test(v.trim()) },
    { type: 'email', test: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()) },
    { type: 'uuid', test: (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v.trim()) },
  ];
  const nonEmpty = values.filter((v) => v != null && String(v).trim() !== '');
  for (const { type, test } of checks) {
    if (nonEmpty.length && nonEmpty.every((v) => test(String(v)))) return type;
  }
  return 'string';
}

export function profile(rows, { sampleLimit = 10000 } = {}) {
  const data = rows.slice(0, sampleLimit);
  const headers = data.length ? Object.keys(data[0]) : [];
  const columns = {};
  for (const col of headers) {
    const values = data.map((r) => r[col]);
    const raw = values.map((v) => (v == null ? '' : String(v)));
    const nonEmpty = raw.filter((v) => v.trim() !== '');
    const distinct = new Set(nonEmpty);
    const type = inferType(nonEmpty);
    const numeric = type === 'integer' || type === 'float' ? nonEmpty.map(Number) : null;
    const topCounts = new Map();
    for (const v of nonEmpty) topCounts.set(v, (topCounts.get(v) || 0) + 1);
    const top = [...topCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([value, count]) => ({ value, count }));
    columns[col] = {
      type,
      count: raw.length,
      non_empty: nonEmpty.length,
      nulls: raw.length - nonEmpty.length,
      null_ratio: raw.length ? +((raw.length - nonEmpty.length) / raw.length).toFixed(4) : 0,
      distinct: distinct.size,
      distinct_ratio: nonEmpty.length ? +(distinct.size / nonEmpty.length).toFixed(4) : 0,
      ...(numeric ? {
        min: Math.min(...numeric), max: Math.max(...numeric),
        mean: +(numeric.reduce((a, b) => a + b, 0) / numeric.length).toFixed(4),
        median: median(numeric), stddev: +stddev(numeric).toFixed(4),
      } : {}),
      max_length: nonEmpty.reduce((a, v) => Math.max(a, v.length), 0),
      top_values: top,
    };
  }
  return {
    rows: data.length,
    columns: headers.length,
    column_stats: columns,
    profiled_at: new Date().toISOString(),
  };
}
