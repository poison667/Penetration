import { median, stddev, mean } from '#core/util';

/**
 * Statistical anomaly detection over numeric columns:
 * z-score, modified z-score (MAD-based) and IQR fences per row.
 */
export function detectAnomalies(rows, { zThreshold = 3, madThreshold = 3.5, iqrMultiplier = 1.5 } = {}) {
  const numericCols = [];
  if (rows.length) {
    for (const col of Object.keys(rows[0])) {
      const sample = rows.slice(0, 500).map((r) => Number(r[col])).filter((v) => Number.isFinite(v));
      if (sample.length >= Math.min(10, rows.length * 0.5)) numericCols.push(col);
    }
  }
  const columnStats = {};
  for (const col of numericCols) {
    const values = rows.map((r) => Number(r[col]));
    const nums = values.filter((v) => Number.isFinite(v));
    const med = median(nums);
    const absDev = nums.map((v) => Math.abs(v - med));
    const mad = median(absDev) || 1e-9;
    const meanV = mean(nums);
    const sd = stddev(nums) || 1e-9;
    const q1 = percentile(nums, 25), q3 = percentile(nums, 75);
    columnStats[col] = { mean: +meanV.toFixed(4), median: med, stddev: +sd.toFixed(4), mad: +mad.toFixed(6), q1, q3, iqr: q3 - q1 };
  }

  const anomalies = [];
  rows.forEach((row, idx) => {
    const reasons = [];
    for (const col of numericCols) {
      const v = Number(row[col]);
      if (!Number.isFinite(v)) continue;
      const s = columnStats[col];
      const z = (v - s.mean) / s.stddev;
      const mz = 0.6745 * (v - s.median) / s.mad;
      const lowFence = s.q1 - iqrMultiplier * s.iqr;
      const highFence = s.q3 + iqrMultiplier * s.iqr;
      if (Math.abs(z) >= zThreshold) reasons.push({ column: col, method: 'zscore', score: +z.toFixed(3), value: v });
      if (Math.abs(mz) >= madThreshold) reasons.push({ column: col, method: 'mad', score: +mz.toFixed(3), value: v });
      if (v < lowFence || v > highFence) reasons.push({ column: col, method: 'iqr', fence: [lowFence, highFence], value: v });
    }
    if (reasons.length) anomalies.push({ row_index: idx, row, reasons });
  });
  return { anomalies, column_stats: columnStats, params: { zThreshold, madThreshold, iqrMultiplier }, analyzed_columns: numericCols };
}

function percentile(nums, p) {
  if (!nums.length) return null;
  const s = [...nums].sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1));
  return s[idx];
}
