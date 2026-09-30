import { evaluate } from '#core/expr';

/**
 * Data transformation pipeline.
 * steps: [
 *   {op:'rename', from, to}, {op:'select', columns:[...]}, {op:'drop', columns:[...]},
 *   {op:'cast', column, type:'number'|'string'|'boolean'|'date'},
 *   {op:'derive', column, expr}, {op:'filter', expr},
 *   {op:'sort', column, dir}, {op:'fill', column, value}, {op:'limit', count}
 * ]
 */
export function transform(rows, steps) {
  let data = [...rows];
  const lineage = [];
  for (const step of steps || []) {
    const before = data.length;
    switch (step.op) {
      case 'rename': data = data.map((r) => { const { [step.from]: v, ...rest } = r; return { ...rest, [step.to]: v }; }); break;
      case 'select': data = data.map((r) => Object.fromEntries(step.columns.filter((c) => c in r).map((c) => [c, r[c]]))); break;
      case 'drop': data = data.map((r) => Object.fromEntries(Object.entries(r).filter(([k]) => !step.columns.includes(k)))); break;
      case 'cast':
        data = data.map((r) => ({ ...r, [step.column]: cast(r[step.column], step.type) }));
        break;
      case 'derive':
        data = data.map((r) => ({ ...r, [step.column]: evaluate(step.expr, { $: r, row: r }) }));
        break;
      case 'filter':
        data = data.filter((r) => !!evaluate(step.expr, { $: r, row: r }));
        break;
      case 'sort':
        data.sort((a, b) => {
          const av = a[step.column], bv = b[step.column];
          const cmp = av === bv ? 0 : av == null ? -1 : bv == null ? 1 : av < bv ? -1 : 1;
          return step.dir === 'desc' ? -cmp : cmp;
        });
        break;
      case 'fill': data = data.map((r) => ({ ...r, [step.column]: r[step.column] == null || r[step.column] === '' ? step.value : r[step.column] })); break;
      case 'limit': data = data.slice(0, step.count); break;
      default: throw new Error(`unknown transform op: ${step.op}`);
    }
    lineage.push({ op: step.op, rows_before: before, rows_after: data.length, detail: summarizeStep(step) });
  }
  return { rows: data, lineage };
}

function cast(v, type) {
  if (v == null || v === '') return null;
  switch (type) {
    case 'number': { const n = Number(v); return Number.isNaN(n) ? null : n; }
    case 'string': return String(v);
    case 'boolean': return /^(true|yes|1)$/i.test(String(v)) ? true : /^(false|no|0)$/i.test(String(v)) ? false : null;
    case 'date': { const d = new Date(v); return Number.isNaN(d.getTime()) ? null : d.toISOString(); }
    default: return v;
  }
}
function summarizeStep(step) {
  const clone = { ...step };
  if (clone.expr) clone.expr = String(clone.expr).slice(0, 120);
  return clone;
}
