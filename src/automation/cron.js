/**
 * Cron expression parser + next-run computation (5 fields: minute hour
 * day-of-month month day-of-week; supports *, lists, ranges, steps, names).
 */
const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const DAYS = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

export function parseCron(expr) {
  const fields = String(expr).trim().split(/\s+/);
  if (fields.length !== 5) throw new Error(`cron expression must have 5 fields (min hour dom month dow), got ${fields.length}`);
  const parsed = fields.map((field, idx) => parseField(field, idx));
  return { expr, minute: parsed[0], hour: parsed[1], dom: parsed[2], month: parsed[3], dow: parsed[4] };
}

function parseField(field, idx) {
  const ranges = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]];
  const [min, max] = ranges[idx];
  const values = new Set();
  for (const part of field.split(',')) {
    const [body, stepStr] = part.split('/');
    const step = stepStr ? parseInt(stepStr, 10) : 1;
    if (!Number.isInteger(step) || step < 1) throw new Error(`invalid step in cron field: ${field}`);
    let from = min, to = max;
    if (body !== '*') {
      const rangeM = /^(\w+)-(\w+)$/.exec(body);
      if (rangeM) {
        from = parseValue(rangeM[1], idx);
        to = parseValue(rangeM[2], idx);
      } else {
        from = to = parseValue(body, idx);
        if (!stepStr) {
          if (from < min || from > max) throw new Error(`cron field out of range: ${field}`);
          values.add(from === 7 && idx === 4 ? 0 : from);
          continue;
        }
      }
    }
    if (from < min || to > max || from > to) throw new Error(`cron field out of range: ${field}`);
    for (let v = from; v <= to; v += step) values.add(v === 7 && idx === 4 ? 0 : v);
  }
  return values;
}
function parseValue(v, idx) {
  const lower = String(v).toLowerCase();
  if (idx === 3 && MONTHS[lower]) return MONTHS[lower];
  if (idx === 4 && DAYS[lower] != null) return DAYS[lower];
  if (!/^\d+$/.test(v)) throw new Error(`invalid cron value: ${v}`);
  return parseInt(v, 10);
}

/** Next matching time strictly after `after` (Date), in UTC. */
export function nextRun(cron, after = new Date()) {
  // start at the next minute boundary strictly after `after` (cron fires on minute boundaries)
  const d = new Date((Math.floor(after.getTime() / 60000) + 1) * 60000);
  for (let i = 0; i < 366 * 24 * 60 * 2; i++) { // bound: 2 years of minutes
    if (!cron.minute.has(d.getUTCMinutes())) { d.setUTCMinutes(d.getUTCMinutes() + 1, 0, 0); continue; }
    if (!cron.hour.has(d.getUTCHours())) { d.setUTCHours(d.getUTCHours() + 1, 0, 0, 0); continue; }
    if (!cron.month.has(d.getUTCMonth() + 1)) { d.setUTCMonth(d.getUTCMonth() + 1, 1, 0, 0, 0, 0); continue; }
    const domOk = cron.dom.has(d.getUTCDate());
    const dowOk = cron.dow.has(d.getUTCDay());
    // standard cron semantics: if BOTH dom and dow are restricted (not *), either may match;
    // otherwise both must match. An unrestricted dow is {0..6} (size 7 — 7 is normalized to 0).
    const bothRestricted = cron.dom.size !== 31 && cron.dow.size !== 7;
    const dayMatches = bothRestricted ? (domOk || dowOk) : (domOk && dowOk);
    if (!dayMatches) { d.setUTCDate(d.getUTCDate() + 1); d.setUTCHours(0, 0, 0, 0); continue; }
    return new Date(d);
  }
  return null;
}
