/** Design-system primitives. Dense, restrained, enterprise. */
import React, { useEffect, useRef, useState } from 'react';
import { ApiError } from './api';

export function Panel({ title, actions, children, className = '', pad = true }: { title?: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`panel ${className}`}>
      {title !== undefined && (
        <div className="panel-head">
          <h3>{title}</h3>
          <div className="spacer" />
          {actions}
        </div>
      )}
      <div className={`panel-body ${pad ? '' : 'p0'}`}>{children}</div>
    </section>
  );
}

export function PageHead({ title, desc, actions }: { title: string; desc?: string; actions?: React.ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h2>{title}</h2>
        {desc && <div className="desc">{desc}</div>}
      </div>
      <div className="spacer" />
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function Stat({ k, v, d, tone }: { k: string; v: React.ReactNode; d?: React.ReactNode; tone?: 'ok' | 'err' | 'warn' }) {
  return (
    <div className="panel stat">
      <div className="k">{k}</div>
      <div className="v" style={tone ? { color: `var(--${tone === 'ok' ? 'ok' : tone === 'err' ? 'danger' : 'warn'})` } : undefined}>{v}</div>
      {d && <div className="d">{d}</div>}
    </div>
  );
}

type Col<T> = { key: string; label: string; render?: (row: T) => React.ReactNode; className?: string; w?: number };
export function DataTable<T extends { id?: string }>({ cols, rows, loading, empty, onRow, rowKey }: {
  cols: Col<T>[]; rows: T[] | undefined; loading?: boolean; empty?: string; onRow?: (row: T) => void; rowKey?: (row: T, i: number) => string;
}) {
  if (loading && !rows) return <div className="loading"><span className="spinner" /> Loading…</div>;
  if (!rows || rows.length === 0) return <div className="empty"><div className="big">{empty || 'Nothing here yet'}</div></div>;
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead><tr>{cols.map((c) => <th key={c.key} style={c.w ? { width: c.w } : undefined}>{c.label}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={rowKey ? rowKey(row, i) : (row.id ?? String(i))} className={onRow ? 'clickable' : ''} onClick={onRow ? () => onRow(row) : undefined}>
              {cols.map((c) => <td key={c.key} className={c.className}>{c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? '—')}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function SevBadge({ sev }: { sev: string }) {
  return <span className={`badge sev-${sev}`}>{sev}</span>;
}
export function Badge({ children, tone = 'plain' }: { children: React.ReactNode; tone?: 'plain' | 'ok' | 'err' | 'warn' | 'accent' }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
const STATE_TONES: Record<string, 'ok' | 'err' | 'warn' | 'accent' | 'plain'> = {
  COMPLETED: 'ok', PARTIALLY_COMPLETED: 'warn', FAILED: 'err', CANCELLED: 'plain', RUNNING: 'accent',
  ANALYZING: 'accent', QUALITY_CHECK: 'accent', QUEUED: 'plain', VALIDATING: 'plain', REQUESTED: 'plain', RETRYING: 'warn',
  completed: 'ok', failed: 'err', cancelled: 'plain', running: 'accent', pending: 'plain', succeeded: 'ok', open: 'err', active: 'ok', expired: 'warn', revoked: 'err', declared: 'warn', verified: 'ok', up: 'ok', down: 'err', paused: 'warn', draft: 'plain', closed: 'ok', resolved: 'ok',
};
export function StateBadge({ s }: { s: string }) {
  const tone = STATE_TONES[s] ?? 'plain';
  return <span className={`badge ${tone}`}>{s.replace(/_/g, ' ').toLowerCase()}</span>;
}
export function Dot({ tone }: { tone: 'ok' | 'err' | 'warn' | 'idle' }) {
  return <span className={`dot ${tone}`} />;
}

export function Field({ label, help, children }: { label: string; help?: string; children: React.ReactNode }) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {help && <div className="help">{help}</div>}
    </div>
  );
}

export function Modal({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: React.ReactNode; footer?: React.ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${wide ? 'wide' : ''}`}>
        <div className="modal-head"><h3>{title}</h3><button className="ghost sm" onClick={onClose}>Close</button></div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Tabs({ tabs, active, onPick }: { tabs: { key: string; label: string }[]; active: string; onPick: (k: string) => void }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <div key={t.key} className={`tab ${active === t.key ? 'active' : ''}`} onClick={() => onPick(t.key)}>{t.label}</div>
      ))}
    </div>
  );
}

export function KV({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => <React.Fragment key={i}><dt>{k}</dt><dd>{v}</dd></React.Fragment>)}
    </dl>
  );
}

export function Chips({ options, value, onPick }: { options: { key: string; label: string }[]; value: string; onPick: (k: string) => void }) {
  return (
    <div className="chips">
      {options.map((o) => (
        <button key={o.key} className={`chip ${value === o.key ? 'active' : ''}`} onClick={() => onPick(o.key)}>{o.label}</button>
      ))}
    </div>
  );
}

export function Progress({ pct }: { pct: number }) {
  return <div className="progress"><div style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} /></div>;
}

export function CodeBlock({ text }: { text: string }) {
  return <div className="codeblock">{text}</div>;
}

export function FactBlocks({ facts, inference, recommendation }: { facts: string[]; inference: string[]; recommendation?: string | null }) {
  return (
    <>
      <div className="fact-block facts">
        <div className="lbl">Facts — directly observed</div>
        {facts.length ? <ul>{facts.map((f, i) => <li key={i}>{f}</li>)}</ul> : <div className="help">none recorded</div>}
      </div>
      <div className="fact-block inference">
        <div className="lbl">Inference — interpreted from facts</div>
        {inference.length ? <ul>{inference.map((f, i) => <li key={i}>{f}</li>)}</ul> : <div className="help">none recorded</div>}
      </div>
      {recommendation && (
        <div className="fact-block recommendation">
          <div className="lbl">Recommendation</div>
          <div>{recommendation}</div>
        </div>
      )}
    </>
  );
}

/** useAsync — minimal data-fetching hook with refresh */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []): { data: T | undefined; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    let alive = true;
    setLoading(true);
    fnRef.current().then((d) => { if (alive) { setData(d); setError(null); } })
      .catch((e) => { if (alive) setError(e instanceof ApiError ? `${e.message}` : String(e?.message || e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [...deps, tick]);
  return { data, error, loading, refresh: () => setTick((t) => t + 1) };
}

export function Err({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="notice err">{error}</div>;
}

export function EmptyGate({ children }: { children: React.ReactNode }) {
  return <div className="empty">{children}</div>;
}
