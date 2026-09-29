/** Application shell: sidebar navigation + topbar + routed content. */
import React, { useEffect, useRef, useState } from 'react';
import { useApp } from './state';
import { Badge, Dot } from './ui';
import { api, Notification, eventsUrl, currentAccessToken } from './api';

interface NavDef { path: string; label: string; group: string; staff?: boolean }

export const NAV: NavDef[] = [
  { path: '/', label: 'Dashboard', group: 'Overview' },
  { path: '/marketplace', label: 'Marketplace', group: 'Overview' },
  { path: '/requests', label: 'Service requests', group: 'Delivery' },
  { path: '/jobs', label: 'Jobs', group: 'Delivery' },
  { path: '/assets', label: 'Assets', group: 'Delivery' },
  { path: '/findings', label: 'Findings', group: 'Delivery' },
  { path: '/evidence', label: 'Evidence', group: 'Delivery' },
  { path: '/security', label: 'Security', group: 'Delivery' },
  { path: '/monitoring', label: 'Monitoring', group: 'Delivery' },
  { path: '/reports', label: 'Reports', group: 'Delivery' },
  { path: '/data', label: 'Data workbench', group: 'Analysis' },
  { path: '/documents', label: 'Document vault', group: 'Analysis' },
  { path: '/ai', label: 'AI workspace', group: 'Analysis' },
  { path: '/automation', label: 'Automation', group: 'Analysis' },
  { path: '/billing', label: 'Billing & credits', group: 'Account' },
  { path: '/notifications', label: 'Notifications', group: 'Account' },
  { path: '/support', label: 'Support', group: 'Account' },
  { path: '/audit', label: 'Audit log', group: 'Account' },
  { path: '/settings', label: 'Settings', group: 'Account' },
  { path: '/iam', label: 'IAM & users', group: 'Account' },
  { path: '/admin', label: 'Administration', group: 'Platform', staff: true },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const { session, logout, theme, toggleTheme, route } = useApp();
  const [menuOpen, setMenuOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [live, setLive] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!session) return;
    let alive = true;
    const load = async () => {
      try {
        const j = await api<{ notifications: Notification[] }>('/api/v1/notifications?limit=50');
        if (alive) setUnread(j.notifications.filter((n) => !n.read_at).length);
      } catch { /* ignore */ }
    };
    void load();
    const t = setInterval(load, 15000);
    return () => { alive = false; clearInterval(t); };
  }, [session, route.path]);

  // Live updates over SSE (falls back to the 15s poll above if the stream drops)
  useEffect(() => {
    if (!session) return;
    const tok = currentAccessToken();
    if (!tok || typeof EventSource === 'undefined') return;
    let es: EventSource | null = null;
    let closed = false;
    let retry: ReturnType<typeof setTimeout> | null = null;
    const bump = () => {
      void (async () => {
        try {
          const j = await api<{ notifications: Notification[] }>('/api/v1/notifications?limit=50');
          setUnread(j.notifications.filter((n) => !n.read_at).length);
        } catch { /* polling still runs */ }
      })();
    };
    const open = () => {
      if (closed) return;
      es = new EventSource(eventsUrl());
      es.onopen = () => setLive(true);
      es.onerror = () => {
        setLive(false);
        es?.close();
        if (!closed) retry = setTimeout(open, 5000); // token may have rotated
      };
      es.addEventListener('notification', bump);
      es.addEventListener('job.updated', bump);
      es.addEventListener('job.completed', bump);
      es.addEventListener('monitor.event', bump);
    };
    open();
    return () => { closed = true; if (retry) clearTimeout(retry); es?.close(); setLive(false); };
  }, [session]);

  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, []);

  if (!session) return <>{children}</>;

  const groups = [...new Set(NAV.filter((n) => !n.staff || session.user.is_staff).map((n) => n.group))];
  const current = NAV.slice().sort((a, b) => b.path.length - a.path.length).find((n) => n.path === route.path || (n.path !== '/' && route.path.startsWith(n.path)));
  const initials = (session.user.name || session.user.email).split(/\s+/).map((w) => w[0]).slice(0, 2).join('').toUpperCase();

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <img src="/favicon.svg" alt="" />
          <div>
            <div className="name">Meridian</div>
            <div className="sub">{session.tenant?.name || 'workspace'}</div>
          </div>
        </div>
        <nav style={{ flex: 1 }}>
          {groups.map((g) => (
            <div className="nav-group" key={g}>
              <div className="nav-label">{g}</div>
              {NAV.filter((n) => n.group === g && (!n.staff || session.user.is_staff)).map((n) => (
                <a key={n.path} className={`nav-item ${route.path === n.path ? 'active' : ''}`} href={`#${n.path}`}>
                  {n.label}
                  {n.path === '/notifications' && unread > 0 && <span className="badge accent">{unread}</span>}
                </a>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          Meridian Platform v1.0 · node/zero-dep core
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="crumb">
            <span>Workspace</span><span>/</span><b>{current?.label || 'Dashboard'}</b>
          </div>
          <div className="spacer" />
          <span title={live ? 'Live event stream connected' : 'Live stream offline — polling'} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--text-faint)', fontSize: 11 }}>
            <Dot tone={live ? 'ok' : 'idle'} /> {live ? 'live' : 'polling'}
          </span>
          <span className="cred-balance" title="Credit balance">{session.credits.toLocaleString()} cr</span>
          <button className="ghost sm" onClick={toggleTheme} title="Toggle theme">{theme === 'light' ? 'Dark' : 'Light'} mode</button>
          <div style={{ position: 'relative' }} ref={menuRef}>
            <button className="ghost" onClick={() => setMenuOpen((o) => !o)} style={{ gap: 8 }}>
              <span className="avatar">{initials}</span>
              <span className="user-chip">
                <span className="who">
                  {session.user.name}
                  <span className="r">{session.user.role}{session.user.is_staff ? ' · staff' : ''}</span>
                </span>
              </span>
            </button>
            {menuOpen && (
              <div className="menu">
                <button onClick={() => { setMenuOpen(false); window.location.hash = '/settings'; }}>Settings & security</button>
                <button onClick={() => { setMenuOpen(false); window.location.hash = '/billing'; }}>Billing</button>
                <button className="danger" onClick={() => { setMenuOpen(false); void logout(); }}>Sign out</button>
              </div>
            )}
          </div>
        </header>
        <main className="content">
          <div className="content-inner">{children}</div>
        </main>
      </div>
    </div>
  );
}

export function StaffOnly({ children }: { children: React.ReactNode }) {
  const { session } = useApp();
  if (!session?.user.is_staff) {
    return <div className="notice err">This area requires platform staff privileges.</div>;
  }
  return <>{children}</>;
}

export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const total = order.reduce((s, k) => s + (counts[k] || 0), 0) || 1;
  return (
    <div style={{ display: 'flex', gap: 2, height: 8, borderRadius: 4, overflow: 'hidden' }}>
      {order.map((k) => (
        <div key={k} title={`${k}: ${counts[k] || 0}`} style={{
          width: `${((counts[k] || 0) / total) * 100}%`,
          background: { critical: '#a02c22', high: 'var(--warn)', medium: '#caa93f', low: 'var(--accent)', info: 'var(--border-strong)' }[k],
        }} />
      ))}
    </div>
  );
}

export { Badge };
