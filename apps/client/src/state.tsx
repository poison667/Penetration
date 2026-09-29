/** App state: session, theme, toasts, hash router. */
import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api, setTokens, tokens, User, Tenant } from './api';

export interface Session { user: User; tenant: Tenant; credits: number }

interface Ctx {
  session: Session | null;
  ready: boolean;
  login: (email: string, password: string, totp?: string) => Promise<{ mfa_required?: boolean }>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
  theme: 'light' | 'dark';
  toggleTheme: () => void;
  toast: (msg: string, tone?: 'ok' | 'err') => void;
  route: { path: string; parts: string[] };
  navigate: (to: string) => void;
}

const AppCtx = createContext<Ctx>({} as Ctx);
export const useApp = () => useContext(AppCtx);

export function parseHash(): { path: string; parts: string[] } {
  const h = window.location.hash.replace(/^#/, '') || '/';
  return { path: h, parts: h.split('/').filter(Boolean) };
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>((localStorage.getItem('meridian.theme') as 'light' | 'dark') || 'light');
  const [toasts, setToasts] = useState<{ id: number; msg: string; tone: 'ok' | 'err' }[]>([]);
  const [route, setRoute] = useState(parseHash());

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('meridian.theme', theme);
  }, [theme]);

  useEffect(() => {
    const h = () => setRoute(parseHash());
    window.addEventListener('hashchange', h);
    return () => window.removeEventListener('hashchange', h);
  }, []);

  const navigate = useCallback((to: string) => { window.location.hash = to; }, []);

  const loadSession = useCallback(async () => {
    if (!tokens().accessToken) { setSession(null); setReady(true); return; }
    try {
      const me = await api<{ user: User; tenant: Tenant; credits: number }>('/api/v1/auth/me');
      setSession({ user: me.user, tenant: me.tenant, credits: me.credits });
    } catch {
      setTokens(null, null);
      setSession(null);
    } finally { setReady(true); }
  }, []);

  useEffect(() => { void loadSession(); }, [loadSession]);

  const login = useCallback(async (email: string, password: string, totp?: string) => {
    const j = await api<{ user?: User; access_token?: string; refresh_token?: string; mfa_required?: boolean }>('/api/v1/auth/login', {
      method: 'POST', body: { email, password, ...(totp ? { totp } : {}) },
    });
    if (j.mfa_required) return { mfa_required: true };
    setTokens(j.access_token!, j.refresh_token!);
    await loadSession();
    return {};
  }, [loadSession]);

  const logout = useCallback(async () => {
    try { await api('/api/v1/auth/logout', { method: 'POST', body: {} }); } catch { /* best effort */ }
    setTokens(null, null);
    setSession(null);
    navigate('/login');
  }, [navigate]);

  const toast = useCallback((msg: string, tone: 'ok' | 'err' = 'ok') => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, msg, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);

  return (
    <AppCtx.Provider value={{
      session, ready, login, logout, refreshSession: loadSession,
      theme, toggleTheme: () => setTheme((t) => (t === 'light' ? 'dark' : 'light')),
      toast, route, navigate,
    }}>
      {children}
      <div className="toasts">
        {toasts.map((t) => <div key={t.id} className={`toast ${t.tone}`}>{t.msg}</div>)}
      </div>
    </AppCtx.Provider>
  );
}
