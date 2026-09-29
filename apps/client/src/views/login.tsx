import React, { useState } from 'react';
import { useApp } from '../state';
import { Field } from '../ui';

export function LoginView() {
  const { login, navigate } = useApp();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [needTotp, setNeedTotp] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      const r = await login(email, password, needTotp ? totp : undefined);
      if (r.mfa_required) { setNeedTotp(true); setBusy(false); return; }
      navigate('/');
    } catch (ex: any) {
      setErr(ex?.message || 'Login failed');
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="brand"><img src="/favicon.svg" alt="Meridian" /><h1>Meridian Platform</h1></div>
        <div className="sub">Sign in to your workspace</div>
        {err && <div className="login-error">{err}</div>}
        <Field label="Email">
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required placeholder="you@company.com" />
        </Field>
        <Field label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required placeholder="••••••••••" />
        </Field>
        {needTotp && (
          <Field label="Authenticator code" help="Your account is protected with two-factor authentication.">
            <input value={totp} onChange={(e) => setTotp(e.target.value)} inputMode="numeric" maxLength={6} placeholder="123456" autoFocus />
          </Field>
        )}
        <button className="primary" type="submit" disabled={busy || !email || !password || (needTotp && totp.length < 6)} style={{ width: '100%', justifyContent: 'center', marginTop: 6 }}>
          {busy ? <span className="spinner" style={{ borderTopColor: '#fff' }} /> : needTotp ? 'Verify and sign in' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
