/** Router: maps hash routes to views. A view crash is contained by ErrorBoundary. */
import React from 'react';
import { useApp } from './state';
import { Shell } from './shell';

/** Contain view crashes: one broken view must never take down the workspace. */
class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidUpdate(prev: { children: React.ReactNode }) {
    if (prev.children !== this.props.children && this.state.error) this.setState({ error: null });
  }
  render() {
    if (this.state.error) {
      return (
        <div className="panel" style={{ marginTop: 14 }}>
          <div className="panel-head"><h3>This view failed to render</h3></div>
          <div className="panel-body">
            <p style={{ marginTop: 0 }}>{String(this.state.error.message || this.state.error)}</p>
            <p style={{ color: 'var(--text-dim)', fontSize: 12 }}>The rest of the workspace is unaffected. This is a bug — please report it via Support with the message above.</p>
            <button onClick={() => this.setState({ error: null })}>Try again</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
import { LoginView } from './views/login';
import { DashboardView, JobsView, JobDetailView, AssetsView, FindingsView, FindingDetailView, EvidenceView, SecurityView, MonitoringView } from './views/ops';
import { MarketplaceView, RequestsView, ReportsView, BillingView, NotificationsView, SupportView } from './views/biz';
import { DataView, DocumentsView, AiView, AutomationView } from './views/data';
import { SettingsView, IamView, AuditView, AdminView } from './views/core';

export function App() {
  const { session, ready, route } = useApp();

  if (!ready) {
    return <div className="loading" style={{ minHeight: '100vh' }}><span className="spinner" /> Loading Meridian…</div>;
  }
  if (!session) {
    return (
      <Shell>
        <LoginView />
      </Shell>
    );
  }

  const p = route.parts;
  let view: React.ReactNode;
  if (p.length === 0) view = <DashboardView />;
  else if (p[0] === 'login') view = <DashboardView />;
  else if (p[0] === 'marketplace') view = <MarketplaceView />;
  else if (p[0] === 'requests') view = <RequestsView />;
  else if (p[0] === 'jobs' && p[1]) view = <JobDetailView id={p[1]} />;
  else if (p[0] === 'jobs') view = <JobsView />;
  else if (p[0] === 'assets') view = <AssetsView />;
  else if (p[0] === 'findings' && p[1]) view = <FindingDetailView id={p[1]} />;
  else if (p[0] === 'findings') view = <FindingsView />;
  else if (p[0] === 'evidence') view = <EvidenceView />;
  else if (p[0] === 'security') view = <SecurityView />;
  else if (p[0] === 'monitoring') view = <MonitoringView />;
  else if (p[0] === 'reports') view = <ReportsView />;
  else if (p[0] === 'data') view = <DataView />;
  else if (p[0] === 'documents') view = <DocumentsView />;
  else if (p[0] === 'ai') view = <AiView />;
  else if (p[0] === 'automation') view = <AutomationView />;
  else if (p[0] === 'billing') view = <BillingView />;
  else if (p[0] === 'notifications') view = <NotificationsView />;
  else if (p[0] === 'support') view = <SupportView />;
  else if (p[0] === 'audit') view = <AuditView />;
  else if (p[0] === 'settings') view = <SettingsView />;
  else if (p[0] === 'iam') view = <IamView />;
  else if (p[0] === 'admin') view = <AdminView />;
  else view = (
    <div className="empty" style={{ padding: 80 }}>
      <div className="big">Page not found</div>
      <a href="#/">Back to dashboard</a>
    </div>
  );

  return <Shell><ErrorBoundary key={route.path}>{view}</ErrorBoundary></Shell>;
}
