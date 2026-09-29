import tls from 'node:tls';
import dns from 'node:dns/promises';
import net from 'node:net';
import { URL } from 'node:url';
import { sha256, nowIso } from '#core/util';
import { bus, TOPICS } from '#core/events';
import { notify } from '#app/notify';

/**
 * Monitoring engine — real checks with recorded history and state-transition
 * events. Types: http, keyword, content_hash, tls_cert, dns, api, port.
 */
export async function runMonitor(db, monitor, { fetchFn } = {}) {
  const tid = monitor.tenant_id;
  const config = { ...(monitor.config || {}) };
  if (monitor.url && !config.url) config.url = monitor.url; // top-level url is the canonical storage shape
  const url = config.url;
  const check = { id: `chk_${Math.random().toString(36).slice(2, 12)}`, monitor_id: monitor.id, tenant_id: tid, ts: nowIso(), ok: false, status_code: null, latency_ms: null, detail: {}, content_hash: null, message: null };
  const t0 = Date.now();

  try {
    switch (monitor.type) {
      case 'http': case 'keyword': case 'content_hash': case 'api': {
        const res = fetchFn ? await fetchFn(url) : await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(15_000) });
        check.status_code = res.status;
        check.latency_ms = Date.now() - t0;
        const body = await res.text();
        check.content_hash = sha256(body);
        if (monitor.type === 'http') {
          check.ok = res.status >= 200 && res.status < 400;
          if (config.expected_status) check.ok = check.ok && res.status === Number(config.expected_status);
          check.message = check.ok ? 'HTTP check passed' : `unexpected status ${res.status}`;
        } else if (monitor.type === 'keyword') {
          const found = body.includes(config.keyword || '');
          check.ok = config.must_exist === false ? !found : found;
          check.message = check.ok ? `keyword "${config.keyword}" ${config.must_exist === false ? 'absent' : 'present'}` : `keyword "${config.keyword}" ${config.must_exist === false ? 'present' : 'absent'}`;
        } else if (monitor.type === 'content_hash') {
          check.ok = !monitor.last_content_hash || monitor.last_content_hash === check.content_hash;
          check.message = check.ok ? (monitor.last_content_hash ? 'content unchanged' : 'baseline recorded') : 'content changed';
          check.detail.changed = !check.ok;
        } else { // api: JSON assertion expression
          let json = null;
          try { json = JSON.parse(body); } catch { check.ok = false; check.message = 'response is not valid JSON'; break; }
          const { evaluate } = await import('#core/expr');
          check.ok = config.assertion ? !!evaluate(config.assertion, { $: json, response: json, status: res.status }) : res.ok;
          check.message = check.ok ? 'assertion passed' : `assertion failed: ${config.assertion}`;
          check.detail.value = json;
        }
        break;
      }
      case 'tls_cert': {
        const u = new URL(url);
        const info = await new Promise((resolve) => {
          const s = tls.connect({ host: u.hostname, port: u.port || 443, servername: u.hostname, rejectUnauthorized: false, timeout: 10_000 }, () => {
            const cert = s.getPeerCertificate();
            resolve({ ok: true, days: cert.valid_to ? Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000) : null, issuer: cert.issuer?.CN || null, subject: cert.subject?.CN || null, valid_to: cert.valid_to });
            s.end();
          });
          s.on('timeout', () => { s.destroy(); resolve({ ok: false, error: 'timeout' }); });
          s.on('error', (e) => resolve({ ok: false, error: e.message }));
        });
        check.ok = info.ok && (info.days == null || info.days > (config.warn_days ?? 14));
        check.latency_ms = Date.now() - t0;
        check.detail = info;
        check.message = info.ok ? `certificate valid ${info.days} days (issuer: ${info.issuer})` : `TLS check failed: ${info.error}`;
        break;
      }
      case 'dns': {
        const u = new URL(url);
        const recordTypes = config.record_types || ['A'];
        const current = {};
        for (const rt of recordTypes) {
          try {
            current[rt] = await (rt === 'A' ? dns.resolve4(u.hostname) : rt === 'AAAA' ? dns.resolve6(u.hostname) : rt === 'CNAME' ? dns.resolveCname(u.hostname) : rt === 'MX' ? dns.resolveMx(u.hostname) : rt === 'TXT' ? dns.resolveTxt(u.hostname) : rt === 'NS' ? dns.resolveNs(u.hostname) : []);
          } catch { current[rt] = []; }
        }
        check.ok = true;
        check.detail.records = current;
        const prev = monitor.last_dns_snapshot ? JSON.stringify(monitor.last_dns_snapshot) : null;
        const cur = JSON.stringify(current);
        check.detail.changed = prev != null && prev !== cur;
        check.message = check.detail.changed ? 'DNS records changed' : 'DNS records stable';
        check.content_hash = sha256(cur);
        break;
      }
      case 'port': {
        const u = new URL(url);
        const open = await new Promise((resolve) => {
          const s = net.connect({ host: u.hostname, port: Number(config.port || u.port || 80), timeout: 5_000 }, () => { s.destroy(); resolve(true); });
          s.on('error', () => resolve(false));
          s.on('timeout', () => { s.destroy(); resolve(false); });
        });
        check.ok = config.expect_open === false ? !open : open;
        check.latency_ms = Date.now() - t0;
        check.message = `port ${config.port || u.port || 80} ${open ? 'open' : 'closed'}`;
        break;
      }
      default:
        check.message = `unknown monitor type: ${monitor.type}`;
    }
  } catch (e) {
    check.ok = false;
    check.latency_ms = Date.now() - t0;
    check.message = `check error: ${e.message || e}`;
  }

  db.store.put('monitor_checks', check);

  // state transition + events
  const wasUp = monitor.last_status === 'up';
  const nowUp = check.ok;
  const events = [];
  if (monitor.last_status !== (nowUp ? 'up' : 'down')) {
    if (monitor.last_status != null) {
      const ev = db.insert('monitor_events', {
        tenant_id: tid, monitor_id: monitor.id, ts: nowIso(),
        type: nowUp ? 'up' : 'down', detail: { status_code: check.status_code, message: check.message, latency_ms: check.latency_ms },
      });
      events.push(ev);
      bus.publish(TOPICS.monitorEvent, { id: ev.id, tenant_id: tid, monitor: { id: monitor.id, type: monitor.type, name: monitor.name, asset_id: monitor.asset_id }, event: { type: ev.type, message: ev.message || check.message, detail: ev.detail } });
      notify(db, { tenantId: tid, type: nowUp ? 'monitor_up' : 'monitor_down', title: `${monitor.name} is ${nowUp ? 'up' : 'DOWN'}`, body: check.message || '', data: { monitor_id: monitor.id, event_id: ev.id } });
    }
  }
  if (check.detail?.changed) {
    const kind = monitor.type === 'dns' ? 'change' : 'change';
    const ev = db.insert('monitor_events', {
      tenant_id: tid, monitor_id: monitor.id, ts: nowIso(), type: kind,
      detail: { message: check.message, before_hash: monitor.last_content_hash || null, after_hash: check.content_hash },
    });
    events.push(ev);
    bus.publish(TOPICS.monitorEvent, { id: ev.id, tenant_id: tid, monitor: { id: monitor.id, type: monitor.type, name: monitor.name, asset_id: monitor.asset_id }, event: { type: 'change', message: check.message, detail: ev.detail } });
    notify(db, { tenantId: tid, type: 'monitor_change', title: `${monitor.name}: change detected`, body: check.message, data: { monitor_id: monitor.id } });
  }
  if (monitor.type === 'tls_cert' && check.detail?.days != null && check.detail.days <= (config.warn_days ?? 14) && !check.ok) {
    const ev = db.insert('monitor_events', { tenant_id: tid, monitor_id: monitor.id, ts: nowIso(), type: 'cert_expiring', detail: { days: check.detail.days } });
    bus.publish(TOPICS.monitorEvent, { id: ev.id, tenant_id: tid, monitor: { id: monitor.id, type: monitor.type, name: monitor.name, asset_id: monitor.asset_id }, event: { type: 'cert_expiring', detail: { days: check.detail.days } } });
    notify(db, { tenantId: tid, type: 'cert_expiring', title: `${monitor.name}: certificate expiring`, body: `Certificate expires in ${check.detail.days} days`, data: { monitor_id: monitor.id } });
  }

  db.store.put('monitors', {
    ...monitor,
    last_status: nowUp ? 'up' : 'down',
    last_run_at: check.ts,
    next_run_at: new Date(Date.now() + (monitor.interval_seconds || 300) * 1000).toISOString(),
    last_content_hash: check.content_hash || monitor.last_content_hash,
    last_dns_snapshot: monitor.type === 'dns' ? (check.detail?.records || monitor.last_dns_snapshot) : monitor.last_dns_snapshot,
  });
  return { check, events };
}
