import { URL } from 'node:url';
import tls from 'node:tls';

/** Engine: Secure Transmission / TLS analysis. */
export const tlsEngine = {
  key: 'sec_transmission',
  title: 'Secure Transmission / TLS Analysis',
  async run(ctx) {
    const start = new URL(ctx.asset.base_url || ctx.asset.identifier);
    let host = start.hostname;
    let port = start.port ? Number(start.port) : start.protocol === 'https:' ? 443 : 80;

    if (start.protocol !== 'https:') {
      // HTTPS enforcement check (TLS-007)
      const httpStart = start.toString();
      const res = await ctx.fetch(httpStart);
      const upgraded = res.redirects.some((r) => String(r.location || '').startsWith('https://')) || res.finalUrl.startsWith('https://');
      const base7 = { target: `${host}:${port}` };
      if (!upgraded) {
        ctx.report('TLS-007', { ...base7, severity: 'high', confidence: 'confirmed', endpoint: '/', facts: [`HTTP ${httpStart} does not redirect to HTTPS (final URL: ${res.finalUrl}).`], inference: ['Traffic and credentials can be intercepted or modified in transit.'], evidence: [ctx.evidenceFrom(res, 'HTTP-to-HTTPS redirect probe')] });
      } else {
        ctx.report('TLS-007', { ...base7, severity: 'low', confidence: 'confirmed', endpoint: '/', facts: [`HTTP redirects to HTTPS: ${res.finalUrl}.`], inference: ['HTTPS enforcement is present.'], evidence: [ctx.evidenceFrom(res, 'HTTP-to-HTTPS redirect probe')] });
      }

      // The declared scope may still include an HTTPS endpoint on another port
      // (e.g. an http+https service pair). Probe only ports explicitly listed in
      // the asset's authorization record — never port-scan beyond the scope.
      const declared = (ctx.asset?.authorization?.ports || []).map(Number).filter((p) => Number.isFinite(p) && p > 0 && p !== port);
      let tlsEndpoint = null;
      for (const p of declared) {
        const probe0 = await ctx.fetcher.tlsProbe(host, p);
        if (probe0.ok) { tlsEndpoint = { port: p, probe: probe0 }; break; }
      }
      if (!tlsEndpoint) return; // no TLS endpoint in the authorized scope — nothing to analyze
      ctx.log('info', `analyzing in-scope TLS endpoint ${host}:${tlsEndpoint.port} (asset base is ${start.protocol}//${host}:${port})`);
      await analyzeTls(ctx, { host, port: tlsEndpoint.port, probe: tlsEndpoint.probe, startUrl: `https://${host}:${tlsEndpoint.port}/` });
      return;
    }

    // Preferred configuration (https asset)
    const probe = await ctx.fetcher.tlsProbe(host, port);
    if (!probe.ok) {
      ctx.log('warn', `TLS probe failed: ${probe.error}`);
      const ev = ctx.evidenceRaw('tls', { host, port, error: probe.error }, `TLS connection failure for ${host}:${port}`);
      ctx.report('TLS-006', { target: `${host}:${port}`, severity: 'high', confidence: 'confirmed', facts: [`TLS handshake failed: ${probe.error}.`], inference: ['The TLS service is misconfigured or unreachable.'], evidence: [ev] });
      return;
    }
    await analyzeTls(ctx, { host, port, probe, startUrl: start.toString() });
  },
};

/** Shared full TLS analysis for a reachable TLS endpoint. */
async function analyzeTls(ctx, { host, port, probe, startUrl }) {
  const base = { target: `${host}:${port}` };
  const cert = probe.cert;
  const evTls = ctx.evidenceRaw('tls', {
    host, port, protocol: probe.protocol, cipher: probe.cipher, authorized: probe.authorized,
    authorization_error: probe.authorizationError, alpn: probe.alpn,
    cert: cert && { subject: cert.subject, issuer: cert.issuer, valid_from: cert.valid_from, valid_to: cert.valid_to, sig_alg: cert.sigAlgorithm, san: cert.subjectaltname, fingerprint256: cert.fingerprint256, serial: cert.serialNumber },
    chain_length: probe.chain.length,
  }, `TLS handshake details for ${host}:${port}`);

  // TLS-001 protocol versions
  const weak = [];
  for (const version of ['TLSv1', 'TLSv1.1']) {
    const p = await ctx.fetcher.tlsProbe(host, port, { maxVersion: version, minVersion: 'TLSv1' });
    if (p.ok && (p.protocol === version)) weak.push(version);
  }
  ctx.metrics.tls = { protocol: probe.protocol, cipher: probe.cipher?.name, weak_versions_accepted: weak };
  if (weak.length) {
    ctx.report('TLS-001', { ...base, severity: 'high', confidence: 'confirmed', facts: [`Negotiated protocol: ${probe.protocol} with ${probe.cipher?.name}.`, `Server accepts obsolete protocol versions: ${weak.join(', ')}.`], inference: ['Legacy TLS versions are subject to downgrade and BEAST/POODLE-class attacks.'], evidence: [evTls, ctx.evidenceRaw('tls', { weak_probes: weak }, `Weak TLS version acceptance for ${host}`)] });
  } else {
    ctx.report('TLS-001', { ...base, severity: 'info', confidence: 'confirmed', facts: [`Negotiated protocol: ${probe.protocol}; TLS 1.0/1.1 rejected.`], inference: ['Protocol policy meets current guidance.'], evidence: [evTls] });
  }

  // TLS-002 weak ciphers
  const weakCipher = await ctx.fetcher.tlsProbe(host, port, { ciphers: 'DES-CBC3-SHA:AES128-SHA:RC4-SHA' });
  if (weakCipher.ok && /3DES|RC4|CBC/i.test(weakCipher.cipher?.name || '')) {
    ctx.report('TLS-002', { ...base, severity: 'high', confidence: 'confirmed', facts: [`Server negotiated weak cipher ${weakCipher.cipher?.name} (${weakCipher.cipher?.version}) when offered.`], inference: ['Weak ciphers expose traffic to cryptanalytic attacks (SWEET32/BAR MITM).'], evidence: [evTls, ctx.evidenceRaw('tls', { offered_weak: true, negotiated: weakCipher.cipher }, `Weak cipher acceptance for ${host}`)] });
  }

  if (cert) {
    // TLS-003 validity
    const daysLeft = cert.valid_to_ts ? Math.floor((cert.valid_to_ts - Date.now()) / 86400_000) : null;
    ctx.metrics.cert_expiry_days = daysLeft;
    if (cert.valid_to_ts && cert.valid_to_ts < Date.now()) {
      ctx.report('TLS-003', { ...base, severity: 'high', confidence: 'confirmed', facts: [`Certificate expired on ${cert.valid_to}.`], inference: ['Clients receive security warnings; impersonation risk.'], evidence: [evTls] });
    } else if (daysLeft != null && daysLeft < 21) {
      ctx.report('TLS-003', { ...base, severity: 'medium', confidence: 'confirmed', facts: [`Certificate expires in ${daysLeft} days (${cert.valid_to}).`], inference: ['Renewal should be scheduled now.'], evidence: [evTls] });
    }
    // TLS-004 signature
    if (/sha-?1|md5/i.test(cert.sigAlgorithm || '')) {
      ctx.report('TLS-004', { ...base, severity: 'high', confidence: 'confirmed', facts: [`Certificate uses signature algorithm ${cert.sigAlgorithm}.`], inference: ['Weak signature algorithms allow forged certificates.'], evidence: [evTls] });
    }
    // TLS-005 CN/SAN
    const san = String(cert.subjectaltname || '');
    const cn = cert.subjectCN || '';
    const matches = san.split(',').some((s) => s.trim().replace(/^DNS:/i, '') === host) || cn === host || san.includes(`*.${host.split('.').slice(1).join('.')}`);
    if (!matches) {
      ctx.report('TLS-005', { ...base, severity: 'high', confidence: 'confirmed', facts: [`Certificate CN="${cn}", SAN="${san.slice(0, 200)}" — does not cover "${host}".`], inference: ['Clients will reject the certificate; MITM proxies become viable.'], evidence: [evTls] });
    }
    // TLS-006 trust
    if (!probe.authorized) {
      ctx.report('TLS-006', { ...base, severity: 'medium', confidence: 'confirmed', facts: [`Certificate not trusted by system CA store: ${probe.authorizationError}.`, `Issuer: ${cert.issuerCN || 'unknown'}; chain length served: ${probe.chain.length}.`], inference: ['Self-signed or incomplete chain — clients fail or users learn to click through warnings.'], evidence: [evTls] });
    }
  }

  // TLS-008 mixed content + TLS-009 credential transport on the https page
  const page = await ctx.getOrFetch(startUrl);
  if (page.dom) {
    const { findAll, attr } = await import('#lib/html');
    const httpRes = findAll(page.dom, (n) => ['img', 'script', 'iframe', 'link'].includes(n.tag) && (attr(n, 'src') || attr(n, 'href') || '').startsWith('http:'));
    if (httpRes.length) {
      ctx.report('TLS-008', { ...base, severity: 'medium', confidence: 'confirmed', endpoint: new URL(startUrl).pathname, facts: [`${httpRes.length} subresources loaded over http: ${httpRes.slice(0, 5).map((n) => attr(n, 'src') || attr(n, 'href')).join(', ')}.`], inference: ['Mixed content triggers browser warnings and enables active MITM injection.'], evidence: [evTls, ctx.evidenceFrom(page.res, 'Page containing mixed content')] });
    }
  }
}
