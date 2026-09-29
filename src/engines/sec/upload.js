import { URL } from 'node:url';
import { forms } from '#lib/html';

/** Engine: File Upload Security Assessment. Passive inventory; active probes gated to intrusive profile. */
export const uploadEngine = {
  key: 'sec_upload',
  title: 'File Upload Security Assessment',
  async run(ctx) {
    const start = ctx.asset.base_url || ctx.asset.identifier;
    const origin = new URL(start).origin;

    // Discover upload endpoints
    const uploadForms = (ctx.state.crawl?.forms || []).filter((f) => f.hasFileField);
    const extra = [];
    if (!uploadForms.length) {
      for (const path of ['/upload', '/profile/upload', '/media/upload']) {
        const p = await ctx.getOrFetch(new URL(path, origin).toString());
        if (p.res.ok && p.dom) for (const f of forms(p.dom, p.res.finalUrl)) if (f.hasFileField) extra.push(f);
      }
    }
    const all = [...uploadForms, ...extra];
    ctx.inventory.uploads = all.map((f) => ({ action: f.action, method: f.method, fields: f.fields.filter((x) => x.type === 'file').map((x) => x.name), accept: f.fields.find((x) => x.type === 'file')?.accept || null }));
    if (!all.length) {
      ctx.log('info', 'no upload endpoints found in scope');
      return;
    }

    for (const f of all.slice(0, 3)) {
      const fileField = f.fields.find((x) => x.type === 'file')?.name || 'file';
      // UPL-009/010: unauthenticated access
      const unauth = await ctx.fetch(f.action, { method: 'GET' });
      const authRequired = unauth.status === 401 || unauth.status === 403 || /login|password/i.test(unauth.bodyText.slice(0, 1000));
      if (!authRequired) {
        ctx.report('UPL-009', {
          severity: 'high', confidence: 'medium', endpoint: f.action, target: ctx.asset.identifier,
          facts: [`Upload surface at ${f.action} is reachable without authentication (HTTP ${unauth.status}, no login redirect).`],
          inference: ['Unauthenticated upload surfaces allow abuse for storage, malware hosting and DoS.'],
          evidence: [ctx.evidenceFrom(unauth, 'Unauthenticated access to upload surface')],
        });
      } else {
        ctx.log('info', `upload endpoint ${f.action} requires authentication — UPL-009 satisfied`);
      }

      // Passive inventory finding
      ctx.report('UPL-001', {
        severity: 'info', confidence: 'confirmed', endpoint: f.action, target: ctx.asset.identifier, parameter: fileField,
        facts: [`File upload endpoint discovered: ${f.method} ${f.action} (field "${fileField}").`, `Client-side accept attribute: ${f.fields.find((x) => x.type === 'file')?.accept || '(none)'}.`],
        inference: ['Client-side restrictions are bypassable; server-side allowlists must be verified (active verification requires the intrusive profile with explicit authorization).'],
        evidence: [ctx.evidenceRaw('derived', { form: f }, `Upload form inventory for ${f.action}`)],
      });
    }

    // Active gated probes: intrusive profile only
    if (ctx.profile === 'intrusive' && all.length) {
      const f = all[0];
      const fileField = f.fields.find((x) => x.type === 'file')?.name || 'file';
      // UPL-004/UPL-001: benign content with mismatched extension
      const boundary = `----meridian${Date.now()}`;
      const body = Buffer.from(
        `--${boundary}\r\ncontent-disposition: form-data; name="${fileField}"; filename="probe.txt.php"\r\ncontent-type: application/x-php\r\n\r\nMERIDIAN_PROBE benign content\r\n--${boundary}--\r\n`,
      );
      const up = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, body });
      if (up.status >= 200 && up.status < 300) {
        // If the response reveals a hosted path, attempt retrieval
        const loc = up.bodyText.match(/(?:\/[\w./-]+)\.(?:php|txt)/)?.[0];
        if (loc) {
          const served = await ctx.fetch(new URL(loc, origin).toString());
          if (served.ok && served.bodyText.includes('MERIDIAN_PROBE')) {
            const execHint = /x-php|text\/html/i.test(served.contentType);
            ctx.report('UPL-004', {
              severity: 'high', confidence: 'confirmed', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier,
              facts: [`Uploaded "probe.txt.php" (content "MERIDIAN_PROBE") was accepted and is served at ${served.finalUrl} as ${served.contentType}.`],
              inference: [execHint ? 'Content is served with an executable/HTML type — extension-content mismatch accepted, RCE risk.' : 'Uploaded file is publicly retrievable.'],
              evidence: [ctx.evidenceFrom(up, 'Upload acceptance'), ctx.evidenceFrom(served, 'Retrieval of uploaded file')],
            });
            ctx.report('UPL-007', { severity: 'high', confidence: 'confirmed', endpoint: loc, target: ctx.asset.identifier, facts: [`Uploaded file is publicly served at ${served.finalUrl}.`], inference: ['Uploads land inside the web root and are publicly accessible.'], evidence: [ctx.evidenceFrom(served, 'Public upload retrieval')] });
          }
        }
      } else {
        ctx.report('UPL-001', { severity: 'info', confidence: 'confirmed', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier, facts: [`Mismatched-extension upload was rejected (HTTP ${up.status}).`], inference: ['A server-side rejection was observed.'], evidence: [ctx.evidenceFrom(up, 'Rejected mismatched upload')] });
      }
      // UPL-002 size limit: 5MB benign file
      const bigBoundary = `----meridianbig${Date.now()}`;
      const bigContent = 'A'.repeat(5 * 1024 * 1024);
      const bigBody = Buffer.from(`--${bigBoundary}\r\ncontent-disposition: form-data; name="${fileField}"; filename="big.txt"\r\ncontent-type: text/plain\r\n\r\n${bigContent}\r\n--${bigBoundary}--\r\n`);
      const bigUp = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${bigBoundary}` }, body: bigBody });
      if (bigUp.status >= 200 && bigUp.status < 300) {
        ctx.report('UPL-002', { severity: 'medium', confidence: 'medium', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier, facts: ['A 5MB upload was accepted without rejection.'], inference: ['No effective upload size limit observed.'], evidence: [ctx.evidenceFrom(bigUp, 'Oversize upload acceptance')] });
      }

      const multipart = (boundary, filename, content, ctype) => Buffer.from(
        `--${boundary}\r\ncontent-disposition: form-data; name="${fileField}"; filename="${filename}"\r\ncontent-type: ${ctype}\r\n\r\n${content}\r\n--${boundary}--\r\n`);

      // UPL-003: upload frequency/count limiting — 8 rapid small uploads
      let accepted = 0, lastStatus = null;
      for (let i = 0; i < 8; i++) {
        const b = `----mrpdfreq${Date.now()}${i}`;
        const r = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${b}` }, body: multipart(b, `freq-probe-${i}.txt`, `MERIDIAN_FREQ_PROBE ${i}`, 'text/plain') });
        lastStatus = r.status;
        if (r.status >= 200 && r.status < 300) accepted++;
      }
      ctx.metrics.upload_frequency_accepted = accepted;
      if (accepted >= 8) {
        ctx.report('UPL-003', { severity: 'low', confidence: 'medium', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier, facts: [`8 consecutive uploads were all accepted (${accepted}/8, last HTTP ${lastStatus}) with no rate limiting observed.`], inference: ['No upload frequency/count limit — storage-exhaustion abuse is possible.'], evidence: [ctx.evidenceRaw('derived', { accepted, attempts: 8, last_status: lastStatus }, 'Upload frequency probe result')] });
      }

      // UPL-005: malware scanning — EICAR test string (harmless industry-standard test file)
      const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
      const eb = `----mrpdeicar${Date.now()}`;
      const eicarUp = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${eb}` }, body: multipart(eb, 'eicar-test.txt', EICAR, 'text/plain') });
      ctx.metrics.eicar_upload_status = eicarUp.status;
      if (eicarUp.status >= 200 && eicarUp.status < 300) {
        ctx.report('UPL-005', { severity: 'info', confidence: 'low', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier, facts: ['The EICAR standard antivirus test file was accepted by the upload endpoint (no synchronous malware rejection).'], inference: ['No inline malware scanning observed — scanning may still occur asynchronously; verify deployment.'], evidence: [ctx.evidenceFrom(eicarUp, 'EICAR test file acceptance')] });
      }

      // UPL-006: filename sanitization — traversal characters in filename
      const tb = `----mrpdtrav${Date.now()}`;
      const travUp = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${tb}` }, body: multipart(tb, '../../../mrpd-traversal-probe.txt', 'MERIDIAN_TRAVERSAL_PROBE', 'text/plain') });
      ctx.metrics.traversal_filename_status = travUp.status;
      const travReflected = /\.\.[\/\\]|mrpd-traversal-probe/.test(travUp.bodyText);
      if (travUp.status >= 200 && travUp.status < 300 && /\.\.[\/\\]/.test(travUp.bodyText)) {
        ctx.report('UPL-006', { severity: 'medium', confidence: 'medium', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier, facts: ['A filename containing path-traversal sequences (../../../mrpd-traversal-probe.txt) was accepted and the response reflects the unsanitized path.'], inference: ['Filenames are not sanitized — uploaded files may land outside the intended directory.'], evidence: [ctx.evidenceFrom(travUp, 'Unsanitized filename handling')] });
      }

      // UPL-008: upload host separation — where is the upload served from?
      const loc = up.bodyText.match(/(?:https?:\/\/[^\s"']+)?\/[\w./-]+\.(?:php|txt|png|jpe?g)/)?.[0];
      if (loc) {
        const served = await ctx.fetch(new URL(loc, origin).toString());
        if (served.ok) {
          const sameHost = new URL(served.finalUrl).host === new URL(origin).host;
          ctx.report('UPL-008', { severity: sameHost ? 'medium' : 'info', confidence: 'low', endpoint: served.finalUrl, target: ctx.asset.identifier, facts: [`Uploaded content is served from ${new URL(served.finalUrl).host}${sameHost ? ' — the same host as the application.' : ' — a separate upload host.'}`], inference: sameHost ? ['Uploads are served from the application origin — XSS/malware on the main domain is possible if content-type checks fail.'] : ['Uploads are isolated on a separate host — good practice.'], evidence: [ctx.evidenceFrom(served, 'Upload retrieval host')] });
        }
      }

      // UPL-010: authorization (distinct from authentication) — forged session cookie
      const fb = `----mrpdforged${Date.now()}`;
      const forged = await ctx.fetch(f.action, { method: 'POST', headers: { 'content-type': `multipart/form-data; boundary=${fb}`, cookie: 'sid=mrpd-forged-session-token; session=mrpd-forged-session-token' }, body: multipart(fb, 'forged-session-probe.txt', 'MERIDIAN_FORGED_SESSION_PROBE', 'text/plain') });
      ctx.metrics.forged_session_upload_status = forged.status;
      if (forged.status >= 200 && forged.status < 300 && !/login|password|unauthorized|forbidden/i.test(forged.bodyText.slice(0, 2000))) {
        ctx.report('UPL-010', { severity: 'high', confidence: 'medium', endpoint: f.action, parameter: fileField, target: ctx.asset.identifier, facts: ['An upload with a forged (invalid) session cookie was accepted (HTTP ' + forged.status + ') without an authorization failure.'], inference: ['The upload endpoint does not validate session ownership — authorization is not enforced.'], evidence: [ctx.evidenceFrom(forged, 'Upload accepted with forged session')] });
      }
    } else {
      ctx.log('info', 'active upload probes skipped (requires intrusive profile + explicit authorization)');
    }
  },
};
