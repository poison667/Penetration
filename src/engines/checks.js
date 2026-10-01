/**
 * Check registry — every individual test requirement from the specification
 * is registered here with: category, default severity, test kind
 * (passive | safe | active | intrusive | assisted), CWE and OWASP mapping,
 * remediation, and the specification reference it traces to (spec field).
 * Engines report findings against these check ids; the Requirements Coverage
 * Matrix is generated from this registry.
 */
export const CHECK_CATEGORIES = {
  recon: 'Information Gathering',
  config: 'Configuration Management',
  transmission: 'Secure Transmission / TLS',
  auth: 'Authentication',
  session: 'Session Management',
  authz: 'Authorization',
  val: 'Data & Input Validation',
  dos: 'DoS / Resilience',
  biz: 'Business Logic',
  crypt: 'Cryptography',
  upload: 'File Upload Security',
  payment: 'Payment / High-Risk Functionality',
  html5: 'HTML5 / Modern Web',
  seo: 'SEO',
  perf: 'Performance',
  a11y: 'Accessibility',
  manual: 'Manual Testing',
};

/** c(...) builds a check with defaults. */
const c = (id, cat, sev, kind, cwe, owasp, t, rem, spec) => ({ id, cat, sev, kind, cwe, owasp, t, rem, spec });

export const CHECKS = [
  // ================= INFORMATION GATHERING (SPEC Part 3: recon) =================
  c('REC-001', 'recon', 'info', 'passive', null, null, 'robots.txt analyzed', 'Review robots.txt for disallowed paths that reveal sensitive areas; do not rely on it for access control.', 'SEC/IG/robots'),
  c('REC-002', 'recon', 'info', 'passive', null, null, 'Sitemap discovered and processed', 'Keep sitemaps accurate; remove entries for internal-only resources.', 'SEC/IG/sitemap'),
  c('REC-003', 'recon', 'high', 'active', 538, 'A05', 'Exposed sensitive file', 'Remove the file from the web root and purge from caches/backups; rotate any exposed credentials.', 'SEC/IG/exposed-files'),
  c('REC-004', 'recon', 'info', 'passive', null, null, 'Technology fingerprint', 'Minimize version disclosure (banners, generators, asset paths).', 'SEC/IG/fingerprint'),
  c('REC-005', 'recon', 'info', 'passive', null, null, 'Third-party content inventory', 'Review third-party scripts/domains for necessity and integrity (SRI, allowlists).', 'SEC/IG/third-party'),
  c('REC-006', 'recon', 'info', 'passive', null, null, 'Entry points and forms inventory', 'Maintain an inventory of entry points; retire dead ones.', 'SEC/IG/entry-points'),
  c('REC-007', 'recon', 'info', 'passive', null, null, 'Client-side code inventory', 'Audit client JS for sensitive logic and data.', 'SEC/IG/client-code'),
  c('REC-008', 'recon', 'info', 'active', null, null, 'Network port exposure (authorized ports only)', 'Close unneeded ports; firewall management interfaces.', 'SEC/IG/ports'),
  c('REC-009', 'recon', 'info', 'passive', null, null, 'Hostname and DNS intelligence', 'Review DNS records for stale or over-exposed entries.', 'SEC/IG/hostnames'),
  c('REC-010', 'recon', 'info', 'passive', null, null, 'Search-engine exposure hints', 'Use meta robots/X-Robots-Tag deliberately; avoid exposing internal URLs.', 'SEC/IG/search-cache'),
  c('REC-011', 'recon', 'info', 'passive', null, null, 'User-Agent response differences', 'Serve consistent content across agents; avoid UA-based security decisions.', 'SEC/IG/user-agent'),
  c('REC-012', 'recon', 'info', 'passive', null, null, 'Application fingerprint and version/channel', 'Remove version strings; subscribe to security advisories for identified components.', 'SEC/IG/app-version'),
  c('REC-013', 'recon', 'info', 'passive', null, null, 'Related applications and hostnames detected', 'Ensure related apps share security standards and scope boundaries.', 'SEC/IG/related-apps'),

  // ================= CONFIGURATION MANAGEMENT =================
  c('CFG-001', 'config', 'high', 'active', 284, 'A05', 'Administrative interface exposed', 'Restrict admin interfaces by network/VPN, add authentication and rate limiting.', 'SEC/CM/admin-urls'),
  c('CFG-002', 'config', 'high', 'active', 538, 'A05', 'Backup/old/unreferenced file exposed', 'Delete stale backups and old files from web roots; block common backup extensions.', 'SEC/CM/backup-files'),
  c('CFG-003', 'config', 'medium', 'safe', null, 'A05', 'Permissive HTTP methods allowed', 'Restrict to required methods (GET/POST/HEAD); reject others with 405.', 'SEC/CM/http-methods'),
  c('CFG-004', 'config', 'medium', 'safe', 841, 'A05', 'Cross-Site Tracing (TRACE) enabled', 'Disable the TRACE method at the server.', 'SEC/CM/xst'),
  c('CFG-005', 'config', 'low', 'safe', 436, 'A05', 'Extension handling inconsistency', 'Serve files with correct content types; block ambiguous extensions (.bak, .old, ~).', 'SEC/CM/extension-handling'),
  c('CFG-006', 'config', 'medium', 'passive', 693, 'A05', 'Content-Security-Policy missing or weak', 'Deploy a strict CSP (default-src, script-src without unsafe-inline/eval, base-uri, frame-ancestors, object-src).', 'SEC/CM/csp'),
  c('CFG-007', 'config', 'medium', 'passive', 1021, 'A05', 'Clickjacking protection missing', 'Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.', 'SEC/CM/xfo'),
  c('CFG-008', 'config', 'medium', 'passive', 319, 'A05', 'Strict-Transport-Security missing or weak', 'Send HSTS with max-age ≥ 15768000 once HTTPS is stable.', 'SEC/CM/hsts'),
  c('CFG-009', 'config', 'low', 'passive', null, 'A05', 'X-Content-Type-Options missing', 'Add X-Content-Type-Options: nosniff.', 'SEC/CM/security-policies'),
  c('CFG-010', 'config', 'low', 'passive', null, 'A05', 'Referrer-Policy missing', 'Add a restrictive Referrer-Policy (strict-origin-when-cross-origin or stricter).', 'SEC/CM/security-policies'),
  c('CFG-011', 'config', 'info', 'passive', null, 'A05', 'Permissions-Policy missing', 'Declare a Permissions-Policy restricting powerful browser features.', 'SEC/CM/security-policies'),
  c('CFG-012', 'config', 'low', 'passive', null, 'A05', 'Cross-origin isolation headers missing', 'Add COOP/COEP as appropriate for the application threat model.', 'SEC/CM/security-policies'),
  c('CFG-013', 'config', 'high', 'passive', 489, 'A05', 'Non-production data / stack traces exposed', 'Disable debug output in production; sanitize error pages.', 'SEC/CM/non-prod-data'),
  c('CFG-014', 'config', 'high', 'passive', 312, 'A02', 'Sensitive data in client-side HTML', 'Remove sensitive tokens/data from HTML; move to server-side session state.', 'SEC/CM/sensitive-client-data'),
  c('CFG-015', 'config', 'info', 'passive', 200, 'A06', 'Server banner/version disclosure', 'Suppress server version banners.', 'SEC/CM/banners'),
  c('CFG-016', 'config', 'medium', 'active', 489, 'A05', 'Debug endpoint exposed', 'Remove or protect diagnostic endpoints in production.', 'SEC/CM/debug-endpoints'),
  c('CFG-017', 'config', 'medium', 'safe', 548, 'A05', 'Directory listing enabled', 'Disable autoindex; provide an index document.', 'SEC/CM/dir-listing'),

  // ================= SECURE TRANSMISSION / TLS =================
  c('TLS-001', 'transmission', 'high', 'passive', 326, 'A02', 'Outdated TLS protocol version accepted', 'Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).', 'SEC/ST/tls-versions'),
  c('TLS-002', 'transmission', 'high', 'passive', 327, 'A02', 'Weak cipher suite negotiated', 'Use modern AEAD cipher suites; disable NULL/EXPORT/RC4/3DES.', 'SEC/ST/algorithms'),
  c('TLS-003', 'transmission', 'high', 'passive', 298, 'A02', 'Certificate expired or expiring soon', 'Renew certificates and monitor expiry (built-in TLS monitor available).', 'SEC/ST/cert-validity'),
  c('TLS-004', 'transmission', 'high', 'passive', 347, 'A02', 'Weak certificate signature algorithm', 'Use SHA-256 or stronger certificate signatures.', 'SEC/ST/cert-signature'),
  c('TLS-005', 'transmission', 'high', 'passive', 297, 'A02', 'Certificate hostname mismatch (CN/SAN)', 'Issue a certificate valid for all served hostnames.', 'SEC/ST/cn-san'),
  c('TLS-006', 'transmission', 'medium', 'passive', 295, 'A02', 'Certificate trust problem (self-signed/incomplete chain)', 'Serve a complete chain from a trusted CA.', 'SEC/ST/cert-trust'),
  c('TLS-007', 'transmission', 'high', 'safe', 319, 'A02', 'HTTPS not enforced', 'Redirect all HTTP traffic to HTTPS and set HSTS.', 'SEC/ST/https-enforcement'),
  c('TLS-008', 'transmission', 'medium', 'passive', 311, 'A02', 'Mixed content on HTTPS page', 'Load all subresources over HTTPS; add upgrade-insecure-requests.', 'SEC/ST/mixed-content'),
  c('TLS-009', 'transmission', 'high', 'passive', 319, 'A02', 'Credentials submitted over unencrypted transport', 'Serve authentication forms only over HTTPS.', 'SEC/ST/credential-transport'),

  // ================= AUTHENTICATION =================
  c('ATH-001', 'auth', 'medium', 'active', 204, 'A07', 'Username enumeration on login', 'Return identical messages/timing for valid and invalid usernames.', 'SEC/AT/user-enumeration'),
  c('ATH-002', 'auth', 'medium', 'active', 204, 'A07', 'Username enumeration on password reset', 'Do not reveal account existence in reset responses.', 'SEC/AT/user-enumeration-reset'),
  c('ATH-003', 'auth', 'high', 'active', 287, 'A07', 'Authentication bypass signal detected', 'Investigate and fix the bypass path; enforce server-side checks.', 'SEC/AT/auth-bypass'),
  c('ATH-004', 'auth', 'medium', 'active', 307, 'A07', 'No brute-force/lockout protection observed', 'Implement progressive throttling/lockout and monitoring.', 'SEC/AT/brute-force'),
  c('ATH-005', 'auth', 'low', 'passive', 521, 'A07', 'Password quality controls weak or absent', 'Enforce length ≥ 10 with composition checks server-side.', 'SEC/AT/password-quality'),
  c('ATH-006', 'auth', 'medium', 'passive', 522, 'A07', 'Insecure remember-me implementation', 'Use random server-side tokens with rotation and expiry.', 'SEC/AT/remember-me'),
  c('ATH-007', 'auth', 'low', 'passive', 525, 'A07', 'Autocomplete enabled on sensitive fields', 'Set autocomplete="new-password"/"off" on sensitive inputs.', 'SEC/AT/autocomplete'),
  c('ATH-008', 'auth', 'high', 'active', 640, 'A07', 'Password reset token exposed in URL', 'Deliver tokens out-of-band; use POST bodies and single-use short-lived tokens.', 'SEC/AT/password-reset'),
  c('ATH-009', 'auth', 'medium', 'assisted', 620, 'A07', 'Password change lacks re-authentication', 'Require current password verification on change.', 'SEC/AT/password-change'),
  c('ATH-010', 'auth', 'info', 'passive', 807, 'A07', 'No CAPTCHA/anti-automation on sensitive forms', 'Add CAPTCHA or equivalent anti-automation to login/reset.', 'SEC/AT/captcha'),
  c('ATH-011', 'auth', 'info', 'passive', 308, 'A07', 'No MFA observed on authentication', 'Offer MFA (TOTP/WebAuthn) to reduce credential risk.', 'SEC/AT/mfa'),
  c('ATH-012', 'auth', 'high', 'active', 613, 'A07', 'Session not invalidated on logout', 'Destroy server-side session state on logout.', 'SEC/AT/logout'),
  c('ATH-013', 'auth', 'low', 'passive', 525, 'A07', 'Authentication pages cacheable', 'Send Cache-Control: no-store on authenticated/auth pages.', 'SEC/AT/cache'),
  c('ATH-014', 'auth', 'high', 'intrusive', 798, 'A07', 'Default credentials accepted', 'Remove default accounts; force first-login password change.', 'SEC/AT/default-credentials'),
  c('ATH-015', 'auth', 'info', 'assisted', 778, 'A09', 'Authentication history/notifications not observed', 'Provide login history and alerts for new devices/locations.', 'SEC/AT/auth-history'),
  c('ATH-016', 'auth', 'info', 'assisted', null, 'A07', 'SSO consistency not established', 'Align session lifetimes and logout propagation across SSO-integrated apps.', 'SEC/AT/sso'),

  // ================= SESSION MANAGEMENT =================
  c('SES-001', 'session', 'high', 'passive', 598, 'A07', 'Session token in URL', 'Move session identifiers to Secure/HttpOnly cookies.', 'SEC/SM/url-tokens'),
  c('SES-002', 'session', 'high', 'passive', 614, 'A02', 'Session cookie without Secure flag', 'Set the Secure attribute on all session cookies.', 'SEC/SM/secure-flag'),
  c('SES-003', 'session', 'high', 'passive', 1004, 'A07', 'Session cookie without HttpOnly', 'Set HttpOnly on session cookies.', 'SEC/SM/httponly'),
  c('SES-004', 'session', 'medium', 'passive', 1275, 'A07', 'Session cookie without SameSite', 'Set SameSite=Lax/Strict as appropriate.', 'SEC/SM/samesite'),
  c('SES-005', 'session', 'low', 'passive', null, 'A05', 'Overly broad cookie scope', 'Scope cookies to the minimal path/domain.', 'SEC/SM/scope'),
  c('SES-006', 'session', 'medium', 'passive', 613, 'A07', 'Session cookie lacks expiration', 'Set a finite Max-Age/Expires.', 'SEC/SM/expiration'),
  c('SES-007', 'session', 'low', 'assisted', 613, 'A07', 'Idle timeout not observed', 'Implement idle timeout appropriate to risk (e.g. 30 min).', 'SEC/SM/timeout'),
  c('SES-008', 'session', 'high', 'active', 613, 'A07', 'Session survives logout', 'Invalidate sessions server-side at logout.', 'SEC/SM/logout-invalidation'),
  c('SES-009', 'session', 'medium', 'assisted', 613, 'A07', 'Unbounded simultaneous sessions', 'Consider limiting concurrent sessions per account.', 'SEC/SM/simultaneous'),
  c('SES-010', 'session', 'medium', 'active', 330, 'A07', 'Session token entropy insufficient', 'Use ≥ 128-bit random tokens from a CSPRNG.', 'SEC/SM/randomness'),
  c('SES-011', 'session', 'high', 'active', 384, 'A07', 'Session not rotated on authentication', 'Regenerate session ids at privilege changes (login).', 'SEC/SM/rotation'),
  c('SES-012', 'session', 'low', 'assisted', 488, 'A04', 'Session puzzling risk (multi-stage state reuse)', 'Use distinct session variables per authentication stage.', 'SEC/SM/puzzling'),
  c('SES-013', 'session', 'medium', 'passive', 352, 'A01', 'CSRF protection not observed on state-changing forms', 'Add per-session CSRF tokens and verify on POST.', 'SEC/SM/csrf'),
  c('SES-014', 'session', 'medium', 'passive', 1021, 'A05', 'Clickjacking exposure (missing framing defenses)', 'Deny framing via X-Frame-Options/CSP frame-ancestors.', 'SEC/SM/clickjacking'),

  // ================= AUTHORIZATION =================
  c('AUT-001', 'authz', 'high', 'active', 22, 'A01', 'Path traversal possible', 'Canonicalize paths; restrict file access to an allowlist root.', 'SEC/AZ/path-traversal'),
  c('AUT-002', 'authz', 'high', 'active', 862, 'A01', 'Authorization bypass on protected resource', 'Enforce authorization server-side on every request.', 'SEC/AZ/bypass'),
  c('AUT-003', 'authz', 'critical', 'active', 269, 'A01', 'Vertical privilege escalation', 'Verify role checks server-side for every privileged action.', 'SEC/AZ/vertical'),
  c('AUT-004', 'authz', 'high', 'active', 639, 'A01', 'Horizontal access control flaw (IDOR)', 'Use indirect references and verify object ownership.', 'SEC/AZ/horizontal'),
  c('AUT-005', 'authz', 'high', 'active', 862, 'A01', 'Missing object-level authorization', 'Check authorization per object, not per endpoint.', 'SEC/AZ/missing'),
  c('AUT-006', 'authz', 'info', 'active', 425, 'A04', 'Direct object references in use', 'Prefer opaque, per-user indirect references.', 'SEC/AZ/dor'),

  // ================= DATA VALIDATION =================
  c('VAL-001', 'val', 'high', 'active', 79, 'A03', 'Reflected cross-site scripting', 'Contextual output encoding; CSP as a secondary control.', 'SEC/DV/reflected-xss'),
  c('VAL-002', 'val', 'critical', 'active', 79, 'A03', 'Stored cross-site scripting', 'Validate+encode on input and output; sanitize stored content.', 'SEC/DV/stored-xss'),
  c('VAL-003', 'val', 'high', 'passive', 79, 'A03', 'DOM-based XSS sink in client code', 'Use safe sinks (textContent); avoid injecting location/referrer into HTML.', 'SEC/DV/dom-xss'),
  c('VAL-004', 'val', 'medium', 'active', 80, 'A03', 'HTML injection', 'Encode user-supplied data before rendering as HTML.', 'SEC/DV/html-injection'),
  c('VAL-005', 'val', 'critical', 'active', 89, 'A03', 'SQL injection (error-based)', 'Use parameterized queries; disable verbose DB errors.', 'SEC/DV/sql-injection'),
  c('VAL-006', 'val', 'critical', 'intrusive', 89, 'A03', 'SQL injection (time-based)', 'Parameterize queries; block stacked/delay statements.', 'SEC/DV/sql-injection-time'),
  c('VAL-007', 'val', 'high', 'active', 90, 'A03', 'LDAP injection', 'Escape LDAP filters; use parameterized APIs.', 'SEC/DV/ldap-injection'),
  c('VAL-008', 'val', 'high', 'active', 943, 'A03', 'ORM injection', 'Use typed query builders; never interpolate user input into query strings.', 'SEC/DV/orm-injection'),
  c('VAL-009', 'val', 'high', 'active', 611, 'A03', 'XML external entity (XXE) injection', 'Disable DTDs and external entities in the XML parser.', 'SEC/DV/xxe'),
  c('VAL-010', 'val', 'high', 'active', 97, 'A03', 'Server-side includes injection', 'Disable SSI execution for user content.', 'SEC/DV/ssi'),
  c('VAL-011', 'val', 'high', 'active', 643, 'A03', 'XPath injection', 'Use parameterized XPath or precompiled expressions.', 'SEC/DV/xpath'),
  c('VAL-012', 'val', 'high', 'active', 93, 'A03', 'IMAP/SMTP injection detected', 'Validate/escape mail commands; reject CR/LF in mail parameters.', 'SEC/DV/imap-smtp'),
  c('VAL-013', 'val', 'critical', 'active', 94, 'A03', 'Code/expression injection', 'Never eval user input; use safe interpreters with allowlists.', 'SEC/DV/code-injection'),
  c('VAL-014', 'val', 'critical', 'active', 78, 'A03', 'OS command injection', 'Avoid shell calls with user input; use argument arrays; allowlist commands.', 'SEC/DV/command-injection'),
  c('VAL-015', 'val', 'medium', 'active', 120, 'A03', 'Buffer/length overflow handling issue', 'Enforce input length limits server-side.', 'SEC/DV/overflow'),
  c('VAL-016', 'val', 'medium', 'active', 134, 'A03', 'Format string handling issue', 'Reject unexpected % patterns in user input passed to format functions.', 'SEC/DV/format-string'),
  c('VAL-017', 'val', 'high', 'active', 113, 'A03', 'HTTP response splitting (CRLF injection)', 'Reject CR/LF in any data reflected into headers.', 'SEC/DV/http-splitting'),
  c('VAL-018', 'val', 'medium', 'safe', 444, 'A03', 'HTTP request smuggling exposure', 'Normalize header parsing (reject ambiguous Content-Length/Transfer-Encoding); upgrade proxies.', 'SEC/DV/http-smuggling'),
  c('VAL-019', 'val', 'medium', 'safe', 650, 'A03', 'HTTP verb tampering exposure', 'Enforce method-based authorization consistently (405 not 200).', 'SEC/DV/verb-tampering'),
  c('VAL-020', 'val', 'medium', 'active', 601, 'A01', 'Open redirect', 'Validate redirect targets against an allowlist; use relative URLs.', 'SEC/DV/open-redirect'),
  c('VAL-021', 'val', 'high', 'active', 98, 'A01', 'Local file inclusion', 'Map user input to an allowlist; never pass raw paths to file APIs.', 'SEC/DV/lfi'),
  c('VAL-022', 'val', 'high', 'active', 98, 'A03', 'Remote file inclusion signal', 'Prohibit URL/file wrappers in include paths.', 'SEC/DV/rfi'),
  c('VAL-023', 'val', 'medium', 'active', 602, 'A04', 'Client/server validation mismatch', 'Duplicate all client validation server-side.', 'SEC/DV/client-server-validation'),
  c('VAL-024', 'val', 'critical', 'active', 943, 'A03', 'NoSQL injection', 'Use typed query APIs; sanitize operators.', 'SEC/DV/nosql-injection'),
  c('VAL-025', 'val', 'medium', 'active', 235, 'A03', 'HTTP parameter pollution behavior', 'Reject or deterministically merge duplicate parameters.', 'SEC/DV/hpp'),
  c('VAL-026', 'val', 'high', 'intrusive', 915, 'A04', 'Mass assignment exposure', 'Allowlist bindable fields; never bind privileged attributes from requests.', 'SEC/DV/mass-assignment'),
  c('VAL-027', 'val', 'medium', 'active', 47, 'A04', 'Invalid/null session state mishandled', 'Handle missing/invalid state explicitly; fail closed.', 'SEC/DV/null-session'),
  c('VAL-028', 'val', 'info', 'safe', null, null, 'Parameter reflection map', 'Understand where input is reflected to inform context-aware encoding.', 'SEC/DV/reflection-map'),

  // ================= DOS / RESILIENCE =================
  c('DOS-001', 'dos', 'medium', 'safe', 770, 'A04', 'No anti-automation controls observed', 'Add rate limiting/CAPTCHA on automated-accessible endpoints.', 'SEC/DR/anti-automation'),
  c('DOS-002', 'dos', 'medium', 'safe', 645, 'A07', 'No account lockout under repeated failures', 'Implement lockout/throttling with safe unlock.', 'SEC/DR/lockout'),
  c('DOS-003', 'dos', 'low', 'safe', 400, 'A04', 'SQL wildcard search performance degradation', 'Cap wildcard search complexity; reject leading wildcards on large tables.', 'SEC/DR/sql-wildcard'),
  c('DOS-004', 'dos', 'low', 'intrusive', 400, 'A04', 'Large payload handling unbounded', 'Enforce request body limits.', 'SEC/DR/large-payload'),

  // ================= BUSINESS LOGIC =================
  c('BIZ-001', 'biz', 'info', 'assisted', 840, 'A04', 'Feature misuse surface inventoried', 'Review misuse cases per feature; add abuse controls.', 'SEC/BL/feature-misuse'),
  c('BIZ-002', 'biz', 'info', 'assisted', 778, 'A04', 'Non-repudiation controls not observed', 'Log security-relevant actions with actor, time and integrity protection.', 'SEC/BL/non-repudiation'),
  c('BIZ-003', 'biz', 'info', 'assisted', null, 'A08', 'Trust relationship inventory (third parties)', 'Verify integrity (SRI) and least privilege for third-party integrations.', 'SEC/BL/trust-relationships'),
  c('BIZ-004', 'biz', 'low', 'passive', 345, 'A08', 'Data integrity controls missing (no SRI)', 'Add subresource integrity attributes to third-party scripts.', 'SEC/BL/data-integrity'),
  c('BIZ-005', 'biz', 'info', 'assisted', null, 'A04', 'Segregation of duties review', 'Separate initiation/approval/execution roles for sensitive operations.', 'SEC/BL/segregation'),

  // ================= CRYPTOGRAPHY =================
  c('CRP-001', 'crypt', 'high', 'passive', 312, 'A02', 'Sensitive data transmitted in plaintext', 'Enforce TLS for all sensitive flows.', 'SEC/CR/plaintext-data'),
  c('CRP-002', 'crypt', 'medium', 'passive', 327, 'A02', 'Weak algorithm usage detected', 'Replace MD5/SHA1/DES/RC4 with modern alternatives.', 'SEC/CR/weak-algorithms'),
  c('CRP-003', 'crypt', 'medium', 'passive', 327, 'A02', 'Incorrect algorithm usage detected', 'Use vetted constructions (AEAD, salted slow hashes for passwords).', 'SEC/CR/incorrect-algorithms'),
  c('CRP-004', 'crypt', 'medium', 'passive', 759, 'A02', 'Salting absent in hash usage', 'Salt all hashed values (per-item random salts).', 'SEC/CR/salting'),
  c('CRP-005', 'crypt', 'high', 'passive', 338, 'A02', 'Weak randomness in security tokens', 'Use cryptographically secure random generators for tokens.', 'SEC/CR/randomness'),
  c('CRP-006', 'crypt', 'high', 'passive', 922, 'A02', 'Sensitive token stored in Web Storage', 'Prefer HttpOnly cookies; never store bearer tokens in localStorage.', 'SEC/CR/crypto-storage'),
  c('CRP-007', 'crypt', 'critical', 'passive', 798, 'A02', 'Hardcoded secret in client code', 'Remove the secret; rotate it; proxy secret-dependent flows server-side.', 'SEC/CR/hardcoded-secrets'),

  // ================= FILE UPLOAD =================
  c('UPL-001', 'upload', 'high', 'active', 434, 'A04', 'Upload type allowlist not enforced', 'Validate extension + content type + magic bytes against a strict allowlist.', 'SEC/FU/type-allowlist'),
  c('UPL-002', 'upload', 'medium', 'active', 400, 'A04', 'Upload size limit not enforced', 'Cap upload sizes server-side.', 'SEC/FU/size-limits'),
  c('UPL-003', 'upload', 'low', 'active', 770, 'A04', 'Upload frequency/count limit not observed', 'Rate-limit uploads per user/session.', 'SEC/FU/frequency-limits'),
  c('UPL-004', 'upload', 'high', 'active', 434, 'A04', 'Content/extension consistency not validated', 'Verify actual content matches the declared type.', 'SEC/FU/content-consistency'),
  c('UPL-005', 'upload', 'info', 'assisted', 509, 'A08', 'No malware scanning integration observed', 'Scan uploads with an AV/ malware engine before storage.', 'SEC/FU/malware-av'),
  c('UPL-006', 'upload', 'medium', 'active', 78, 'A03', 'Filename not sanitized', 'Generate server-side filenames; never trust user filenames.', 'SEC/FU/filename-sanitization'),
  c('UPL-007', 'upload', 'high', 'active', 552, 'A05', 'Uploads stored in web root / publicly served', 'Store uploads outside the web root with controlled access.', 'SEC/FU/storage-location'),
  c('UPL-008', 'upload', 'medium', 'assisted', 434, 'A04', 'Upload host separation not observed', 'Serve user content from a separate origin/domain.', 'SEC/FU/host-separation'),
  c('UPL-009', 'upload', 'high', 'active', 306, 'A01', 'Upload endpoint accessible without authentication', 'Require authentication for upload endpoints.', 'SEC/FU/upload-authentication'),
  c('UPL-010', 'upload', 'high', 'active', 862, 'A01', 'Upload endpoint lacks authorization', 'Verify per-user quotas/permissions server-side.', 'SEC/FU/upload-authorization'),

  // ================= PAYMENT / HIGH RISK =================
  c('PAY-001', 'payment', 'info', 'passive', null, null, 'Payment flow inventory', 'Maintain a PCI-scoped inventory of payment flows.', 'SEC/PF/inventory'),
  c('PAY-002', 'payment', 'high', 'passive', 311, 'A02', 'Card-data handling surface on first-party page', 'Use tokenization (payment provider fields/iframe); never touch raw PAN on your origin.', 'SEC/PF/card-handling'),
  c('PAY-003', 'payment', 'high', 'passive', 319, 'A02', 'Payment page transport/integrity weaknesses', 'Serve payment pages over HTTPS with a strict CSP and SRI on scripts.', 'SEC/PF/payment-page'),
  c('PAY-004', 'payment', 'medium', 'passive', 1021, 'A05', 'Unrecognized payment iframe origin', 'Allowlist payment provider iframe origins via CSP frame-src.', 'SEC/PF/iframe-allowlist'),
  c('PAY-005', 'payment', 'high', 'passive', 489, 'A05', 'Debug/test payment mode exposed in production', 'Disable test payment modes and mock endpoints in production.', 'SEC/PF/debug-modes'),

  // ================= HTML5 / MODERN WEB =================
  c('H5-001', 'html5', 'medium', 'passive', 1021, 'A05', 'postMessage handler without origin validation', 'Validate event.origin in message handlers.', 'SEC/H5/web-messaging'),
  c('H5-002', 'html5', 'medium', 'passive', 922, 'A02', 'Sensitive data in Web Storage', 'Do not store secrets/tokens in localStorage/sessionStorage.', 'SEC/H5/web-storage'),
  c('H5-003', 'html5', 'medium', 'safe', 942, 'A05', 'Permissive CORS policy', 'Reflect only allowlisted origins; never ACAO:* with credentials.', 'SEC/H5/cors'),
  c('H5-004', 'html5', 'low', 'passive', null, 'A08', 'Service worker attack surface', 'Serve service workers from a controlled scope; review fetch handler.', 'SEC/H5/offline-apps'),
  c('H5-005', 'html5', 'medium', 'passive', null, 'A02', 'Unencrypted WebSocket (ws://) usage', 'Use wss:// and authenticate the opening handshake.', 'SEC/H5/websockets'),
  c('H5-006', 'html5', 'low', 'passive', 922, 'A02', 'Sensitive data in IndexedDB', 'Avoid storing sensitive data client-side; encrypt if unavoidable.', 'SEC/H5/indexeddb'),

  // ================= SEO =================
  c('SEO-001', 'seo', 'medium', 'passive', null, null, 'Missing or poor page title', 'Provide a unique, descriptive <title> (30–60 chars) per page.', 'SEO/title'),
  c('SEO-002', 'seo', 'low', 'passive', null, null, 'Missing meta description', 'Add a unique meta description (70–160 chars).', 'SEO/meta-description'),
  c('SEO-003', 'seo', 'low', 'passive', null, null, 'Heading structure issues', 'Use exactly one h1 and sequential heading levels.', 'SEO/headings'),
  c('SEO-004', 'seo', 'medium', 'passive', null, null, 'Images without alt text', 'Add descriptive alt attributes to all meaningful images.', 'SEO/alt-text'),
  c('SEO-005', 'seo', 'low', 'passive', null, null, 'Missing canonical link', 'Declare a canonical URL to prevent duplicate-content issues.', 'SEO/canonical'),
  c('SEO-006', 'seo', 'info', 'passive', null, null, 'Robots directives review', 'Verify meta robots/X-Robots-Tag match your indexing intent.', 'SEO/robots-meta'),
  c('SEO-007', 'seo', 'low', 'passive', null, null, 'Sitemap missing or not linked', 'Publish a sitemap.xml and reference it in robots.txt.', 'SEO/sitemap'),
  c('SEO-008', 'seo', 'low', 'passive', null, null, 'Structured data missing/invalid', 'Add valid JSON-LD structured data (organization, product, article).', 'SEO/structured-data'),
  c('SEO-009', 'seo', 'medium', 'passive', null, null, 'Mobile viewport not declared', 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.', 'SEO/viewport'),
  c('SEO-010', 'seo', 'low', 'passive', null, null, 'Missing language attribute', 'Declare lang on <html>.', 'SEO/lang'),
  c('SEO-011', 'seo', 'low', 'active', null, null, 'Broken internal links', 'Fix or remove broken internal links.', 'SEO/broken-links'),
  c('SEO-012', 'seo', 'info', 'passive', null, null, 'Open Graph / social meta incomplete', 'Add og:title, og:description and og:image.', 'SEO/open-graph'),
  c('SEO-013', 'seo', 'info', 'passive', null, null, 'URL quality issues', 'Prefer short, readable URLs with meaningful slugs and few parameters.', 'SEO/url-quality'),
  c('SEO-014', 'seo', 'info', 'passive', null, null, 'Thin content', 'Ensure primary content is substantive and server-rendered.', 'SEO/content-depth'),
  c('SEO-015', 'seo', 'medium', 'passive', null, null, 'HTTPS required for SEO', 'Serve all content over HTTPS with canonical https URLs.', 'SEO/https'),

  // ================= PERFORMANCE =================
  c('PRF-001', 'perf', 'medium', 'passive', null, null, 'Slow time-to-first-byte', 'Target < 800ms TTFB; add caching/CDN and optimize backend latency.', 'PERF/ttfb'),
  c('PRF-002', 'perf', 'low', 'passive', null, null, 'Large HTML document', 'Reduce initial HTML weight (< 500KB).', 'PERF/transfer-size'),
  c('PRF-003', 'perf', 'medium', 'passive', null, null, 'Compression not enabled', 'Enable gzip/brotli for text assets.', 'PERF/compression'),
  c('PRF-004', 'perf', 'low', 'passive', null, null, 'Long redirect chain', 'Minimize redirects to final destination.', 'PERF/redirects'),
  c('PRF-005', 'perf', 'low', 'passive', null, null, 'Heavy resource inventory', 'Optimize/lazy-load images and scripts; set budgets.', 'PERF/resources'),
  c('PRF-006', 'perf', 'medium', 'passive', null, null, 'Caching headers missing on static assets', 'Set long-lived Cache-Control with content hashing.', 'PERF/caching'),
  c('PRF-007', 'perf', 'low', 'passive', null, null, 'Render-blocking resources detected', 'Defer/async scripts; inline critical CSS.', 'PERF/render-blocking'),
  c('PRF-008', 'perf', 'info', 'passive', null, null, 'Protocol observations (HTTP/2, keep-alive)', 'Enable HTTP/2+ and keep-alive.', 'PERF/protocol'),
  c('PRF-009', 'perf', 'info', 'passive', null, null, 'Core Web Vitals provider status', 'Full field-grade CWV requires the browser-based measurement provider (adapter interface; see docs/LIMITATIONS.md).', 'PERF/cwv-adapter'),

  // ================= ACCESSIBILITY =================
  c('A11Y-001', 'a11y', 'medium', 'passive', null, null, 'Images missing alt text', 'Add alt attributes (empty alt for decorative images).', 'A11Y/img-alt'),
  c('A11Y-002', 'a11y', 'high', 'passive', null, null, 'Form inputs without labels', 'Associate every input with a <label>.', 'A11Y/labels'),
  c('A11Y-003', 'a11y', 'medium', 'passive', null, null, 'Heading order breaks hierarchy', 'Do not skip heading levels.', 'A11Y/heading-order'),
  c('A11Y-004', 'a11y', 'high', 'passive', null, null, 'Page language or title missing', 'Set <html lang> and a descriptive <title>.', 'A11Y/lang-title'),
  c('A11Y-005', 'a11y', 'low', 'passive', null, null, 'Landmark structure missing', 'Use semantic landmarks (header/nav/main/footer).', 'A11Y/landmarks'),
  c('A11Y-006', 'a11y', 'low', 'passive', null, null, 'Non-descriptive link text', 'Use meaningful link text (avoid "click here").', 'A11Y/link-text'),
  c('A11Y-007', 'a11y', 'medium', 'passive', null, null, 'Positive tabindex usage', 'Remove positive tabindex values; use DOM order.', 'A11Y/tabindex'),
  c('A11Y-008', 'a11y', 'medium', 'passive', null, null, 'iframe without title', 'Add a title attribute to iframes.', 'A11Y/iframe-title'),
  c('A11Y-009', 'a11y', 'low', 'passive', null, null, 'ARIA attribute issues', 'Fix invalid/duplicate ARIA attributes and roles.', 'A11Y/aria'),
  c('A11Y-010', 'a11y', 'low', 'passive', null, null, 'Table accessibility missing', 'Add <caption> and th scope attributes.', 'A11Y/tables'),
  c('A11Y-011', 'a11y', 'low', 'passive', null, null, 'Skip link missing', 'Provide a skip-to-content link.', 'A11Y/skip-link'),
  c('A11Y-012', 'a11y', 'info', 'passive', null, null, 'Color contrast requires manual verification', 'Verify ≥ 4.5:1 contrast for text (browser-based measurement provider; see docs/LIMITATIONS.md).', 'A11Y/contrast'),

  // ================= MANUAL TESTING (manual-work hub) =================
  // Manual findings: entered by a human tester through the manual hub
  // (direct entry or HAR/Burp/ZAP evidence import). kind = assisted:
  // a person performs the test; the platform records and reports it.
  c('MAN-001', 'manual', 'medium', 'assisted', null, null, 'Manually identified vulnerability', 'Remediate as described in the finding; verify the fix with a retest run.', 'MAN/hub/manual-vuln'),
  c('MAN-002', 'manual', 'medium', 'assisted', null, null, 'Manually identified business-logic issue', 'Remediate the workflow flaw as described; verify with a retest and a manual walkthrough.', 'MAN/hub/bizlogic'),
  c('MAN-003', 'manual', 'medium', 'assisted', null, null, 'Manually identified misconfiguration', 'Correct the configuration as described; verify with a retest run.', 'MAN/hub/config'),
  c('MAN-004', 'manual', 'info', 'assisted', null, null, 'Manual observation / note', 'Review the observation and decide on follow-up (promote to a finding if applicable).', 'MAN/hub/observation'),
];

export const CHECKS_BY_ID = Object.fromEntries(CHECKS.map((x) => [x.id, x]));
export function getCheck(id) {
  const c = CHECKS_BY_ID[id];
  if (!c) throw new Error(`unknown check id: ${id}`);
  return c;
}
export function checksByCategory(cat) { return CHECKS.filter((c) => c.cat === cat); }
