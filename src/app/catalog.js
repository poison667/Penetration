/**
 * Service catalog — the marketplace backbone. Every service maps to a real
 * engine (execution implementation in src/engines/*). Credits are metered by
 * the job engine and recorded in the credit ledger.
 *
 * profiles:
 *  - passive    : only inspects fetched responses / metadata, no probes
 *  - safe       : adds benign differential probes (canary payloads, OPTIONS, TRACE)
 *  - standard   : safe + active injection probes with non-destructive payloads
 *  - intrusive  : adds state-changing/gated probes (upload bypass, time-based SQLi,
 *                 mass-assignment) — requires explicit authorization flag on the asset
 */
export const SERVICE_CATALOG = [
  // ---- Website technical auditing / SEO / Performance / Accessibility ----
  {
    key: 'web_audit', name: 'Full Website Technical Audit', category: 'audit',
    description: 'Composite audit: information gathering, technology fingerprinting, security header analysis, crawling, SEO, performance and accessibility. Runs as an orchestrated workflow of seven engines.',
    engine: 'composite', workflow: ['recon', 'techdetect', 'headers', 'crawl', 'seo', 'perf', 'a11y'],
    params: [{ key: 'max_pages', label: 'Max pages to crawl', type: 'int', default: 10, min: 1, max: 50 }],
    base_credits: 40, per_unit: { unit: 'page', credits: 1, cap: 60 }, profiles: ['safe'],
    outputs: 'Findings across recon/config/SEO/performance/accessibility with per-page evidence',
  },
  { key: 'recon', name: 'Information Gathering', category: 'audit', engine: 'recon',
    description: 'robots.txt, sitemap discovery, exposed files, entry points, third-party content, client-side code inventory, fingerprinting inputs.',
    params: [], base_credits: 10, profiles: ['passive', 'safe'],
    outputs: 'Recon findings + asset inventory' },
  { key: 'techdetect', name: 'Technology Detection', category: 'audit', engine: 'techdetect',
    description: 'Fingerprint servers, frameworks, CMS, JS libraries and third-party services from real responses.',
    params: [], base_credits: 5, profiles: ['passive'], outputs: 'Detected technology inventory (evidence-backed)' },
  { key: 'headers', name: 'HTTP Security Header Audit', category: 'audit', engine: 'headers',
    description: 'CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP, cookie flags, cache-control, banners.',
    params: [], base_credits: 5, profiles: ['passive'], outputs: 'Header findings with request/response evidence' },
  { key: 'crawl', name: 'Website Crawl & Spider', category: 'audit', engine: 'crawl',
    description: 'Breadth-first crawl within authorized scope, collecting links, forms, scripts, and page inventory.',
    params: [{ key: 'max_pages', label: 'Max pages', type: 'int', default: 10, min: 1, max: 50 }],
    base_credits: 8, per_unit: { unit: 'page', credits: 1, cap: 60 }, profiles: ['safe'], outputs: 'Sitemap of crawled pages, forms, parameters' },
  { key: 'seo', name: 'SEO Analysis', category: 'seo', engine: 'seo',
    description: 'Titles, meta descriptions, heading hierarchy, canonicals, robots directives, structured data, alt text, mobile viewport, Open Graph, internal link health.',
    params: [], base_credits: 10, profiles: ['passive'], outputs: 'SEO findings and page metrics' },
  { key: 'perf', name: 'Performance & Web Vitals Analysis', category: 'performance', engine: 'perf',
    description: 'Real network measurements: TTFB, transfer size/time, compression, redirect chains, resource weights, caching headers, HTTP/2. Full field-grade Core Web Vitals requires the browser-based provider adapter (documented limitation).',
    params: [], base_credits: 10, profiles: ['passive'], outputs: 'Measured timing metrics + findings' },
  { key: 'a11y', name: 'Accessibility Analysis', category: 'accessibility', engine: 'a11y',
    description: 'Automated static WCAG checks: image alt text, form labels, heading order, page lang/title, landmarks, link text, tabindex misuse, iframe titles, ARIA basics, table headers, skip links.',
    params: [], base_credits: 10, profiles: ['passive'], outputs: 'Accessibility findings per page' },

  // ---- Security (authorized testing only) ----
  { key: 'security_full', name: 'Full Authorized Security Assessment', category: 'security', engine: 'composite',
    description: 'Orchestrated workflow running all thirteen security engines within the asset\'s authorized scope and testing profile.',
    workflow: ['sec_config', 'sec_transmission', 'sec_auth', 'sec_session', 'sec_authz', 'sec_validation', 'sec_dos', 'sec_bizlogic', 'sec_crypto', 'sec_upload', 'sec_payment', 'sec_html5', 'recon'],
    params: [{ key: 'test_username', label: 'Test account username (optional)', type: 'string', optional: true },
             { key: 'test_password', label: 'Test account password (optional)', type: 'string', optional: true }],
    base_credits: 120, per_unit: { unit: 'page', credits: 2, cap: 120 }, profiles: ['safe', 'standard', 'intrusive'],
    outputs: 'Full findings set across all security categories' },
  { key: 'sec_config', name: 'Configuration Management Testing', category: 'security', engine: 'sec_config',
    description: 'Admin interfaces, backup/old files, HTTP methods, XST, extension handling, security policies, non-production data exposure, sensitive client-side data, banners, debug endpoints.',
    params: [{ key: 'max_pages', label: 'Max pages to crawl', type: 'int', default: 6, min: 1, max: 30 }], base_credits: 15, profiles: ['passive', 'safe'], outputs: 'Configuration findings' },
  { key: 'sec_transmission', name: 'Secure Transmission / TLS Analysis', category: 'security', engine: 'sec_transmission',
    description: 'TLS protocol versions, cipher strength, certificate validity/signature/CN-SAN, HTTPS enforcement, mixed content, credential transport, HSTS.',
    params: [], base_credits: 15, profiles: ['passive'], outputs: 'TLS findings with certificate evidence' },
  { key: 'sec_auth', name: 'Authentication Security Assessment', category: 'security', engine: 'sec_auth',
    description: 'User enumeration, bypass signals, brute-force/lockout assessment, password quality controls, remember-me, autocomplete, reset/change flows, CAPTCHA, MFA, logout, cache behavior, default credentials (gated), SSO inventory.',
    params: [{ key: 'test_username', label: 'Test username', type: 'string', optional: true },
             { key: 'test_password', label: 'Test password', type: 'string', optional: true }],
    base_credits: 20, profiles: ['safe', 'standard', 'intrusive'], outputs: 'Authentication findings' },
  { key: 'sec_session', name: 'Session Management Assessment', category: 'security', engine: 'sec_session',
    description: 'Token placement, cookie flags (Secure/HttpOnly/SameSite), scope, expiration, logout invalidation, simultaneous sessions, randomness/entropy estimation, rotation, CSRF protections, clickjacking.',
    params: [{ key: 'test_username', label: 'Test username', type: 'string', optional: true },
             { key: 'test_password', label: 'Test password', type: 'string', optional: true },
             { key: 'max_pages', label: 'Max pages to crawl', type: 'int', default: 6, min: 1, max: 30 }],
    base_credits: 15, profiles: ['safe', 'standard'], outputs: 'Session findings + entropy measurements' },
  { key: 'sec_authz', name: 'Authorization Testing', category: 'security', engine: 'sec_authz',
    description: 'Path traversal, authorization bypass, vertical/horizontal privilege escalation (IDOR), missing object-level authorization. Credential-dependent tests are skipped and reported when no test account is provided.',
    params: [{ key: 'test_username', label: 'Test username', type: 'string', optional: true },
             { key: 'test_password', label: 'Test password', type: 'string', optional: true },
             { key: 'max_pages', label: 'Max pages to crawl', type: 'int', default: 6, min: 1, max: 30 }],
    base_credits: 20, profiles: ['safe', 'standard'], outputs: 'Authorization findings' },
  { key: 'sec_validation', name: 'Data & Input Validation Testing', category: 'security', engine: 'sec_validation',
    description: 'XSS (reflected/stored/DOM), HTML injection, SQL/LDAP/ORM/NoSQL injection, XXE, SSI, XPath, code/command injection, overflow, format string, HTTP splitting/smuggling, verb tampering, open redirects, LFI/RFI, HPP, mass assignment (gated), client/server validation differences.',
    params: [{ key: 'max_pages', label: 'Max pages to test', type: 'int', default: 5, min: 1, max: 20 }],
    base_credits: 30, per_unit: { unit: 'page', credits: 3, cap: 90 }, profiles: ['safe', 'standard', 'intrusive'], outputs: 'Injection/validation findings with request/response evidence' },
  { key: 'sec_dos', name: 'DoS Resilience Assessment (safe)', category: 'security', engine: 'sec_dos',
    description: 'Anti-automation controls, account-lockout resilience, SQL wildcard resource exhaustion timing, large-payload handling — strictly rate-limited, non-destructive probes.',
    params: [{ key: 'max_pages', label: 'Max pages to crawl', type: 'int', default: 6, min: 1, max: 30 }], base_credits: 15, profiles: ['safe', 'intrusive'], outputs: 'Resilience observations' },
  { key: 'sec_bizlogic', name: 'Business Logic Assessment (assisted)', category: 'security', engine: 'sec_bizlogic',
    description: 'Feature misuse surfaces, non-repudiation signals, trust relationships, data integrity controls, segregation of duties. Inventory + evidence collection with assisted analysis.',
    params: [], base_credits: 10, profiles: ['passive'], outputs: 'Logic-risk inventory with evidence' },
  { key: 'sec_crypto', name: 'Cryptography Assessment', category: 'security', engine: 'sec_crypto',
    description: 'Plaintext sensitive data, weak/incorrect algorithms, salting and randomness signals, cryptographic storage patterns, hardcoded secrets in client code.',
    params: [], base_credits: 15, profiles: ['passive', 'safe'], outputs: 'Cryptographic findings' },
  { key: 'sec_upload', name: 'File Upload Security Assessment', category: 'security', engine: 'sec_upload',
    description: 'Upload endpoint inventory; allowlist, size, frequency, content/extension consistency, filename sanitization, storage location and public accessibility. Active bypass probes only under the intrusive profile with explicit authorization.',
    params: [], base_credits: 15, profiles: ['passive', 'intrusive'], outputs: 'Upload findings' },
  { key: 'sec_payment', name: 'Payment / High-Risk Functionality Assessment', category: 'security', engine: 'sec_payment',
    description: 'Payment flow inventory, card-data handling surfaces (PCI scope), payment page TLS and script integrity, third-party iframe allowlists, debug/test payment modes. Passive, authorized scope only.',
    params: [], base_credits: 15, profiles: ['passive'], outputs: 'Payment-surface findings' },
  { key: 'sec_html5', name: 'HTML5 / Modern Web Security', category: 'security', engine: 'sec_html5',
    description: 'Web Messaging (postMessage origin validation), Web Storage/IndexedDB sensitive data, CORS, offline applications/service workers, WebSocket security.',
    params: [], base_credits: 12, profiles: ['passive', 'safe'], outputs: 'Modern-web findings' },

  // ---- Data ----
  { key: 'data_profile', name: 'Data Profiling', category: 'data', engine: 'data_profile',
    description: 'Column type inference, null/distinct counts, min/max/mean/median/stddev, top values, pattern detection.',
    params: [{ key: 'source_id', label: 'Data source', type: 'string' }], base_credits: 5, profiles: ['passive'], outputs: 'Profile report + column stats' },
  { key: 'data_cleanse', name: 'Data Cleansing', category: 'data', engine: 'data_cleanse',
    description: 'Trim, case normalization, regex replace, null handling, invalid-row filtering via a real rule pipeline.',
    params: [{ key: 'source_id', label: 'Data source', type: 'string' }, { key: 'rules', label: 'Cleansing rules (JSON)', type: 'json', optional: true }],
    base_credits: 5, profiles: ['passive'], outputs: 'Cleaned dataset + change log' },
  { key: 'data_dedup', name: 'Deduplication', category: 'data', engine: 'data_dedup',
    description: 'Exact, normalized and fuzzy (Levenshtein with blocking) duplicate detection and removal.',
    params: [{ key: 'source_id', label: 'Data source', type: 'string' }, { key: 'keys', label: 'Key columns (comma-sep)', type: 'string', optional: true }, { key: 'mode', label: 'Mode', type: 'enum', options: ['exact', 'normalized', 'fuzzy'], default: 'exact' }],
    base_credits: 5, profiles: ['passive'], outputs: 'Deduplicated dataset + duplicate clusters' },
  { key: 'data_transform', name: 'Transformation', category: 'data', engine: 'data_transform',
    description: 'Rename, cast, derive via safe expression evaluator, filter rows, sort, select columns.',
    params: [{ key: 'source_id', label: 'Data source', type: 'string' }, { key: 'steps', label: 'Transform steps (JSON)', type: 'json', optional: true }],
    base_credits: 5, profiles: ['passive'], outputs: 'Transformed dataset + lineage' },
  { key: 'data_anomaly', name: 'Anomaly Detection', category: 'data', engine: 'data_anomaly',
    description: 'Statistical anomaly detection: z-score, modified z-score (MAD), IQR fences per numeric column.',
    params: [{ key: 'source_id', label: 'Data source', type: 'string' }], base_credits: 5, profiles: ['passive'], outputs: 'Row-level anomaly scores + column summaries' },

  // ---- Document intelligence ----
  { key: 'doc_extract', name: 'Document Text Extraction', category: 'documents', engine: 'doc_extract',
    description: 'Text-layer extraction for TXT/MD/CSV/JSON/HTML/PDF; OCR via provider adapter when available.',
    params: [{ key: 'document_id', label: 'Document ID', type: 'string' }], base_credits: 5, profiles: ['passive'], outputs: 'Extracted text + metadata + SHA-256' },
  { key: 'doc_compare', name: 'Document Comparison', category: 'documents', engine: 'doc_compare',
    description: 'Line-level LCS diff and word-level statistics between two documents.',
    params: [{ key: 'doc_a', label: 'Document A', type: 'string' }, { key: 'doc_b', label: 'Document B', type: 'string' }],
    base_credits: 5, profiles: ['passive'], outputs: 'Structured diff report' },

  // ---- AI ----
  { key: 'kb_build', name: 'Knowledge Base Build (RAG index)', category: 'ai', engine: 'kb_build',
    description: 'Chunks selected documents and builds a BM25 retrieval index for grounded Q&A.',
    params: [{ key: 'name', label: 'Knowledge base name', type: 'string' }, { key: 'document_ids', label: 'Document IDs (comma-sep)', type: 'string' }],
    base_credits: 8, profiles: ['passive'], outputs: 'Indexed knowledge base' },
  { key: 'ai_readiness', name: 'AI Readiness Assessment', category: 'ai', engine: 'ai_readiness',
    description: 'Scores data availability, quality, security posture, monitoring and automation coverage from real platform data — every score is backed by evidence.',
    params: [], base_credits: 10, profiles: ['passive'], outputs: 'Scored readiness report with evidence links' },
  { key: 'ai_analyze', name: 'AI-Assisted Finding Analysis', category: 'ai', engine: 'ai_analyze',
    description: 'Grounded explanation of a finding from its actual evidence; never fabricates measurements.',
    params: [{ key: 'finding_id', label: 'Finding ID', type: 'string' }], base_credits: 3, profiles: ['passive'], outputs: 'Grounded analysis with citations' },
];

export const PLANS = [
  { key: 'free', name: 'Free', price_cents: 0, credits_monthly: 200, features: { max_monitors: 3, max_documents: 20, data_rows_monthly: 50000 } },
  { key: 'pro', name: 'Pro', price_cents: 9900, credits_monthly: 5000, features: { max_monitors: 25, max_documents: 500, data_rows_monthly: 1000000 } },
  { key: 'business', name: 'Business', price_cents: 49900, credits_monthly: 25000, features: { max_monitors: 200, max_documents: 5000, data_rows_monthly: 10000000 } },
  { key: 'enterprise', name: 'Enterprise', price_cents: 0, custom: true, credits_monthly: 100000, features: { max_monitors: 0, max_documents: 0, data_rows_monthly: 0 } },
];

export function catalogMap() {
  const map = {};
  for (const s of SERVICE_CATALOG) map[s.key] = s;
  return map;
}
export function serviceByKey(key) {
  return SERVICE_CATALOG.find((s) => s.key === key) || null;
}
