/** Domain taxonomy: severities, confidence, job lifecycle, roles/permissions, OWASP mapping. */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };
export const SEVERITY_META = {
  critical: { label: 'Critical', color: '#d13438' },
  high: { label: 'High', color: '#f7630c' },
  medium: { label: 'Medium', color: '#c19c00' },
  low: { label: 'Low', color: '#2d7d9a' },
  info: { label: 'Informational', color: '#605e5c' },
};

export const CONFIDENCES = ['confirmed', 'high', 'medium', 'low'];
export const CONFIDENCE_RANK = { confirmed: 4, high: 3, medium: 2, low: 1 };
export const FINDING_STATUSES = ['open', 'in_progress', 'remediated', 'false_positive', 'accepted_risk', 'retest_pending'];
export const VERIFICATION_STATES = ['not_retested', 'retest_pending', 'verified_fixed', 'still_present'];

export const FACT_KINDS = ['fact', 'inference', 'recommendation'];

/** Job lifecycle (Part 9 of specification). */
export const JOB_STATES = [
  'REQUESTED', 'VALIDATING', 'QUEUED', 'RUNNING', 'ANALYZING', 'QUALITY_CHECK',
  'COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED', 'RETRYING',
];
export const JOB_STATE_TRANSITIONS = {
  REQUESTED: ['VALIDATING', 'CANCELLED'],
  VALIDATING: ['QUEUED', 'FAILED', 'CANCELLED'],
  QUEUED: ['RUNNING', 'CANCELLED'],
  RUNNING: ['ANALYZING', 'FAILED', 'CANCELLED', 'RETRYING'],
  ANALYZING: ['QUALITY_CHECK', 'FAILED', 'PARTIALLY_COMPLETED'],
  QUALITY_CHECK: ['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED'],
  RETRYING: ['QUEUED', 'FAILED', 'CANCELLED'],
  FAILED: ['QUEUED'],
  CANCELLED: [],
  COMPLETED: [],
  PARTIALLY_COMPLETED: [],
};

/** Roles and the permission set each carries. */
export const ROLES = ['owner', 'admin', 'auditor', 'analyst', 'operator', 'viewer'];
export const PERMISSIONS = [
  'assets:read', 'assets:write',
  'requests:read', 'requests:write',
  'jobs:read', 'jobs:write',
  'findings:read', 'findings:write',
  'evidence:read',
  'reports:read', 'reports:write',
  'monitors:read', 'monitors:write',
  'data:read', 'data:write',
  'documents:read', 'documents:write',
  'ai:read', 'ai:write',
  'automation:read', 'automation:write',
  'billing:read', 'billing:write',
  'users:read', 'users:write',
  'support:read', 'support:write',
  'audit:read',
  'settings:read', 'settings:write',
  'admin:platform',
];
export const ROLE_PERMISSIONS = {
  owner: PERMISSIONS,
  admin: PERMISSIONS.filter((p) => p !== 'admin:platform'),
  auditor: ['assets:read', 'requests:read', 'requests:write', 'jobs:read', 'jobs:write', 'findings:read', 'findings:write', 'evidence:read', 'reports:read', 'reports:write', 'monitors:read', 'ai:read', 'ai:write', 'audit:read', 'support:read', 'support:write', 'documents:read', 'data:read', 'automation:read', 'billing:read', 'users:read', 'settings:read'],
  analyst: ['assets:read', 'requests:read', 'jobs:read', 'findings:read', 'evidence:read', 'reports:read', 'reports:write', 'monitors:read', 'data:read', 'data:write', 'documents:read', 'documents:write', 'ai:read', 'ai:write', 'automation:read', 'automation:write', 'support:read', 'support:write', 'billing:read', 'users:read', 'settings:read'],
  operator: ['assets:read', 'assets:write', 'requests:read', 'requests:write', 'jobs:read', 'jobs:write', 'findings:read', 'monitors:read', 'monitors:write', 'automation:read', 'automation:write', 'reports:read', 'reports:write', 'support:read', 'support:write', 'data:read', 'documents:read', 'billing:read', 'users:read', 'settings:read', 'ai:read'],
  viewer: ['assets:read', 'requests:read', 'jobs:read', 'findings:read', 'evidence:read', 'reports:read', 'monitors:read', 'data:read', 'documents:read', 'ai:read', 'automation:read', 'billing:read', 'support:read', 'users:read', 'settings:read'],
};

export function roleHas(role, permission) {
  const perms = ROLE_PERMISSIONS[role] || [];
  return perms.includes(permission);
}

export const OWASP_2021 = {
  A01: 'A01:2021 Broken Access Control',
  A02: 'A02:2021 Cryptographic Failures',
  A03: 'A03:2021 Injection',
  A04: 'A04:2021 Insecure Design',
  A05: 'A05:2021 Security Misconfiguration',
  A06: 'A06:2021 Vulnerable and Outdated Components',
  A07: 'A07:2021 Identification and Authentication Failures',
  A08: 'A08:2021 Software and Data Integrity Failures',
  A09: 'A09:2021 Security Logging and Monitoring Failures',
  A10: 'A10:2021 Server-Side Request Forgery (SSRF)',
};

export const SERVICE_CATEGORIES = {
  audit: 'Website technical auditing',
  seo: 'SEO analysis',
  performance: 'Performance & Core Web Vitals',
  accessibility: 'Accessibility',
  security: 'Authorized security assessment',
  monitoring: 'Monitoring',
  data: 'Data engineering',
  documents: 'Document intelligence',
  ai: 'AI services',
  reporting: 'Reporting',
};

export const ASSET_KINDS = ['web_host', 'api', 'domain', 'ip_range'];
export const AUTHZ_STATUS = ['declared', 'verified', 'expired', 'revoked'];

export const CREDIT_ENTRY_TYPES = ['grant', 'hold', 'commit', 'release', 'adjust'];
