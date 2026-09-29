/** CSP directive parsing with weakness detection. */
export function parseCsp(cspRaw) {
  const issues = [];
  const directives = {};
  for (const part of String(cspRaw).split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1);
  }
  const srcList = (name) => directives[name] || [];
  const sources = [...srcList('default-src'), ...srcList('script-src')];
  if (sources.includes("'unsafe-inline'")) {
    issues.push({ fact: "script-src/default-src includes 'unsafe-inline'.", inference: 'Inline script injection is permitted, largely defeating XSS protections.' });
  }
  if (sources.includes("'unsafe-eval'")) {
    issues.push({ fact: "script-src/default-src includes 'unsafe-eval'.", inference: 'eval-style execution is permitted (DOM XSS and prototype pollution enablers).' });
  }
  if (sources.includes('*')) {
    issues.push({ fact: 'script-src/default-src allows * (any source).', inference: 'Script can load from any origin — no supply-chain restriction.' });
  }
  if (!directives['default-src'] && !directives['script-src']) {
    issues.push({ fact: 'No default-src or script-src directive.', inference: 'Script loading is unrestricted by policy defaults.' });
  }
  if (!directives['base-uri']) issues.push({ fact: 'No base-uri directive.', inference: '<base> injection can hijack relative URLs.' });
  if (!directives['object-src'] && !directives['default-src']?.length) issues.push({ fact: 'No object-src directive.', inference: 'Plugin content is not restricted.' });
  const frameAncestors = directives['frame-ancestors'];
  if (frameAncestors && frameAncestors.includes('*')) {
    issues.push({ fact: 'frame-ancestors allows *.', inference: 'Clickjacking not mitigated by CSP.' });
  }
  if (/http:\/\//i.test(String(cspRaw))) {
    issues.push({ fact: 'Policy permits plain http: sources.', inference: 'Active content could be loaded over unencrypted transport (MITM injection).' });
  }
  return issues;
}
