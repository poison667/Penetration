/** Technology fingerprint signatures (matched against real fetched responses). */
export const TECH_SIGNATURES = [
  { tech: 'Nginx', kind: 'server', match: (h, _c, _m, _s) => /^nginx/i.test(h['server']?.[0] || '') },
  { tech: 'Apache HTTP Server', kind: 'server', match: (h) => /^apache/i.test(h['server']?.[0] || '') },
  { tech: 'Microsoft IIS', kind: 'server', match: (h) => /^microsoft-iis/i.test(h['server']?.[0] || '') },
  { tech: 'Cloudflare', kind: 'cdn', match: (h) => /cloudflare/i.test(h['server']?.[0] || '') || !!h['cf-ray'] },
  { tech: 'PHP', kind: 'language', match: (h) => /php/i.test(h['x-powered-by']?.[0] || '') || !!h['x-php'] },
  { tech: 'ASP.NET', kind: 'framework', match: (h) => /asp\.net/i.test(h['x-powered-by']?.[0] || '') || !!h['x-aspnet-version'] },
  { tech: 'Express (Node.js)', kind: 'framework', match: (h) => /express/i.test(h['x-powered-by']?.[0] || '') },
  { tech: 'WordPress', kind: 'cms', match: (h, _c, meta, s) => /wordpress/i.test(meta?.generator || '') || s.some((x) => /\/wp-(content|includes|json)\//.test(x.src || '')) },
  { tech: 'Drupal', kind: 'cms', match: (h, _c, meta, s) => /drupal/i.test(meta?.generator || '') || !!h['x-drupal-cache'] },
  { tech: 'Joomla', kind: 'cms', match: (h, _c, meta) => /joomla/i.test(meta?.generator || '') },
  { tech: 'Wix', kind: 'cms', match: (h, _c, meta) => /wix\.com/i.test(meta?.generator || '') },
  { tech: 'Squarespace', kind: 'cms', match: (h, _c, meta) => /squarespace/i.test(meta?.generator || '') },
  { tech: 'React', kind: 'js-library', match: (_h, body, _m, s) => /react(-dom)?([.@/-]|$)/i.test(body || '') || s.some((x) => /react(\.production)?(\.min)?\.js/i.test(x.src || '')) },
  { tech: 'Next.js', kind: 'framework', match: (_h, body, _m, s) => /__next|\/_next\//i.test(body || '') || s.some((x) => /\/_next\/static\//.test(x.src || '')) },
  { tech: 'Vue.js', kind: 'js-library', match: (_h, body, _m, s) => /vue(\.runtime)?(\.global)?(\.prod)?\.js|data-v-app/i.test(body || '') || s.some((x) => /vue/i.test(x.src || '')) },
  { tech: 'Angular', kind: 'framework', match: (_h, body, _m, s) => /ng-version|angular(\.min)?\.js/i.test(body || '') || s.some((x) => /angular/i.test(x.src || '')) },
  { tech: 'jQuery', kind: 'js-library', match: (_h, _b, _m, s) => s.some((x) => /jquery(-|\.)[0-9.]*(\.min)?\.js/i.test(x.src || '')) },
  { tech: 'Bootstrap', kind: 'css-framework', match: (_h, body, _m, s) => /bootstrap(\.min)?\.(css|js)/i.test(body || '') || s.some((x) => /bootstrap/i.test(x.src || '')) },
  { tech: 'Tailwind CSS', kind: 'css-framework', match: (_h, body) => /tailwind/i.test(body || '') },
  { tech: 'Google Analytics', kind: 'analytics', match: (_h, body, _m, s) => /google-analytics\.com|gtag\/js|googletagmanager/i.test(body || '') || s.some((x) => /googletagmanager/i.test(x.src || '')) },
  { tech: 'Google Fonts', kind: 'third-party', match: (_h, body) => /fonts\.googleapis\.com|fonts\.gstatic\.com/i.test(body || '') },
  { tech: 'Font Awesome', kind: 'third-party', match: (_h, body) => /font-?awesome/i.test(body || '') },
  { tech: 'PHP (session cookie)', kind: 'language', match: (_h, _b, _m, _s, cookies) => cookies.some((x) => /^PHPSESSID=/i.test(x)) },
  { tech: 'Java (session cookie)', kind: 'language', match: (_h, _b, _m, _s, cookies) => cookies.some((x) => /^JSESSIONID=/i.test(x)) },
  { tech: 'Laravel', kind: 'framework', match: (_h, _b, _m, _s, cookies) => cookies.some((x) => /^laravel_session=|^XSRF-TOKEN=/i.test(x)) },
  { tech: 'ASP.NET (session cookie)', kind: 'framework', match: (_h, _b, _m, _s, cookies) => cookies.some((x) => /^ASP\.NET_SessionId=/i.test(x)) },
  { tech: 'Varnish Cache', kind: 'cache', match: (h) => !!h['x-varnish'] },
  { tech: 'Nuxt', kind: 'framework', match: (_h, body) => /__nuxt|\/_nuxt\//i.test(body || '') },
  { tech: 'Svelte/SvelteKit', kind: 'framework', match: (_h, body) => /svelte-kit|__sveltekit/i.test(body || '') },
];

/** Curated safe-GET probes for configuration/recon checks (authorized scope only). */
export const COMMON_FILE_PROBES = [
  { path: '/.git/HEAD', expect: /ref: refs\//, kind: 'version-control' },
  { path: '/.env', expect: /[A-Z_]+=(?!.$).{3,}/, kind: 'environment-config' },
  { path: '/.DS_Store', expect: null, kind: 'os-metadata' },
  { path: '/server-status', expect: /Apache Server Status|Server Status/i, kind: 'server-status' },
  { path: '/backup.zip', expect: /^PK/, kind: 'backup-archive' },
  { path: '/backup.tar.gz', expect: /^\x1f\x8b/, kind: 'backup-archive' },
  { path: '/index.php.bak', expect: null, kind: 'backup-file' },
  { path: '/index.html.old', expect: null, kind: 'old-file' },
  { path: '/.svn/entries', expect: null, kind: 'version-control' },
  { path: '/composer.json', expect: /"require"/, kind: 'dependency-manifest' },
  { path: '/package.json', expect: /"dependencies"|"devDependencies"/, kind: 'dependency-manifest' },
  { path: '/web.config', expect: /<configuration/, kind: 'server-config' },
  { path: '/.htaccess', expect: null, kind: 'server-config' },
  { path: '/phpinfo.php', expect: /phpinfo\(\)|PHP Version/i, kind: 'diagnostic' },
  { path: '/debug', expect: /debug|stack trace|traceback/i, kind: 'debug' },
  { path: '/admin/config', expect: null, kind: 'admin' },
];

export const ADMIN_PATH_PROBES = ['/admin', '/admin/', '/wp-admin/', '/administrator/', '/manager/html', '/phpmyadmin/', '/cpanel', '/dashboard', '/console'];

export const EXTENSION_PROBES = [
  { path: '/index.bak', type: 'application/octet-stream' },
  { path: '/robots.txt.bak', type: 'text/plain' },
  { path: '/%2e%2e%2f', type: null },
];
