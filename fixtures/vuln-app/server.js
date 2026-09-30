#!/usr/bin/env node
/**
 * ⚠️  DELIBERATELY VULNERABLE FIXTURE APPLICATION — TEST/DEMO DATA ONLY ⚠️
 *
 * This server exists exclusively as an authorized internal target for
 * Meridian's execution engines (integration tests + local demo). It is
 * started on loopback by the platform's seed/demo setup and is NEVER part
 * of the product attack surface. Every vulnerability below is real code
 * that the engines must genuinely detect from actual HTTP exchanges.
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function createFixtureApp() {
  let sessionCounter = 1000;
  const sessions = new Map(); // sequential session id → user
  // VULNERABLE (fixture): default credentials (root/root) and a blank-password service account
  const users = {
    admin: { password: 'admin123!A', role: 'admin', profile: { name: 'Administrator', email: 'admin@fixture.local' } },
    alice: { password: 'alice123!A', role: 'user', profile: { name: 'Alice Example', email: 'alice@fixture.local' } },
    root: { password: 'root', role: 'admin', profile: { name: 'Root', email: 'root@fixture.local' } },
    service: { password: '', role: 'service', profile: { name: 'Service Account', email: 'service@fixture.local' } },
  };
  // VULNERABLE (fixture): any login upgrades the whole previously-issued session family
  // (pre-authentication tokens silently gain authenticated state — session puzzling)
  let familyHighWater = 0;
  const profiles = { 1: { user: 'admin', name: 'Administrator', email: 'admin@fixture.local' }, 2: { user: 'alice', name: 'Alice Example', email: 'alice@fixture.local' }, 3: { user: 'bob', name: 'Bob Example', email: 'bob@fixture.local' } };
  const comments = [];
  const uploads = new Map();
  const database = { products: ['Laptop', 'Keyboard', 'Monitor', 'USB Hub'] }; // "backing store" for the SQLi-vulnerable search

  const BANNER = '<!-- FIXTURE: deliberately vulnerable application for authorized testing only -->';

  const home = (sessUser) => `<!DOCTYPE html>
<html lang="en"><head><title>Meridian Fixture Store — demo target</title><meta name="generator" content="FixtureCMS 2.3.1"><script src="https://cdn.example.com/jquery.min.js"></script>
<link rel="stylesheet" href="http://cdn.example-assets.invalid/style.css">
<script src="/js/app.js"></script>
<script src="https://cdn.thirdparty.invalid/lib.js"></script>
</head>
<body>
<header><nav><a href="/">Home</a> <a href="/search?q=laptop">Search</a> ${sessUser ? `<strong>Welcome, ${sessUser}</strong> <a href="/logout">Logout</a> <a href="/profile?id=1">My profile</a>` : '<a href="/login">Login</a>'} <a href="/comment">Feedback</a> <a href="/checkout">Checkout</a> <a href="/tools">Tools</a> <a href="/account">Account</a> <a href="/deals">Deals</a> <a href="/ping?host=127.0.0.1">Network tool</a> <a href="/error">Status</a></nav></header>
${BANNER}
<!-- left-over integration credentials: api_key = "AKIAIOSFODNN7EXAMPLE99" -->
<script>document.write(location.hash); if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script>
<h1>Fixture Store</h1>
<h3>Products (deliberately skipped h2)</h3>
<ul><li><a href="/search?q=laptop">Laptop</a></li><li><a href="/search?q=keyboard">Keyboard</a></li><li><a href="/profile?id=1&sid=1005">Laptop deal for signed-in users</a></li><li><a href="/Old_Deals.aspx?sort=price&dir=desc">Last season's deals</a></li><li><a href="/products/gone">Discontinued product</a></li><li><a href="http://fixture.local/tools">click here</a> for site tools</li></ul>
<img src="/logo.png" width="120" height="40">
<form action="/search" method="get"><input type="text" name="q" placeholder="Search products"><button type="submit">Go</button></form>
<form action="/goto" method="get"><input type="text" name="url" value="https://example.com/"><button type="submit">Go to URL</button></form>
<form action="/comment" method="post"><textarea name="comment" maxlength="200" placeholder="Your feedback"></textarea><input type="submit" value="Post"></form>
<form action="/login" method="post"><input name="username" id="u"><input type="password" name="password" id="p" autocomplete="on"><input type="checkbox" name="remember" value="1"> Remember me</form>
<p><a href="/sso/saml">SSO sign-in</a></p>
<footer><p>© Fixture — <a href="/forgot-password">Forgot password?</a> · <a href="mailto:admin@fixture.local">Contact the store admin</a></p></footer>
</body></html>`;

  const toolsPage = () => `<!DOCTYPE html><html lang="en"><head><title>Tools — Fixture</title><meta name="robots" content="noindex, follow"></head><body>
<h1>Site Tools</h1>
<form action="/include" method="get"><input name="url" placeholder="URL to include" value="https://example.com/robots.txt"><button>Include</button></form>
<form action="/xml" method="post"><textarea name="xml_document" placeholder="Paste XML document"></textarea><button>Parse XML</button></form>
<form action="/api/profile" method="post"><input name="name" value="Administrator" placeholder="Display name"><button>Save profile</button></form>
<form action="/file" method="get"><input name="name" value="notes.txt" placeholder="File name"><button>Open file</button></form>
<p><a href="/profile?id=2">View user profile</a> — <a href="/">Back to store</a></p>
<h2>Keyboard navigation</h2>
<input name="quick" tabindex="3" placeholder="Quick jump (positive tabindex fixture)">
<div aria-labelledby="missing-section-title">Section labelled by a non-existent id</div>
<h2>Price table</h2>
<table>
  <tr><td>Item</td><td>Price</td><td>Stock</td></tr>
  <tr><td>Laptop</td><td>999</td><td>4</td></tr>
  <tr><td>Keyboard</td><td>49</td><td>18</td></tr>
  <tr><td>Monitor</td><td>199</td><td>7</td></tr>
</table>
</body></html>`;

  const loginPage = () => `<!DOCTYPE html><html lang="en"><head><title>Login — Fixture</title></head><body>
<h1>Login</h1>
<form action="/login" method="post">
<input name="username" id="login-user"><input type="password" name="password" id="login-pass" maxlength="8" autocomplete="on">
<input type="checkbox" name="remember" value="1" id="remember-me"> <label for="remember-me">Remember me</label>
<button type="submit">Sign in</button></form>
<p><a href="/sso/saml">Sign in with SSO (SAML)</a></p>
</body></html>`;

  const commentPage = () => `<!DOCTYPE html><html lang="en"><head><title>Feedback — Fixture</title></head><body>
<h1>Feedback</h1>
${comments.map((c) => `<div class="comment"><b>${c.author}</b>: ${c.text}</div>`).join('\n')}
<form action="/comment" method="post"><input name="name" placeholder="Name"><textarea name="comment"></textarea><button>Post</button></form>
</body></html>`;

  const checkoutPage = () => `<!DOCTYPE html><html lang="en"><head><title>Checkout — Fixture</title></head><body>
<h1>Checkout</h1>
<form action="/pay" method="post">
<input name="cardnumber" autocomplete="cc-number" placeholder="Card number">
<input name="cvc" autocomplete="cc-csc"><input name="expiry">
<input name="amount" value="99.00"><input name="qty" value="1">
<button>Pay</button></form>
<iframe src="https://unknown-paywall.invalid/embed"></iframe>
<p>Test mode enabled — use sandbox card 4242 4242 4242 4242</p>
</body></html>`;

  async function searchHandler(query) {
    // VULNERABLE (fixture): every duplicate q value is processed and reflected (HTTP parameter pollution)
    const q = query.getAll('q').join(' ') || '';

    // VULNERABLE (fixture): unbounded recursive-descent "parser" — long input really exhausts the stack
    if (q.length > 8192) {
      const dive = (n) => (n === 0 ? 0 : dive(n - 1) + 1);
      dive(q.length * 8); // throws a real RangeError: Maximum call stack size exceeded
    }

    // VULNERABLE (fixture): input reaches the "database" query scheduler — SLEEP() delays it (blind SQLi)
    const sleepM = /SLEEP\s*\(\s*(\d+)\s*\)/i.exec(q);
    if (sleepM) await new Promise((r) => setTimeout(r, Math.min(Number(sleepM[1]), 5) * 1000));

    // VULNERABLE (fixture): server-side includes are processed — <!--#exec cmd="..."--> really executes
    let ssiOut = '';
    const ssiM = /<!--#exec cmd="([^"]{1,120})"-->/.exec(q);
    if (ssiM) {
      try { ssiOut = execSync(ssiM[1], { timeout: 2000, encoding: 'utf8', shell: '/bin/sh' }); }
      catch (e) { ssiOut = String((e && e.stderr) || e?.message || e); }
    }

    // VULNERABLE (fixture): user input is passed through the template engine — {{arithmetic}} is evaluated
    const rendered = q.replace(/\{\{\s*([0-9+\-*/(). ]{1,64})\s*\}\}/g, (_, expr) => String(new Function(`"use strict"; return (${expr});`)()));

    // vulnerable: value is concatenated into a "SQL query" — a quote breaks it
    if (/['"]/.test(q)) {
      const body = `<html><body><h1>Error</h1><pre>sqlite3.OperationalError: near "${q.slice(0, 40)}": syntax error
SQL: SELECT * FROM products WHERE name LIKE '%${q}%'</pre>${ssiOut ? `<pre>${ssiOut}</pre>` : ''}</body></html>`;
      return { status: 500, body };
    }
    const matches = database.products.filter((p) => p.toLowerCase().includes(q.toLowerCase()));
    return { status: 200, body: `<html><body><h1>Search: ${rendered}</h1><ul>${matches.map((m) => `<li>${m}</li>`).join('')}</ul><p>Reflected: ${rendered}</p>${ssiOut ? `<pre>SSI output: ${ssiOut}</pre>` : ''}</body></html>` };
  }

  async function handler(req, res) {
    const u = new URL(req.url, 'http://fixture.local');
    const send = (status, body, headers = {}) => res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers }).end(body);
    // VULNERABLE (fixture): technology/version banner disclosure
    res.setHeader('x-powered-by', 'FixtureCMS/2.3.1');

    // XST: TRACE echoes headers
    if (req.method === 'TRACE') {
      const echoed = Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n');
      return send(200, `TRACE / HTTP/1.1\r\n${echoed}`);
    }
    if (req.method === 'OPTIONS') {
      return send(204, '', { allow: 'GET, POST, HEAD, OPTIONS, TRACE, PUT, DELETE' });
    }

    // CORS reflect (misconfigured)
    if (req.headers.origin) res.setHeader('access-control-allow-origin', req.headers.origin);
    if (req.headers.origin) res.setHeader('access-control-allow-credentials', 'true');

    // a fresh sequential session cookie for every request (weak randomness fixture)
    if (!req.headers.cookie || !/sess=/.test(req.headers.cookie)) {
      sessionCounter += 1;
      res.setHeader('set-cookie', [`sess=${sessionCounter}; Path=/; Domain=.fixture.local`, 'tracker_sid=' + String(900000 + sessionCounter) + '; Path=/; HttpOnly']);
    }

    switch (u.pathname) {
      case '/': {
        const sessCookie = (req.headers.cookie || '').match(/sess=(\d+)/)?.[1];
        const sessUser = sessCookie ? sessions.get(`sess=${sessCookie}`)?.user : null;
        if (req.headers['user-agent'] && /curl/i.test(req.headers['user-agent'])) {
          return send(200, home(sessUser).replace('Fixture Store', 'Fixture Store (plain text variant)'));
        }
        return send(200, home(sessUser));
      }
      case '/robots.txt':
        return send(200, `User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /private\nSitemap: http://fixture.invalid/sitemap.xml`, { 'content-type': 'text/plain' });
      case '/sitemap.xml':
        return send(200, `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://fixture.local/</loc></url><url><loc>http://fixture.local/search</loc></url><url><loc>http://fixture.local/login</loc></url></urlset>`, { 'content-type': 'application/xml' });
      case '/js/app.js':
        return send(200, `// fixture client code — deliberately insecure crypto and storage patterns
var API_KEY = "sk_live_51FixtureDemoKeyA91xYz2abcdef0123456789";
var INTERNAL_TOKEN = "api_key: 'AKIAIOSFODNN7EXAMPLE'";
document.write(location.hash);
function handleMessage(e) { document.getElementById('out').innerHTML = e.data; } // no origin check
localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
window.addEventListener('message', handleMessage);
// VULNERABLE (fixture): weak/incorrect client-side cryptography
var passwordHash = md5(password + "s4lt"); // weak algorithm + short constant salt
var legacyCipher = CryptoJS.AES.encrypt(data, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }); // ECB mode
var session_token = Math.random().toString(36).slice(2); // token from a weak RNG
// VULNERABLE (fixture): unencrypted WebSocket + sensitive IndexedDB usage
var liveSocket = new WebSocket('ws://fixture.local/socket');
var authDb = indexedDB.open('auth-tokens', 1);
`, { 'content-type': 'application/javascript' });
      case '/.git/HEAD':
        return send(200, 'ref: refs/heads/main\n', { 'content-type': 'text/plain' });
      case '/.env':
        return send(200, 'APP_ENV=production\nDB_PASSWORD=Sup3rS3cretFixture!\nSTRIPE_SECRET_KEY=sk_live_51FixtureDemoKeyA91xYz2\n', { 'content-type': 'text/plain' });
      case '/backup.zip':
        return send(200, Buffer.from('504b0304140000000800' + '00'.repeat(64), 'hex').toString('latin1'), { 'content-type': 'application/zip' });
      case '/admin':
        return send(200, `<html><body><h1>Admin Dashboard</h1><p>Users list: admin, alice, bob</p><a href="/">Manage</a></body></html>`);
      case '/search': {
        const r = await searchHandler(u.searchParams);
        return send(r.status, r.body);
      }
      case '/login':
        if (req.method === 'GET') return send(200, loginPage());
        collectBody(req, (body) => {
          const params = new URLSearchParams(body.toString());
          const uname = params.get('username') || '';
          const pass = params.get('password') || '';
          const user = users[uname];
          if (!user) return send(200, `<html><body><p>No account found with that username.</p></body></html>`);
          if (user.password !== pass) return send(200, `<html><body><p>Incorrect password for ${uname}.</p></body></html>`);
          const sid = `sess=${++sessionCounter}`;
          sessions.set(sid, { user: uname, role: user.role });
          // VULNERABLE (fixture): login upgrades every previously-issued anonymous session
          // to authenticated state (session puzzling — pre-auth tokens gain privileges)
          familyHighWater = sessionCounter;
          for (let i = 1001; i <= familyHighWater; i++) sessions.set(`sess=${i}`, { user: uname, role: user.role });
          res.setHeader('set-cookie', `${sid}; Path=/; Domain=.fixture.local`);
          return send(200, `<html><body><h1>Welcome ${uname}</h1><a href="/logout">Logout</a> <a href="/profile?id=1">My profile</a></body></html>`);
        });
        return;
      case '/change-password':
        if (req.method === 'GET') return send(200, `<html><body><h1>Change password</h1><form action="/change-password" method="post"><input name="new_password" type="password"><input name="password_confirm" type="password"><button>Change</button></form></body></html>`);
        collectBody(req, (body) => {
          const params = new URLSearchParams(body.toString());
          // VULNERABLE (fixture): no current-password verification
          if (params.get('new_password')) return send(200, `<html><body><p>Password changed successfully.</p></body></html>`);
          return send(400, '<html><body><p>Missing new password.</p></body></html>');
        });
        return;
      case '/logout':
        return send(200, '<html><body><p>Logged out (session actually kept alive — fixture bug)</p></body></html>');
      case '/profile': {
        const cookie = (req.headers.cookie || '').match(/sess=(\d+)/)?.[1];
        // VULNERABLE (fixture): the session id is also accepted from the URL (session token in URL)
        const sidParam = u.searchParams.get('sid');
        const sessKey = (sidParam && /^\d+$/.test(sidParam) ? `sess=${sidParam}` : null) || (cookie ? `sess=${cookie}` : null);
        if (!sessKey || !sessions.has(sessKey)) return send(401, '<html><body><p>Auth required</p></body></html>');
        const id = u.searchParams.get('id') || '1';
        const record = profiles[id]; // IDOR: no ownership check
        if (!record) return send(404, '<html><body>Not found</body></html>');
        return send(200, `<html><body><h1>Profile</h1><p>user_id: ${id}</p><p>user_name: ${record.name}</p><p>email: ${record.email}</p></body></html>`);
      }
      case '/comment':
        if (req.method === 'GET') return send(200, commentPage());
        collectBody(req, (body) => {
          const params = new URLSearchParams(body.toString());
          comments.push({ author: params.get('name') || 'anonymous', text: params.get('comment') || '' });
          return send(200, commentPage()); // rendered unescaped → stored XSS
        });
        return;
      case '/redirect': {
        const url = u.searchParams.get('url');
        if (url) return send(302, '', { location: url }); // open redirect
        return send(400, 'missing url');
      }
      case '/goto': {
        // VULNERABLE (fixture): open redirect through a GET form parameter; the Location header is built from raw input
        const url = u.searchParams.get('url');
        if (url) return send(302, '', { location: url });
        return send(400, 'missing url');
      }
      case '/include': {
        // VULNERABLE (fixture): remote file inclusion — the server really fetches the URL and surfaces fetch errors
        const url = u.searchParams.get('url') || u.searchParams.get('page');
        if (!url) return send(400, 'missing url');
        try {
          const r = await fetch(url, { signal: AbortSignal.timeout(4000) });
          const text = await r.text();
          return send(200, `<html><body><h1>Included resource</h1><pre>${text.slice(0, 500)}</pre></body></html>`);
        } catch (e) {
          // surface the underlying cause (e.g. getaddrinfo ENOTFOUND) like verbose file-loading errors do
          const detail = [e?.message, e?.cause?.message].filter(Boolean).join(': ');
          return send(200, `<html><body><h1>Include failed</h1><pre>${detail}</pre></body></html>`);
        }
      }
      case '/account': {
        // VULNERABLE (fixture): malformed session state is not handled — an unknown/garbage sid really throws (HTTP 500)
        const sid = (req.headers.cookie || '').match(/sid=([^;]*)/)?.[1];
        if (sid != null) {
          const sess = sessions.get(sid.trim());
          if (!sess) throw new Error(`Invalid session state: ${JSON.stringify(sid)}`);
          return send(200, `<html><body><h1>Account: ${sess.user}</h1><p>Role: ${sess.role}</p><a href="/logout">Logout</a></body></html>`);
        }
        return send(200, `<html><body><h1>Account</h1><p>Sign in to manage your account.</p><form action="/login" method="post"><input name="username" id="acct-user"><input type="password" name="password"><button>Sign in</button></form></body></html>`);
      }
      case '/api/profile': {
        // VULNERABLE (fixture): mass assignment — every submitted field is persisted with no allowlist
        collectBody(req, (body) => {
          let data = {};
          try { data = JSON.parse(body.toString() || '{}'); } catch { return send(400, 'invalid json'); }
          const current = profiles[1] || { user: 'admin' };
          Object.assign(current, data);
          profiles[1] = current;
          return send(200, JSON.stringify({ ok: true, profile: current }), { 'content-type': 'application/json' });
        });
        return;
      }
      case '/Old_Deals.aspx': {
        // legacy URL kept for old bookmarks (uppercase .aspx path — URL-quality fixture)
        return send(200, `<!DOCTYPE html><html lang="en"><head><title>Archived deals — last season</title><meta name="description" content="Deals from last season, kept for old bookmarks and search results."></head><body><h1>Archived deals</h1><p>These offers have ended, but the page remains for historical links and bookmark compatibility with our previous store platform.</p></body></html>`);
      }
      case '/tools':
        return send(200, toolsPage());
      case '/forgot-password': {
        // VULNERABLE (fixture): user enumeration on the reset flow + reset token disclosed in the response
        if (req.method === 'GET') return send(200, `<!DOCTYPE html><html><head><title>Forgot password — Fixture</title></head><body><h1>Forgot password</h1><form action="/forgot-password" method="post"><input type="email" name="email" placeholder="Your account email"><button>Send reset link</button></form></body></html>`);
        collectBody(req, (body) => {
          const params = new URLSearchParams(body.toString());
          const email = params.get('email') || '';
          const known = Object.values(users).some((usr) => usr.profile?.email === email);
          if (known) {
            const token = `tok${Math.random().toString(36).slice(2, 14)}`;
            return send(200, `<html><body><p>Reset link sent. (Fixture debug output: <a href="/reset-password?token=${token}">/reset-password?token=${token}</a>)</p></body></html>`);
          }
          return send(200, '<html><body><p>No account found with that email address.</p></body></html>');
        });
        return;
      }
      case '/index.html.bak':
        // VULNERABLE (fixture): stale backup of the site source served as plain text
        return send(200, `<!-- backup of index.html (FixtureCMS 2.3.1) -->\n<html><head><title>Fixture Store</title></head><body><h1>Fixture Store</h1><?php include('config/db.php'); ?></body></html>\n`, { 'content-type': 'text/plain' });
      case '/debug/vars':
        // VULNERABLE (fixture): exposed debug/diagnostic endpoint
        return send(200, JSON.stringify({ debug: true, mem: process.memoryUsage().rss, uptime_s: Math.round(process.uptime()), pid: process.pid, env_keys: ['APP_ENV', 'NODE_OPTIONS', 'PATH'], vars_sample: 42 }, null, 2), { 'content-type': 'application/json' });
      case '/_debug':
        // VULNERABLE (fixture): directory listing enabled on the debug path
        return send(200, `<!DOCTYPE html><html><head><title>Index of /_debug</title></head><body><h1>Index of /_debug</h1><ul><li><a href="/">../</a></li><li><a href="/debug/vars">vars.json</a></li><li><a href="/backup.zip">backup.zip</a></li></ul></body></html>`);
      case '/sw.js':
        // VULNERABLE (fixture): service worker with a wide-scope fetch handler (no origin checks)
        return send(200, `self.addEventListener('fetch', (event) => { event.respondWith(fetch(event.request).then(r => r)); });\n`, { 'content-type': 'application/javascript' });
      case '/promo':
        // marketing redirect chain → /deals (long redirect chain fixture)
        return send(301, '', { location: '/promo2' });
      case '/promo2':
        return send(302, '', { location: '/deals' });
      case '/deals': {
        // VULNERABLE (fixture): heavy, slow, uncompressed page (performance anti-patterns)
        await new Promise((r) => setTimeout(r, 1200));
        const items = Array.from({ length: 34 }, (_, i) => `<li><img src="/logo.png" alt="" width="60" height="20"> Item ${i + 1}</li>`).join('');
        const filler = '<p>' + 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(9000) + '</p>';
        return send(200, `<!DOCTYPE html><html lang="en"><head><title>Deals — Fixture</title><script src="/js/app.js"></script><script src="/js/jquery.js"></script><script src="/js/util.js"></script><script src="/js/cart.js"></script></head><body><h1>Deals</h1><ul>${items}</ul>${filler}</body></html>`, { 'x-robots-tag': 'noindex, nofollow' });
      }
      case '/file': {
        const name = u.searchParams.get('name') || '';
        if (name.includes('../')) {
          return send(200, `root:x:0:0:root:/root:/bin/bash\ndaemon:/usr/sbin:/usr/sbin/nologin\n(path traversal of ${name})`);
        }
        return send(404, 'not found');
      }
      case '/ping': {
        // genuinely command-injectable (fixture): value concatenated into a shell command
        const { exec } = await import('node:child_process');
        const host = u.searchParams.get('host') || '127.0.0.1';
        exec(`ping -c 1 -W 1 ${host}`, { timeout: 3000 }, (err, stdout, stderr) => {
          send(200, `<html><body><h1>Ping ${host}</h1><pre>${stdout || stderr || err?.message || 'no output'}</pre></body></html>`);
        });
        return;
      }
      case '/xml':
        collectBody(req, (body) => {
          const xml = body.toString();
          // VULNERABLE (fixture): parser resolves SYSTEM entities (XXE) and returns the resolved document text
          const entRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"/g;
          const entities = {};
          let m;
          while ((m = entRe.exec(xml)) !== null) {
            try { entities[m[1]] = fs.readFileSync(m[2].replace(/^file:\/\//, ''), 'utf8').slice(0, 200); }
            catch { entities[m[1]] = '(unreadable)'; }
          }
          // resolve entity references in document text, then strip ALL markup (incl. the DTD) like a real parser
          const text = xml.replace(/&(\w+);/g, (full, name) => (name in entities ? entities[name] : full));
          const stripped = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
          return send(200, `<html><body><h1>Parsed document</h1><p>${stripped.slice(0, 300)}</p></body></html>`);
        });
        return;
      case '/upload':
        if (req.method === 'GET') return send(200, `<html><body><form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="file"><button>Upload</button></form></body></html>`);
        collectBody(req, (body, headers) => {
          const m = /name="file"; filename="([^"]*)"/.exec(body.toString('latin1'));
          const filename = m ? m[1] : `upload-${Date.now()}`;
          uploads.set(filename, body.slice(body.indexOf('\r\n\r\n') + 4, body.lastIndexOf('------')));
          return send(200, `<html><body>Uploaded: <a href="/uploads/${filename}">${filename}</a></body></html>`);
        });
        return;
      default: {
        const upM = /^\/uploads\/(.+)$/.exec(u.pathname);
        if (upM) {
          const data = uploads.get(upM[1]);
          if (data) {
            const ext = upM[1].split('.').pop();
            const types = { php: 'application/x-php', html: 'text/html', txt: 'text/plain', js: 'application/javascript' };
            return send(200, data, { 'content-type': types[ext] || 'application/octet-stream' });
          }
          return send(404, 'not found');
        }
        if (u.pathname === '/checkout') return send(200, checkoutPage());
        if (u.pathname === '/error') return send(500, '<html><body><pre>Fatal error: Uncaught Exception in /var/www/html/app.php on line 42\nStack trace:\n#0 /var/www/html/index.php(10): app->run()</pre></body></html>');
        if (u.pathname === '/logo.png') return send(200, Buffer.from('89504e470d0a1a0a', 'hex'), { 'content-type': 'image/png' });
        return send(404, '<html><body>Not found</body></html>');
      }
    }
    return send(404, 'not found');
  }
  return handler;
}

function collectBody(req, cb) {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => cb(Buffer.concat(chunks)));
}

export function startFixture({ httpPort = 8081, tlsPort = null } = {}) {
  const handler = createFixtureApp();
  const servers = [];
  return new Promise((resolve) => {
    // like a real framework, unhandled exceptions surface as HTTP 500 with a stack trace (error disclosure)
    const wrapped = async (req, res) => {
      try { await handler(req, res); }
      catch (e) {
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'text/html; charset=utf-8' });
          res.end(`<html><body><h1>Internal Server Error</h1><pre>${e?.stack || e}</pre></body></html>`);
        } else { try { res.end(); } catch { /* already sent */ } }
      }
    };
    const httpServer = http.createServer({ maxHeaderSize: 65536 }, wrapped);
    httpServer.listen(httpPort, '127.0.0.1', () => {
      servers.push(httpServer);
      if (tlsPort) {
        const keyPath = path.join(__dirname, 'certs', 'key.pem');
        const certPath = path.join(__dirname, 'certs', 'cert.pem');
        if (fs.existsSync(keyPath)) {
          const httpsMod = import('node:https').then(({ default: https }) => {
            const tlsServer = https.createServer({ maxHeaderSize: 65536, key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, wrapped);
            tlsServer.listen(tlsPort, '127.0.0.1', () => { servers.push(tlsServer); resolve(servers); });
          });
          return;
        }
      }
      resolve(servers);
    });
  });
}

// bin mode
if (process.argv[1] && process.argv[1].endsWith('vuln-app/server.js')) {
  const httpPort = Number(process.env.FIXTURE_HTTP_PORT || 8081);
  const tlsPort = Number(process.env.FIXTURE_TLS_PORT || 8082);
  startFixture({ httpPort, tlsPort }).then(() => {
    console.log(`[fixture] DELIBERATELY VULNERABLE test target on http://127.0.0.1:${httpPort} and https://127.0.0.1:${tlsPort} (loopback only)`);
  });
}
