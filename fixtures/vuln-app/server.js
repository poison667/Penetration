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
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function createFixtureApp() {
  let sessionCounter = 1000;
  const sessions = new Map(); // sequential session id → user
  const users = { admin: { password: 'admin123!A', role: 'admin', profile: { name: 'Administrator', email: 'admin@fixture.local' } }, alice: { password: 'alice123!A', role: 'user', profile: { name: 'Alice Example', email: 'alice@fixture.local' } } };
  const profiles = { 1: { user: 'admin', name: 'Administrator', email: 'admin@fixture.local' }, 2: { user: 'alice', name: 'Alice Example', email: 'alice@fixture.local' }, 3: { user: 'bob', name: 'Bob Example', email: 'bob@fixture.local' } };
  const comments = [];
  const uploads = new Map();
  const database = { products: ['Laptop', 'Keyboard', 'Monitor', 'USB Hub'] }; // "backing store" for the SQLi-vulnerable search

  const BANNER = '<!-- FIXTURE: deliberately vulnerable application for authorized testing only -->';

  const home = () => `<!DOCTYPE html>
<html lang="en"><head><title>Meridian Fixture Store — demo target</title><meta name="generator" content="FixtureCMS 2.3.1"><script src="https://cdn.example.com/jquery.min.js"></script>
<link rel="stylesheet" href="http://cdn.example-assets.invalid/style.css">
<script src="/js/app.js"></script>
<script src="https://cdn.thirdparty.invalid/lib.js"></script>
</head>
<body>
<header><nav><a href="/">Home</a> <a href="/search?q=laptop">Search</a> <a href="/login">Login</a> <a href="/comment">Feedback</a> <a href="/checkout">Checkout</a> <a href="/ping?host=127.0.0.1">Network tool</a></nav></header>
${BANNER}
<h1>Fixture Store</h1>
<h3>Products (deliberately skipped h2)</h3>
<ul><li><a href="/search?q=laptop">Laptop</a></li><li><a href="/search?q=keyboard">Keyboard</a></li></ul>
<img src="/logo.png" width="120" height="40">
<form action="/search" method="get"><input type="text" name="q" placeholder="Search products"><button type="submit">Go</button></form>
<form action="/comment" method="post"><textarea name="comment" placeholder="Your feedback"></textarea><input type="submit" value="Post"></form>
<form action="/login" method="post"><input name="username" id="u"><input type="password" name="password" id="p" autocomplete="on"><input type="checkbox" name="remember" value="1"> Remember me</form>
<footer><p>© Fixture</p></footer>
</body></html>`;

  const loginPage = () => `<!DOCTYPE html><html lang="en"><head><title>Login — Fixture</title></head><body>
<h1>Login</h1>
<form action="/login" method="post">
<input name="username" id="login-user"><input type="password" name="password" id="login-pass" autocomplete="on">
<button type="submit">Sign in</button></form></body></html>`;

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

  function searchHandler(query) {
    const q = query.get('q') || '';
    // vulnerable: value is concatenated into a "SQL query" — a quote breaks it
    if (/['"]/.test(q)) {
      const body = `<html><body><h1>Error</h1><pre>sqlite3.OperationalError: near "${q.slice(0, 40)}": syntax error
SQL: SELECT * FROM products WHERE name LIKE '%${q}%'</pre></body></html>`;
      return { status: 500, body };
    }
    const matches = database.products.filter((p) => p.toLowerCase().includes(q.toLowerCase()));
    return { status: 200, body: `<html><body><h1>Search: ${q}</h1><ul>${matches.map((m) => `<li>${m}</li>`).join('')}</ul><p>Reflected: ${q}</p></body></html>` };
  }

  async function handler(req, res) {
    const u = new URL(req.url, 'http://fixture.local');
    const send = (status, body, headers = {}) => res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers }).end(body);

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
      res.setHeader('set-cookie', `sess=${sessionCounter}; Path=/; Domain=.fixture.local`);
    }

    switch (u.pathname) {
      case '/': {
        if (req.headers['user-agent'] && /curl/i.test(req.headers['user-agent'])) {
          return send(200, home().replace('Fixture Store', 'Fixture Store (plain text variant)'));
        }
        return send(200, home());
      }
      case '/robots.txt':
        return send(200, `User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /private\nSitemap: http://fixture.invalid/sitemap.xml`, { 'content-type': 'text/plain' });
      case '/sitemap.xml':
        return send(200, `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://fixture.local/</loc></url><url><loc>http://fixture.local/search</loc></url><url><loc>http://fixture.local/login</loc></url></urlset>`, { 'content-type': 'application/xml' });
      case '/js/app.js':
        return send(200, `// fixture client code
var API_KEY = "sk_live_51FixtureDemoKeyA91xYz2abcdef0123456789";
var INTERNAL_TOKEN = "api_key: 'AKIAIOSFODNN7EXAMPLE'";
document.write(location.hash);
function handleMessage(e) { document.getElementById('out').innerHTML = e.data; } // no origin check
localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
window.addEventListener('message', handleMessage);
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
        const r = searchHandler(u.searchParams);
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
        if (!cookie || !sessions.has(`sess=${cookie}`)) return send(401, '<html><body><p>Auth required</p></body></html>');
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
          // vulnerable parser: expands internal + SYSTEM entities
          let out = xml;
          const entRe = /<!ENTITY (\w+) SYSTEM "([^"]+)">/g;
          let m; const expanded = {};
          while ((m = entRe.exec(xml)) !== null) {
            try { expanded[m[1]] = fs.readFileSync(m[2].replace('file://', ''), 'utf8').slice(0, 200); } catch { expanded[m[1]] = 'unreadable'; }
          }
          out = xml.replace(/&(\w+);/g, (_, name) => expanded[name] ?? `&${name};`);
          if (out.includes('SYSTEM')) return send(200, `<html><body>Parsed: ${out.replace(/<[^>]+>/g, '').slice(0, 400)}</body></html>`);
          return send(200, `<html><body>Parsed OK</body></html>`);
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
    const httpServer = http.createServer(handler);
    httpServer.listen(httpPort, '127.0.0.1', () => {
      servers.push(httpServer);
      if (tlsPort) {
        const keyPath = path.join(__dirname, 'certs', 'key.pem');
        const certPath = path.join(__dirname, 'certs', 'cert.pem');
        if (fs.existsSync(keyPath)) {
          const httpsMod = import('node:https').then(({ default: https }) => {
            const tlsServer = https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, handler);
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
