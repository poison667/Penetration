'use strict';
// Meridian Platform — desktop application (Electron main process), v1.0.0
//
// Modes:
//   GUI (default)           extract payload, seed on first run, start the
//                           platform server, open it in an app window
//   --launcher-serve        (ELECTRON_RUN_AS_NODE child) run the platform server
//   --launcher-seed         (ELECTRON_RUN_AS_NODE child) run first-run demo seeding
//
// Layout under the app home (%LOCALAPPDATA%\Meridian on Windows):
//   payload-<version>/   extracted platform application files
//   data/                platform data (store, files, secrets)  — NEVER touched by updates
//   logs/desktop.log     desktop shell log
//   instance.lock        { pid, url } while running
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const zlib = require('node:zlib');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');

const VERSION = '1.0.0';

function homeDir() {
  if (process.env.MERIDIAN_DESKTOP_HOME) return process.env.MERIDIAN_DESKTOP_HOME;
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Meridian');
  }
  const xdg = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return path.join(xdg, 'Meridian');
}

// ---------------------------------------------------------------- node mode --
if (process.env.ELECTRON_RUN_AS_NODE === '1') {
  const args = process.argv.slice(2);
  const isServe = args.includes('--launcher-serve');
  const isSeed = args.includes('--launcher-seed');
  if (isServe || isSeed) {
    const home = homeDir();
    const payloadDir = process.env.MERIDIAN_PAYLOAD_DIR || path.join(home, `payload-${VERSION}`);
    const target = path.join(payloadDir, isSeed ? 'src' + path.sep + 'seed' + path.sep + 'seed.js' : 'src' + path.sep + 'main.js');
    const rest = args.filter((a) => !a.startsWith('--launcher-'));
    process.argv = [process.argv[0], target, ...rest];
    import(pathToFileURL(target).href).catch((err) => {
      console.error('[meridian] payload start failed:', (err && err.stack) || err);
      process.exit(1);
    });
  }
  return;
}

// ------------------------------------------------------------------ GUI mode --
const { app, BrowserWindow, shell } = require('electron');

let logStream = null;
let serverChild = null;
let serverUrl = null;
let win = null;

function log(line) {
  console.log(line);
  try {
    if (!logStream) logStream = fs.createWriteStream(path.join(homeDir(), 'logs', 'desktop.log'), { flags: 'a' });
    logStream.write(line + '\n');
  } catch { /* logging must never break the app */ }
}

/** Minimal ustar + gzip extractor (payloads are built with --format=ustar). */
function extractTarGz(buf, dest) {
  const tar = zlib.gunzipSync(buf);
  let off = 0;
  const files = [];
  const destPrefix = path.resolve(dest) + path.sep;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0[\s\S]*$/, '');
    const size = parseInt(header.subarray(124, 136).toString('utf8').replace(/[\0 ]/g, ''), 8) || 0;
    const type = header[156];
    const data = tar.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;
    if (name === '././@PaxHeader' || name === 'pax_global_header') continue;
    const rel = name.replace(/^\.\//, '').replace(/\/+$/, '');
    if (!rel || rel === '.') continue;
    const target = path.join(dest, rel);
    if (!path.resolve(target).startsWith(destPrefix)) continue; // never escape dest
    if (type === 53) { // directory
      fs.mkdirSync(target, { recursive: true });
    } else if (type === 48 || type === 0) { // regular file
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, data);
      files.push(rel);
    }
  }
  return files;
}

function preparePayload(home) {
  const payloadDir = path.join(home, `payload-${VERSION}`);
  if (fs.existsSync(path.join(payloadDir, '.ready'))) {
    log(`[meridian] application files present (v${VERSION})`);
    return payloadDir;
  }
  log('[meridian] preparing application files (first run only)...');
  const tgz = fs.readFileSync(path.join(__dirname, 'payload', 'app.tgz'));
  const tmp = `${payloadDir}.tmp-${process.pid}`;
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
  const n = extractTarGz(tgz, tmp).length;
  fs.writeFileSync(path.join(tmp, '.ready'), VERSION);
  fs.rmSync(payloadDir, { recursive: true, force: true });
  fs.renameSync(tmp, payloadDir);
  log(`[meridian] application ready (${n} files, v${VERSION})`);
  return payloadDir;
}

function needsSeed(home) {
  if (fs.existsSync(path.join(home, '.seeded'))) return false;
  if (fs.existsSync(path.join(home, 'data', 'store'))) return false; // existing workspace
  return true;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

function childEnv(home, payloadDir, ports) {
  return {
    ...process.env,
    ELECTRON_RUN_AS_NODE: '1',
    MERIDIAN_DATA: path.join(home, 'data'),
    MERIDIAN_PAYLOAD_DIR: payloadDir,
    HOST: '127.0.0.1',
    PORT: String(ports.main),
    FIXTURE_HTTP_PORT: String(ports.fixtureHttp),
    FIXTURE_TLS_PORT: String(ports.fixtureTls),
  };
}

function pumpLines(stream, fn) {
  let buf = '';
  stream.on('data', (d) => {
    buf += d;
    const lines = buf.split(/\r?\n/);
    buf = lines.pop();
    for (const l of lines) fn(l);
  });
}

function runSeed(home, payloadDir, ports, onLine) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [__filename, '--launcher-seed'], {
      cwd: payloadDir,
      env: childEnv(home, payloadDir, ports),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const onL = (l) => { log(l); if (onLine) onLine(l); };
    pumpLines(child.stdout, onL);
    pumpLines(child.stderr, onL);
    child.on('error', (e) => { log(`[meridian] seed spawn failed: ${e.message}`); resolve(1); });
    child.on('exit', (code) => resolve(code == null ? 1 : code));
  });
}

function startServer(home, payloadDir, ports, onReady, onDied) {
  const child = spawn(process.execPath, [__filename, '--launcher-serve', '--mode', 'all'], {
    cwd: payloadDir,
    env: childEnv(home, payloadDir, ports),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  serverChild = child;
  const urlRe = /listening on (https?:\/\/[^\s)]+)[\s)]/;
  let ready = false;
  pumpLines(child.stdout, (l) => {
    log(l);
    if (!ready) {
      const m = urlRe.exec(l);
      if (m) { ready = true; onReady(m[1].replace('://0.0.0.0', '://127.0.0.1')); }
    }
  });
  pumpLines(child.stderr, (l) => log(l));
  child.on('error', (e) => { log(`[meridian] server spawn failed: ${e.message}`); if (!ready) onDied(e.message); });
  child.on('exit', (code) => {
    log(`[meridian] platform server exited (code ${code})`);
    serverChild = null;
    if (!ready) onDied(`server exited with code ${code}`);
    else if (win && !win.isDestroyed()) onDied('server stopped');
  });
}

function loadingPage(msg) {
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Meridian Platform</title><style>
    body{margin:0;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif}
    .logo{width:56px;height:56px;border-radius:14px;background:linear-gradient(135deg,#2563eb,#0ea5e9);display:flex;align-items:center;justify-content:center;font-size:26px;color:#fff;margin-bottom:22px}
    h1{font-size:20px;font-weight:600;margin:0 0 10px;letter-spacing:.2px}
    p{color:#94a3b8;font-size:13px;max-width:580px;text-align:center;line-height:1.5;margin:0;padding:0 24px}
    .bar{margin-top:28px;width:220px;height:3px;border-radius:2px;background:#1e293b;overflow:hidden;position:relative}
    .bar::after{content:'';position:absolute;left:-40%;width:40%;height:100%;background:#3b82f6;border-radius:2px;animation:m 1.2s infinite}
    @keyframes m{to{left:100%}}
  </style></head><body><div class="logo">&#9670;</div><h1>Meridian Platform</h1><p id="s">${msg}</p><div class="bar"></div></body></html>`;
  return 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
}

function errorPage(msg) {
  return loadingPage(msg).replace('<div class="bar"></div>', '');
}

async function main() {
  const home = homeDir();
  for (const d of [home, path.join(home, 'data'), path.join(home, 'logs')]) fs.mkdirSync(d, { recursive: true });
  log('');
  log(`[meridian] Meridian Platform desktop v${VERSION} — home: ${home}`);

  if (!app.requestSingleInstanceLock()) {
    log('[meridian] another instance is already running — focusing it and exiting.');
    app.quit();
    return;
  }
  app.on('second-instance', () => {
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });

  win = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1024,
    minHeight: 680,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: '#0f172a',
    title: 'Meridian Platform',
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  win.once('ready-to-show', () => win.show());
  const setStatus = (t) => {
    if (win && !win.isDestroyed()) {
      win.webContents.executeJavaScript(`document.getElementById('s').textContent = ${JSON.stringify(t)}`).catch(() => {});
    }
  };
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  await win.loadURL(loadingPage('Starting…'));

  setStatus('Preparing application files…');
  const payloadDir = preparePayload(home);

  const ports = { main: await freePort(), fixtureHttp: await freePort(), fixtureTls: await freePort() };

  if (needsSeed(home)) {
    log('[meridian] first run: creating the demo workspace — 12 REAL engine jobs will execute.');
    log('[meridian] this takes a few minutes; you can watch the progress here.');
    setStatus('First run: creating the demo workspace — running 12 real engine jobs (this takes a few minutes)…');
    const code = await runSeed(home, payloadDir, ports, (l) => {
      if (l.startsWith('[seed] job ') || l.startsWith('[seed] total')) setStatus(`First run: ${l.replace(/^\[seed\] /, '')}`);
    });
    if (code === 0) {
      fs.writeFileSync(path.join(home, '.seeded'), new Date().toISOString() + '\n');
      log('[meridian] demo workspace ready.');
    } else {
      log(`[meridian] seeding exited with code ${code} — continuing (the platform itself still starts).`);
    }
  } else {
    log('[meridian] existing workspace found — skipping demo seeding.');
  }

  setStatus('Starting the platform…');
  startServer(
    home,
    payloadDir,
    ports,
    (url) => {
      serverUrl = url;
      try {
        fs.writeFileSync(path.join(home, 'instance.lock'), JSON.stringify({ pid: process.pid, url, app: 'meridian-desktop', version: VERSION, started_at: new Date().toISOString() }, null, 2) + '\n');
      } catch { /* best effort */ }
      log(`[meridian] Meridian Platform v${VERSION} is running at ${url}`);
      log(`[meridian] UI login: demo@meridian.local / Demo!Passw0rd   (staff: staff@meridian.local / Staff!Passw0rd)`);
      if (win && !win.isDestroyed()) win.loadURL(url).catch(() => {});
    },
    (reason) => {
      if (!serverUrl) {
        log(`[meridian] the platform server did not start (${reason}).`);
        if (win && !win.isDestroyed()) win.loadURL(errorPage('The platform server did not start. Please close Meridian and start it again.')).catch(() => {});
      } else if (win && !win.isDestroyed()) {
        win.loadURL(errorPage('The platform server stopped. Please close Meridian and start it again.')).catch(() => {});
      }
    }
  );
}

app.whenReady().then(main).catch((err) => {
  log(`[meridian] fatal: ${(err && err.stack) || err}`);
  app.quit();
});
app.on('window-all-closed', () => app.quit());
app.on('before-quit', () => {
  try { fs.rmSync(path.join(homeDir(), 'instance.lock'), { force: true }); } catch { /* best effort */ }
  if (serverChild) serverChild.kill();
});
