'use strict';
// Meridian Platform — one-file setup, v1.0.0
//
// Shipped as a single executable:
//   [node.exe + tiny SEA blob (this script)] [app.tar.gz overlay] [64-byte footer]
// Double-click → installs the windowed desktop app:
//   %LOCALAPPDATA%\Meridian\Program   application files
//   %LOCALAPPDATA%\Meridian\data      workspace data (NEVER touched — preserved)
//   Desktop + Start Menu shortcuts, Apps & Features entry with uninstaller,
//   then launches Meridian.exe (the windowed app).
//
// Modes: (default) install  |  --uninstall  (keeps data)
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { spawn, spawnSync } = require('node:child_process');

const VERSION = '1.0.0';
const APP_NAME = 'Meridian Platform';
const REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MeridianPlatform';

function homeDir() {
  if (process.env.MERIDIAN_DESKTOP_HOME) return process.env.MERIDIAN_DESKTOP_HOME;
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Meridian');
  }
  const xdg = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return path.join(xdg, 'Meridian');
}

function processAlive(pid) {
  if (!pid || typeof pid !== 'number') return false;
  try { process.kill(pid, 0); return true; }
  catch (e) { return e.code === 'EPERM'; } // ESRCH = dead, EPERM = alive (other user)
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

/** Locate the application archive: SEA asset | self-extracting overlay | dev file. */
function readPayload() {
  try { return require('node:sea').getRawAsset('app.tgz'); } catch { /* not a SEA asset */ }
  const MAGIC = 'MERIDIAN-OVL1';
  const FOOTER = 64;
  try {
    const st = fs.statSync(process.execPath);
    if (st.size > FOOTER + 512) {
      const fh = fs.openSync(process.execPath, 'r');
      const foot = Buffer.alloc(FOOTER);
      fs.readSync(fh, foot, 0, FOOTER, st.size - FOOTER);
      if (foot.subarray(0, MAGIC.length).toString('utf8') === MAGIC) {
        const len = Number(foot.readBigUInt64LE(MAGIC.length));
        if (len > 0 && len < st.size) {
          const buf = Buffer.alloc(len);
          fs.readSync(fh, buf, 0, len, st.size - FOOTER - len);
          fs.closeSync(fh);
          console.log(`  embedded application archive: ${(len / 1048576).toFixed(1)} MB`);
          return buf;
        }
      }
      fs.closeSync(fh);
    }
  } catch { /* fall through */ }
  return fs.readFileSync(path.join(__dirname, 'payload', 'app.tgz'));
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
    if (type === 53) {
      fs.mkdirSync(target, { recursive: true });
    } else if (type === 48 || type === 0) {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, data);
      files.push(rel);
    }
  }
  return files;
}

function uninstallCmd(programDir, home) {
  return [
    '@echo off',
    `title ${APP_NAME} Uninstall`,
    `echo Uninstalling ${APP_NAME}...`,
    'taskkill /IM Meridian.exe /F >nul 2>&1',
    `powershell -NoProfile -Command "Remove-Item -Path (Join-Path ([Environment]::GetFolderPath('Desktop') '${APP_NAME}.lnk') ) -Force -ErrorAction SilentlyContinue" >nul 2>&1`,
    `powershell -NoProfile -Command "Remove-Item -Path (Join-Path ([Environment]::GetFolderPath('Programs') '${APP_NAME}.lnk') ) -Force -ErrorAction SilentlyContinue" >nul 2>&1`,
    `del "%USERPROFILE%\\Desktop\\${APP_NAME}.lnk" >nul 2>&1`,
    `del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\${APP_NAME}.lnk" >nul 2>&1`,
    `reg delete "${REG_KEY}" /f >nul 2>&1`,
    `rd /s /q "${programDir}"`,
    'echo.',
    'echo Done. Your workspace data was KEPT at:',
    `echo   ${path.join(home, 'data')}`,
    'echo.',
    'pause',
    '',
  ].join('\r\n');
}

function makeShortcuts(programDir) {
  if (process.platform !== 'win32') {
    console.log('  shortcuts: skipped (Windows only — this is a test run)');
    return;
  }
  const exe = path.join(programDir, 'Meridian.exe');
  const ps = [
    '$ErrorActionPreference = "Stop"',
    '$ws = New-Object -ComObject WScript.Shell',
    `foreach ($dir in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {`,
    `  $lnk = $ws.CreateShortcut((Join-Path $dir '${APP_NAME}.lnk'))`,
    `  $lnk.TargetPath = '${exe}'`,
    `  $lnk.WorkingDirectory = '${programDir}'`,
    `  $lnk.IconLocation = '${exe},0'`,
    `  $lnk.Description = '${APP_NAME}'`,
    '  $lnk.Save()',
    '}',
    'Write-Output OK',
  ].join('\n');
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps], { encoding: 'utf8' });
  if (r.status === 0 && String(r.stdout).trim() === 'OK') {
    console.log('  shortcuts: Desktop + Start Menu ("Meridian Platform")');
  } else {
    console.log(`  shortcuts: FAILED (exit ${r.status}) — the app still works; start it from:\n    ${exe}`);
  }
}

function registerUninstaller(programDir) {
  if (process.platform !== 'win32') {
    console.log('  Apps & Features entry: skipped (Windows only)');
    return;
  }
  const values = [
    ['DisplayName', 'REG_SZ', APP_NAME],
    ['DisplayVersion', 'REG_SZ', VERSION],
    ['Publisher', 'REG_SZ', 'Meridian'],
    ['InstallLocation', 'REG_SZ', programDir],
    ['UninstallString', 'REG_SZ', `"${path.join(programDir, 'uninstall.cmd')}"`],
    ['NoModify', 'REG_DWORD', '1'],
    ['NoRepair', 'REG_DWORD', '1'],
  ];
  let ok = true;
  for (const [name, type, val] of values) {
    const r = spawnSync('reg.exe', ['add', REG_KEY, '/v', name, '/t', type, '/d', val, '/f'], { encoding: 'utf8' });
    if (r.status !== 0) ok = false;
  }
  if (ok) console.log('  Apps & Features entry: registered (uninstall = "Meridian Platform")');
  else console.log('  Apps & Features entry: FAILED (you can still uninstall via the uninstall.cmd in the install folder)');
}

function launch(programDir) {
  if (process.platform !== 'win32') {
    console.log('\n(test run on linux: launch skipped — on Windows this starts Meridian.exe)');
    return;
  }
  const exe = path.join(programDir, 'Meridian.exe');
  try {
    const child = spawn(exe, [], { detached: true, stdio: 'ignore', cwd: programDir });
    child.unref();
    console.log('\nStarting Meridian Platform...');
  } catch (e) {
    console.log(`\nCould not start automatically (${e.message}). Start it from:\n  ${exe}`);
  }
}

async function install() {
  const home = homeDir();
  const programDir = path.join(home, 'Program');
  console.log('');
  console.log(`=== ${APP_NAME} Setup v${VERSION} ===`);
  console.log('');
  const lock = readJson(path.join(home, 'instance.lock'), null);
  if (lock && processAlive(lock.pid)) {
    console.log(`${APP_NAME} is currently running (pid ${lock.pid}).`);
    console.log('Close it first, then run this setup again.');
    process.exit(1);
  }
  const tgzBuffer = readPayload();
  console.log(`Installing to: ${programDir}`);
  fs.rmSync(programDir, { recursive: true, force: true });
  fs.mkdirSync(programDir, { recursive: true });
  console.log('Copying application files (this takes a moment)...');
  const files = extractTarGz(tgzBuffer, programDir);
  console.log(`  ${files.length} files installed`);
  fs.writeFileSync(path.join(programDir, '.installed-version'), VERSION + '\n');
  fs.writeFileSync(path.join(programDir, 'uninstall.cmd'), uninstallCmd(programDir, home));
  makeShortcuts(programDir);
  registerUninstaller(programDir);
  console.log('');
  console.log('Install complete. Existing workspace data is preserved.');
  console.log('(On first launch the app creates the demo workspace if none exists.)');
  launch(programDir);
  console.log('');
  console.log('From now on, start the software like any other program:');
  console.log('  Desktop icon, or Start Menu > "Meridian Platform".');
}

async function uninstall() {
  const home = homeDir();
  const programDir = path.join(home, 'Program');
  console.log('');
  console.log(`=== ${APP_NAME} Uninstall v${VERSION} ===`);
  console.log('');
  const lock = readJson(path.join(home, 'instance.lock'), null);
  if (lock && processAlive(lock.pid)) {
    console.log(`${APP_NAME} is currently running (pid ${lock.pid}). Close it first.`);
    process.exit(1);
  }
  if (process.platform === 'win32') {
    for (const folder of ['Desktop', 'Programs']) {
      spawnSync('powershell.exe', ['-NoProfile', '-Command', `Remove-Item -Path (Join-Path ([Environment]::GetFolderPath('${folder}')) 'Meridian Platform.lnk') -Force -ErrorAction SilentlyContinue`], { encoding: 'utf8' });
    }
    spawnSync('reg.exe', ['delete', REG_KEY, '/f'], { encoding: 'utf8' });
    console.log('Shortcuts and Apps & Features entry removed.');
  } else {
    console.log('(test run on linux: shortcuts/registry skipped)');
  }
  fs.rmSync(programDir, { recursive: true, force: true });
  console.log('Application files removed.');
  console.log('');
  console.log('Uninstalled. Your workspace data was KEPT at:');
  console.log(`  ${path.join(home, 'data')}`);
}

const arg = process.argv[2] || '';
if (arg === '--uninstall') uninstall();
else if (arg === '--help' || arg === '-h') {
  console.log(`Meridian Platform Setup v${VERSION}`);
  console.log('  (no arguments)   install / update the desktop app');
  console.log('  --uninstall      remove the app (keeps workspace data)');
} else install();
