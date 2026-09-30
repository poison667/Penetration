/**
 * Desktop build-input verification (part of the verify gate).
 *
 * The sandbox cannot produce Tauri binaries (no Rust toolchain, no system
 * WebKitGTK — D4/L-2), so installers are built by CI. Everything CI needs is
 * verified HERE, continuously, so the CI matrix can only fail on toolchain
 * issues — never on a defect we could have caught statically:
 *   - tauri.conf.json: structure, identifiers, bundle targets, CSP, window
 *   - icons: existence, correct dimensions, valid .ico (required by the
 *     Windows NSIS/MSI bundlers), byte-identical to the generator output
 *   - shared-codebase invariant: the desktop bundle embeds the SAME webroot/
 *     the web deployment serves, rebuilt by beforeBuildCommand
 *   - shell crate: Cargo.toml deps, main.rs/build.rs wiring
 *   - CI workflow: both OS legs, system deps, per-OS bundles, artifact globs
 *
 * Never fabricates: anything absent or inconsistent is a hard failure.
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderMark, pngBytes, icoBytes } from './gen-icons.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok, detail }); console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`); };

const confPath = path.join(root, 'apps/desktop/src-tauri/tauri.conf.json');
let conf = null;
try { conf = JSON.parse(readFileSync(confPath, 'utf8')); check('tauri.conf.json parses', true); }
catch (e) { check('tauri.conf.json parses', false, e.message); }

if (conf) {
  check('product identity present', !!conf.productName && !!conf.version && /^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$/.test(conf.identifier || ''), `${conf.productName} v${conf.version} (${conf.identifier})`);
  check('identifier is not the Tauri default', (conf.identifier || '') !== 'com.tauri.dev');
  const targets = conf.bundle?.targets || [];
  const required = ['nsis', 'msi', 'appimage', 'deb', 'rpm'];
  check('bundle targets cover Windows (.exe/.msi) + Linux (AppImage/deb/rpm)', required.every((t) => targets.includes(t)), targets.join(','));

  // icons: existence + real PNG dimensions + .ico for Windows
  const iconDir = path.join(root, 'apps/desktop/src-tauri/icons');
  const expectedPng = { '32x32.png': 32, '128x128.png': 128, '128x128@2x.png': 256, 'icon.png': 256 };
  for (const [name, size] of Object.entries(expectedPng)) {
    const f = path.join(iconDir, name);
    if (!existsSync(f)) { check(`icon ${name} exists`, false); continue; }
    const b = readFileSync(f);
    const isPng = b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
    const gen = pngBytes(size, size, renderMark(size));
    check(`icon ${name} (${size}x${size}, generator-identical)`, isPng && w === size && h === size && gen.equals(b), `${w}x${h}, ${b.length}B`);
  }
  // .ico — REQUIRED by the Windows bundlers (NSIS/MSI); missing it fails the CI windows leg
  const icoPath = path.join(iconDir, 'icon.ico');
  if (!existsSync(icoPath)) {
    check('icon.ico (Windows installers) exists + valid', false, 'missing — run `npm run gen:icons`');
  } else {
    const ico = readFileSync(icoPath);
    let ok = ico.readUInt16LE(0) === 0 && ico.readUInt16LE(2) === 1 && ico.readUInt16LE(4) >= 1;
    const count = ico.readUInt16LE(4);
    let sizes = [];
    for (let i = 0; i < count && ok; i++) {
      const e = ico.subarray(6 + 16 * i, 6 + 16 * i + 16);
      const size = e[0] === 0 ? 256 : e[0];
      const bytes = e.readUInt32LE(8), off = e.readUInt32LE(12);
      sizes.push(size);
      ok = ok && e.readUInt16LE(4) === 1 && e.readUInt16LE(6) === 32 && off + bytes <= ico.length
        && ico.subarray(off, off + 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    }
    const genIco = icoBytes([16, 32, 48, 256], renderMark);
    ok = ok && genIco.equals(ico) && sizes.includes(256);
    check('icon.ico (Windows installers) exists + valid + generator-identical', ok, `${count} entries (${sizes.join('/')}), ${ico.length}B`);
  }
  check('.ico listed in bundle.icon (Windows bundlers read it from the config)', (conf.bundle?.icon || []).includes('icons/icon.ico'));

  // shared codebase invariants: desktop embeds the same SPA the web serves
  const fd = conf.build?.frontendDist;
  // Tauri resolves frontendDist relative to tauri.conf.json (src-tauri/); beforeBuildCommand runs from its parent.
  check('frontendDist resolves (relative to src-tauri/) to the repo webroot', fd === '../../../webroot', String(fd));
  const webroot = path.join(root, 'apps/desktop/src-tauri', fd || '');
  const indexOk = existsSync(path.join(webroot, 'index.html'));
  let spaDetail = 'run `npm --prefix apps/client run build` first';
  let spaOk = false;
  if (indexOk) {
    const html = readFileSync(path.join(webroot, 'index.html'), 'utf8');
    const asset = html.match(/src="(\/assets\/[^"]+\.js)"/)?.[1];
    if (asset) {
      const js = readFileSync(path.join(webroot, '.' + asset));
      spaOk = js.length > 100_000;
      spaDetail = `${asset} (${(js.length / 1024).toFixed(0)}KB SPA bundle)`;
    } else { spaDetail = 'index.html references no /assets/*.js bundle'; }
  }
  check('shared SPA is built into webroot (desktop bundle = web bundle)', indexOk && spaOk, spaDetail);
  check('beforeBuildCommand rebuilds the shared SPA', /apps\/client run build|apps\\client run build/.test(conf.build?.beforeBuildCommand || ''), String(conf.build?.beforeBuildCommand));

  check('CSP configured with local API access', /default-src/.test(conf.app?.security?.csp || '') && /127\.0\.0\.1:8080/.test(conf.app?.security?.csp || ''));
  const win = conf.app?.windows?.[0];
  check('sane window configuration', !!win && win.minWidth >= 800 && win.minHeight >= 500 && (win.width || 0) >= win.minWidth, `${win?.width}x${win?.height} (min ${win?.minWidth}x${win?.minHeight})`);
}

// shell crate
const cargo = readFileSync(path.join(root, 'apps/desktop/src-tauri/Cargo.toml'), 'utf8');
check('Cargo.toml: shell crate with tauri 2 + build script', /\[package\]/.test(cargo) && /tauri\s*=\s*\{\s*version\s*=\s*"2/.test(cargo) && /tauri-build/.test(cargo) && /rust-version/.test(cargo));
const mainRs = readFileSync(path.join(root, 'apps/desktop/src-tauri/src/main.rs'), 'utf8');
check('main.rs runs the Tauri shell (builder + generated context)', /tauri::Builder/.test(mainRs) && /generate_context!/.test(mainRs));
const buildRs = readFileSync(path.join(root, 'apps/desktop/src-tauri/build.rs'), 'utf8');
check('build.rs invokes tauri_build', /tauri_build::build\(\)/.test(buildRs));

// CI workflow: both legs, deps, explicit bundles, artifact coverage, gate wiring
const ci = readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
check('CI matrix builds Windows (windows-latest) and Linux (ubuntu-22.04)', ci.includes('windows-latest') && ci.includes('ubuntu-22.04'));
check('CI installs Linux system deps (webkit2gtk 4.1 + rsvg)', /libwebkit2gtk-4\.1-dev/.test(ci) && /librsvg2-dev/.test(ci));
check('CI builds per-OS installer bundles explicitly', /--bundles \$\{\{ matrix\.bundles \}\}/.test(ci) && ci.includes('bundles: nsis,msi') && ci.includes('bundles: appimage,deb,rpm'));
for (const [label, glob] of [['.exe', '**/*.exe'], ['.msi', '**/*.msi'], ['AppImage', '**/*.AppImage'], ['.deb', '**/*.deb'], ['.rpm', '**/*.rpm']]) {
  check(`CI uploads ${label} artifacts`, ci.includes(glob));
}
check('CI regenerates icons before bundling', /run: npm run gen:icons/.test(ci));
check('CI runs this verification before spending build minutes', /run: npm run verify:desktop/.test(ci));
check('CI test job installs dependencies (real OCR engine in CI)', /Install dependencies.*\n\s*run: npm install --no-audit --no-fund/.test(ci));
check('desktop README documents the shared-codebase build', existsSync(path.join(root, 'apps/desktop/README.md')));

const failed = results.filter((r) => !r.ok);
console.log(`[verify-desktop] ${results.length - failed.length}/${results.length} desktop build-input checks passed`);
if (failed.length) { console.error('[verify-desktop] FAILED — installers cannot build cleanly until these pass'); process.exit(1); }
