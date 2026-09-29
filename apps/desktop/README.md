# Meridian Desktop (Tauri 2)

Windows 10/11 and Linux desktop client, built from **one shared codebase** with the
web client: the Tauri shell loads the identical React+TypeScript SPA that
`apps/client` builds into `webroot/`. Feature parity is inherent — same bundle.

## Layout

- `src-tauri/tauri.conf.json` — product config, window, CSP, bundle targets:
  **Windows: NSIS + MSI · Linux: AppImage + deb + rpm**
- `src-tauri/Cargo.toml`, `src-tauri/src/main.rs`, `src-tauri/build.rs` — shell crate
- `../../webroot/` — the shared SPA build (produced by `npm --prefix apps/client run build`)

## Building locally (requires Rust toolchain)

```bash
npm --prefix ../../apps/client run build   # produce the shared SPA
npm run gen:icons                          # app icons
cargo tauri build                          # from src-tauri/ — installers land in target/release/bundle/
```

Installers are also produced by CI (`.github/workflows/ci.yml`, `build-desktop` job
matrix: `windows-latest` → nsis/msi, `ubuntu-22.04` → appimage/deb/rpm). This
sandbox has no Rust toolchain, so binaries are CI-built — recorded as limitation
**L-2** and decision **D4** in `docs/`.

## Connecting to a server

The shell loads the SPA, which talks to a Meridian server. For local use, run
`npm start` in the repository root (API + worker + scheduler on :8080) and open the
desktop app; for hosted deployments the server URL is baked into the deployment
configuration.
