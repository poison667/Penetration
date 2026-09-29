// Meridian Platform — desktop shell (Tauri 2).
// One shared codebase with the web client: this shell loads the identical
// React+TypeScript SPA built into webroot/ by apps/client.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Meridian desktop shell");
}
