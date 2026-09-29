import fs from 'node:fs';
import path from 'node:path';
import { openStore } from '#store/store';
import { Db } from '#app/db';
import { FileStore } from '#app/files';
import { loadOrCreateSecretKey } from '#sec/crypto';
import { createServer } from '#api/server';

/**
 * Meridian platform entrypoint.
 * Modes: api (HTTP server), worker (scheduler+queue), all (single process).
 * Data dir: MERIDIAN_DATA (default ./data)
 */
const args = process.argv.slice(2);
const modeIdx = args.indexOf('--mode');
const mode = modeIdx !== -1 ? args[modeIdx + 1] : 'all';
const dataDir = path.resolve(process.env.MERIDIAN_DATA || './data');
const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || '0.0.0.0';

fs.mkdirSync(dataDir, { recursive: true });
loadOrCreateSecretKey(dataDir, fs);
const store = openStore(path.join(dataDir, 'store'), { sync: true });
const db = new Db(store);
const files = new FileStore(dataDir, store);

const uiRoot = path.resolve('./webroot');
const server = createServer({ db, files, config: { mode, dataDir, uiRoot: fs.existsSync(uiRoot) ? uiRoot : null } });
const { automation, scheduler } = server.app;
automation.start();

if (mode === 'all' || mode === 'worker') {
  scheduler.start();
  console.log(`[meridian] scheduler started (jobs, monitors, schedules, billing grants)`);
}
if (mode === 'all' || mode === 'api') {
  server.listen(port, host, () => {
    console.log(`[meridian] API + UI listening on http://${host}:${port} (mode=${mode})`);
    console.log(`[meridian] data dir: ${dataDir}`);
    console.log(`[meridian] openapi: http://${host}:${port}/openapi.json`);
  });
}
process.on('SIGINT', () => { console.log('\n[meridian] shutting down (snapshot)...'); scheduler.stop(); store.close(); process.exit(0); });
process.on('SIGTERM', () => { scheduler.stop(); store.close(); process.exit(0); });
