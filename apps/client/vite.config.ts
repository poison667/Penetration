import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Build straight into the platform webroot so src/api/server.js serves the SPA
// and the Tauri shell can load the identical build.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../../webroot',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2020',
  },
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8080', '/events': 'http://127.0.0.1:8080' },
  },
});
