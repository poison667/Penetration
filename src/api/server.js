import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';
import { Router, json, readJson, readBody } from './router.js';
import { registerCoreRoutes } from './routes-core.js';
import { registerExtraRoutes } from './routes-extra.js';
import { authenticate, authenticateApiKey } from './authn.js';
import { toAppError, AppError } from '#core/errors';
import { parseMultipart } from '#sec/http';
import { bus } from '#core/events';
import { createServiceRequest } from '#worker/runner';
import { generateReport } from '#report/engine';
import { AutomationEngine } from '#auto/engine';
import { Scheduler } from '#worker/scheduler';
import { createRateLimiter } from './ratelimit.js';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json', '.txt': 'text/plain; charset=utf-8' };

export function createServer({ db, files, config }) {
  const router = new Router();
  const limiter = createRateLimiter();

  const app = { db, files, config, router, limiter, requestService: null, generateReport: (opts) => generateReport(db, files, opts), automation: null, scheduler: null };
  app.requestService = (opts) => {
    const { job } = createServiceRequest({ db, ...opts });
    return job;
  };
  app.automation = new AutomationEngine({ db, files, requestService: app.requestService, generateReport: app.generateReport });
  app.scheduler = new Scheduler({ db, files, automation: app.automation, requestService: app.requestService, generateReport: app.generateReport, intervalMs: config.schedulerIntervalMs || 2500 });

  registerCoreRoutes(router, app);
  registerExtraRoutes(router, app);

  const uiRoot = config.uiRoot && fs.existsSync(config.uiRoot) ? config.uiRoot : null;

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const routePath = u.pathname;
    res.setHeader('x-request-id', `req_${Math.random().toString(36).slice(2, 10)}`);
    // secure headers
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('content-security-policy', uiRoot ? "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'" : "default-src 'none'");
    if (req.method === 'OPTIONS') { res.writeHead(204, { allow: 'GET,POST,PATCH,PUT,DELETE' }); res.end(); return; }

    if (routePath.startsWith('/api/')) {
      try {
        if (!limiter.allow(`ip:${req.socket.remoteAddress}`, 600, 10)) throw new AppError(429, 'rate_limited', 'API rate limit exceeded (600 req/min)');
        const match = router.match(req.method, routePath);
        if (!match) throw new AppError(404, 'not_found', `no route: ${req.method} ${routePath}`);
        const auth = authenticate(db, req, { allowCookie: true }) || authenticateApiKey(db, req);
        const ctx = {
          app, db, files, req, res, query: u.searchParams, params: match.params,
          auth, tid: auth?.user.tenant_id || null, ip: req.socket.remoteAddress,
          body: null, multipart: null,
          respond(status, body) { json(res, status, body); },
          respondRaw(status, buf, mime, headers = {}) { res.writeHead(status, { 'content-type': mime, 'content-length': buf.length, ...headers }); res.end(buf); },
          throw(status, message) { throw new AppError(status, status === 429 ? 'rate_limited' : 'error', message); },
        };
        // parse body
        if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
          const contentType = req.headers['content-type'] || '';
          if (contentType.includes('multipart/form-data')) {
            const buf = await readBody(req, { limit: 20 * 1024 * 1024 });
            ctx.multipart = parseMultipart(buf, contentType);
            ctx.body = ctx.multipart.fields;
          } else {
            ctx.body = await readJson(req, { limit: 5 * 1024 * 1024 });
          }
        }
        await match.route.handler(ctx);
        if (!res.writableEnded) json(res, 204, {});
      } catch (err) {
        const e = toAppError(err);
        if (e.status >= 500) console.error(`[api] ${req.method} ${routePath}`, err);
        if (!res.writableEnded) json(res, e.status, { error: { code: e.code, message: e.message, details: e.details || undefined } });
      }
      logRequest(req, routePath, res, started);
      return;
    }

    // SSE events stream.
    // Browsers' EventSource cannot set an Authorization header, and the session
    // cookie is scoped to /api/v1 — so this endpoint alone also accepts the
    // access token as a query parameter (the standard SSE pattern).
    if (routePath === '/events') {
      let auth = authenticate(db, req, { allowCookie: true }) || authenticateApiKey(db, req);
      if (!auth && u.searchParams.get('access_token')) {
        auth = authenticate(db, { headers: { authorization: `Bearer ${u.searchParams.get('access_token')}` } });
      }
      if (!auth) { json(res, 401, { error: { code: 'unauthorized', message: 'SSE requires authentication' } }); return; }
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-transform', connection: 'keep-alive', 'x-accel-buffering': 'no' });
      res.write(`retry: 5000\n\n`);
      const tenantId = auth.user.tenant_id;
      const onEvent = ({ topic, payload }) => {
        if (payload?.tenant_id && payload.tenant_id !== tenantId) return;
        res.write(`event: ${topic}\ndata: ${JSON.stringify(payload ?? {}).replace(/\n/g, ' ')}\n\n`);
      };
      bus.on('event', onEvent);
      const heartbeat = setInterval(() => { try { res.write(`: ping\n\n`); } catch { /* closed */ } }, 25_000);
      req.on('close', () => { bus.off('event', onEvent); clearInterval(heartbeat); });
      return;
    }

    // OpenAPI
    if (routePath === '/openapi.json') {
      json(res, 200, buildOpenApi(router));
      return;
    }

    // static UI (built client)
    if (uiRoot && req.method === 'GET') {
      let rel = routePath === '/' ? '/index.html' : routePath;
      const filePath = path.normalize(path.join(uiRoot, rel));
      if (!filePath.startsWith(uiRoot)) { res.writeHead(403); res.end(); return; }
      let target = filePath;
      if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) target = path.join(uiRoot, 'index.html'); // SPA fallback
      if (fs.existsSync(target)) {
        const ext = path.extname(target).toLowerCase();
        const body = fs.readFileSync(target);
        res.writeHead(200, { 'content-type': MIME[ext] || 'application/octet-stream', 'content-length': body.length, 'cache-control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
        res.end(body);
        return;
      }
    }
    json(res, 404, { error: { code: 'not_found', message: 'not found', hint: uiRoot ? null : 'client UI build not present — run `npm --prefix apps/client run build`' } });
  });
  server.app = app;
  return server;
}

function logRequest(req, pathName, res, started) {
  if (process.env.MERIDIAN_LOG === 'silent') return;
  console.log(`${new Date().toISOString()} ${req.method} ${pathName} → ${res.statusCode} ${Date.now() - started}ms`);
}

function buildOpenApi(router) {
  const paths = {};
  for (const r of router.routes) {
    const oapiPath = r.pattern.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
    paths[oapiPath] = paths[oapiPath] || {};
    paths[oapiPath][r.method.toLowerCase()] = {
      summary: `${r.method} ${r.pattern}`,
      tags: [r.pattern.split('/')[3] || 'core'],
      security: r.pattern.includes('/auth/') && r.method === 'POST' ? [] : [{ bearerAuth: [] }],
      responses: { '200': { description: 'success' }, '401': { description: 'unauthenticated' }, '403': { description: 'insufficient permissions' }, '422': { description: 'validation failed' } },
    };
  }
  return {
    openapi: '3.1.0',
    info: { title: 'Meridian Platform API', version: '1.0.1', description: 'Unified audit, security assessment, monitoring, data & AI operations platform. Session bearer tokens or API keys (mk_...) are used for authentication.' },
    servers: [{ url: '/' }],
    components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } },
    paths,
  };
}
