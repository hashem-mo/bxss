import { createRemoteJWKSet, jwtVerify } from 'jose';
import { Hono } from 'hono';
import type { Env, Variables } from './types';
import { resolveSession, sessionCookieCleared } from './lib/auth';
import { jsonError, securityHeaders } from './lib/http';
import { runRetention } from './lib/retention';
import authRoutes from './routes/auth';
import adminRoutes from './routes/admin';
import collectorRoutes from './routes/collector';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();
const accessKeySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

const PUBLIC_PREFIXES = ['/p/', '/a/', '/c/', '/probe-runtime/'];
const PUBLIC_EXACT = new Set(['/health', '/ingest/injections']);
const DASHBOARD_EXACT = new Set(['/dashboard', '/dashboard/']);
const LOGIN_ASSET_PREFIX = '/login-assets/';
const ADMIN_ASSET_PREFIX = '/admin-assets/';
const PUBLIC_AUTH = new Set([
  '/api/auth/status',
  '/api/auth/bootstrap/options',
  '/api/auth/bootstrap/verify',
  '/api/auth/login/options',
  '/api/auth/login/verify',
  '/api/auth/recovery',
  '/api/auth/recovery/options',
  '/api/auth/recovery/verify',
]);

function isCollectorPath(path: string): boolean {
  return PUBLIC_EXACT.has(path) || PUBLIC_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function isDashboardPath(path: string): boolean {
  return DASHBOARD_EXACT.has(path) || path.startsWith(ADMIN_ASSET_PREFIX);
}

function normalizedAccessIssuer(value: string): string {
  const withScheme = /^https:\/\//i.test(value) ? value : `https://${value}`;
  return withScheme.replace(/\/$/, '');
}

async function validateCloudflareAccess(request: Request, env: Env): Promise<boolean> {
  if (!env.CF_ACCESS_TEAM_DOMAIN && !env.CF_ACCESS_AUD) return true;
  if (!env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_AUD) return false;
  const assertion = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!assertion) return false;
  const issuer = normalizedAccessIssuer(env.CF_ACCESS_TEAM_DOMAIN);
  let keySet = accessKeySets.get(issuer);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    accessKeySets.set(issuer, keySet);
  }
  try {
    await jwtVerify(assertion, keySet, {
      issuer,
      audience: env.CF_ACCESS_AUD,
      algorithms: ['RS256'],
      clockTolerance: 5,
    });
    return true;
  } catch {
    return false;
  }
}

app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  const publicCollector = isCollectorPath(path);
  c.set('requestId', c.req.header('CF-Ray') ?? crypto.randomUUID());

  if (!publicCollector && !(await validateCloudflareAccess(c.req.raw, c.env))) {
    c.res = jsonError(c, 403, 'access_denied', 'Cloudflare Access verification failed.');
    return;
  }

  const protectedApi = path.startsWith('/api/') && !PUBLIC_AUTH.has(path);
  const protectedDashboard = isDashboardPath(path);
  if (protectedApi || protectedDashboard) {
    const session = await resolveSession(c.req.raw, c.env);
    if (!session) {
      const response = protectedDashboard
        ? DASHBOARD_EXACT.has(path)
          ? new Response(null, { status: 302, headers: { Location: '/' } })
          : new Response(null, { status: 404 })
        : jsonError(c, 401, 'authentication_required', 'Passkey authentication is required.');
      response.headers.append('Set-Cookie', sessionCookieCleared());
      c.res = response;
      return;
    }
    c.set('session', session);
  }

  await next();
  c.res = securityHeaders(c.res, !publicCollector);
  if (!publicCollector && new URL(c.req.url).protocol === 'https:') {
    c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
});

app.get('/health', async (c) => {
  try {
    const state = await c.env.DB.prepare('SELECT id FROM app_state WHERE id = 1').first<{ id: number }>();
    return c.json({ status: state?.id === 1 ? 'ok' : 'uninitialized' }, state?.id === 1 ? 200 : 503);
  } catch {
    return c.json({ status: 'uninitialized' }, 503);
  }
});

app.get('/', async (c) => {
  const session = await resolveSession(c.req.raw, c.env);
  if (session) return c.redirect('/dashboard', 302);
  return c.env.ASSETS.fetch(c.req.raw);
});

app.get('/login-assets/*', (c) => c.env.ASSETS.fetch(c.req.raw));

app.get('/dashboard', (c) => c.env.ASSETS.fetch(c.req.raw));
app.get('/dashboard/', (c) => c.redirect('/dashboard', 308));
app.get('/admin-assets/*', (c) => c.env.ASSETS.fetch(c.req.raw));

// The raw probe bundle has no authenticated configuration and must never be
// exposed directly. Signed collector-bound requests are served by the route
// in collector.ts through the internal static-assets binding.
app.get('/probe-runtime.js', (c) => jsonError(c, 404, 'not_found', 'Not found.'));

app.route('/', collectorRoutes);
app.route('/api/auth', authRoutes);
app.route('/api', adminRoutes);

app.all('*', async (c) => {
  const path = new URL(c.req.url).pathname;
  if (path.startsWith('/api/') || isCollectorPath(path)) return jsonError(c, 404, 'not_found', 'Not found.');
  if (path.startsWith(LOGIN_ASSET_PREFIX) || isDashboardPath(path)) {
    return jsonError(c, 404, 'not_found', 'Not found.');
  }
  return jsonError(c, 404, 'not_found', 'Not found.');
});

app.onError((_, c) => jsonError(c, 500, 'internal_error', 'The request could not be completed.'));

export default {
  fetch: app.fetch,
  scheduled(_controller: ScheduledController, env: Env, context: ExecutionContext) {
    context.waitUntil(runRetention(env));
  },
} satisfies ExportedHandler<Env>;
