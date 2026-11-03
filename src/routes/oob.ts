import type { Context } from 'hono';
import { Hono } from 'hono';
import type { Env, OobInteractionSummary, Variables } from '../types';
import { keyedHash, packSealed, sealJson } from '../lib/crypto';
import { randomId, safeJsonParse } from '../lib/encoding';
import { intSetting } from '../lib/http';
import { discordWebhookConfigured, sendDiscordOobNotification } from '../lib/discord';
import {
  boundOobHeaders,
  boundOobText,
  canonicalOobResponse,
  encodeOobBody,
  MAX_OOB_BODY_BYTES,
  OOB_HOST_MAX_BYTES,
  OOB_METHOD_MAX_BYTES,
  OOB_PATH_MAX_BYTES,
  OOB_QUERY_MAX_BYTES,
  OOB_USER_AGENT_MAX_BYTES,
  oobResponseSpec,
  oobTokenFromPath,
  redactToken,
  type OobResponsePolicy,
  type OobResponseSpec,
} from '../lib/oob';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();
type OobContext = Context<{ Bindings: Env; Variables: Variables }>;

const BODYLESS_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function responseFromSpec(spec: OobResponseSpec): Response {
  const headers = new Headers();
  for (const [name, value] of spec.headers) {
    try {
      headers.set(name, value);
    } catch {
      // Skip any header the runtime rejects; validation should prevent this.
    }
  }
  return new Response(spec.body, { status: spec.status, headers });
}

/**
 * The uniform, inert default response. It is identical for unknown, disabled,
 * and rate-limited tokens so the endpoint cannot be used to enumerate active
 * listeners, and for listeners that have not opted into a custom response.
 * Permissive CORS lets browser-driven callbacks and their preflights complete.
 */
function oobResponse(status = 200): Response {
  return responseFromSpec(oobResponseSpec(null, status));
}

interface ProbeRow {
  id: string;
  name: string;
  discord_notifications: number;
  response_status: number | null;
  response_body: string;
  response_headers: string;
}

/** Resolves a listener's stored response configuration, or null for the default. */
function probeResponsePolicy(probe: ProbeRow): OobResponsePolicy | null {
  if (probe.response_status === null) return null;
  return canonicalOobResponse({
    status: probe.response_status,
    body: probe.response_body ?? '',
    headers: safeJsonParse<unknown>(probe.response_headers ?? '[]', []),
  });
}

function declaredLength(request: Request): number | null {
  const declared = request.headers.get('Content-Length');
  if (!declared || !/^\d+$/.test(declared)) return null;
  const length = Number.parseInt(declared, 10);
  return Number.isSafeInteger(length) && length >= 0 ? length : null;
}

/**
 * Reads at most MAX_OOB_BODY_BYTES of the request body by streaming, so a
 * hostile or chunked callback can never force the Worker to buffer an arbitrary
 * amount of memory. The true size is taken from Content-Length when it is
 * present and consistent; otherwise it is the number of bytes actually read.
 */
async function readCapturedBody(
  request: Request,
  method: string,
): Promise<{ body: string; encoding: 'utf-8' | 'base64url'; byteLength: number; truncated: boolean }> {
  const empty = { body: '', encoding: 'utf-8' as const, byteLength: 0, truncated: false };
  if (BODYLESS_METHODS.has(method.toUpperCase()) || !request.body) return empty;

  const declared = declaredLength(request);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let read = 0;
  let overflow = false;
  try {
    while (read < MAX_OOB_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const remaining = MAX_OOB_BODY_BYTES - read;
      if (value.byteLength > remaining) {
        chunks.push(value.subarray(0, remaining));
        read += remaining;
        overflow = true;
        break;
      }
      chunks.push(value);
      read += value.byteLength;
    }
    if (!overflow && read >= MAX_OOB_BODY_BYTES) {
      const next = await reader.read();
      if (!next.done && next.value && next.value.byteLength > 0) overflow = true;
    }
  } catch {
    // A partial body is still worth recording; fall through with what we have.
  } finally {
    try {
      await reader.cancel();
    } catch {
      // Cancelling an already-finished stream is not an error.
    }
  }

  const combined = new Uint8Array(read);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const encoded = encodeOobBody(combined);
  const truncated = overflow || (declared !== null && declared > read);
  const byteLength = declared !== null && declared >= read ? declared : read;
  return { body: encoded.body, encoding: encoded.encoding, byteLength, truncated };
}

/**
 * Records a single out-of-band interaction. Mirrors the blind-XSS capture path:
 * rate limited per token, encrypted with AES-256-GCM, charged against the shared
 * R2 storage budget atomically, and indexed only while the listener is enabled.
 */
export async function captureOob(
  request: Request,
  env: Env,
  ctx: { waitUntil(promise: Promise<unknown>): void },
  token: string,
  matchedBy: 'path' | 'host',
): Promise<Response> {
  const tokenHash = await keyedHash(env, 'oob-token', token);
  const allowed = await env.COLLECTOR_RATE_LIMITER.limit({ key: `oob:${tokenHash}` });
  if (!allowed.success) return oobResponse(429);

  const probe = await env.DB.prepare(
    `SELECT id, name, discord_notifications, response_status, response_body, response_headers
       FROM oob_probes WHERE token_hash = ? AND enabled = 1`,
  )
    .bind(tokenHash)
    .first<ProbeRow>();
  // Unknown or disabled listeners still receive the uniform default response.
  if (!probe) return oobResponse();

  // Resolved once, so every known-listener exit (capture, cap, storage failure)
  // returns the same operator-configured response the target expects.
  const respond = (): Response => responseFromSpec(oobResponseSpec(probeResponsePolicy(probe)));

  const current = Math.floor(Date.now() / 1_000);
  const createdDay = new Date(current * 1_000).toISOString().slice(0, 10);
  const maxPerDay = intSetting(env.MAX_EVENTS_PER_DAY, 5_000, 1, 50_000);
  const today = await env.DB.prepare('SELECT COUNT(*) AS count FROM oob_interactions WHERE created_day = ?')
    .bind(createdDay)
    .first<{ count: number }>();
  if (Number(today?.count ?? 0) >= maxPerDay) return respond();

  const url = new URL(request.url);
  const rawUserAgent = request.headers.get('User-Agent') ?? '';
  const method = boundOobText(request.method, OOB_METHOD_MAX_BYTES);
  // The detail is step-up-gated, so it keeps the full request line (which, for a
  // path/host capture, contains the listener token). The summary is served by the
  // non-step-up interactions list, so the token is redacted from the raw value
  // before bounding — redacting first prevents truncation leaving a token
  // fragment behind.
  const host = boundOobText(url.host, OOB_HOST_MAX_BYTES);
  const path = boundOobText(url.pathname, OOB_PATH_MAX_BYTES);
  const query = boundOobText(url.search.replace(/^\?/, ''), OOB_QUERY_MAX_BYTES);
  const userAgent = boundOobText(rawUserAgent, OOB_USER_AGENT_MAX_BYTES);
  const summaryHost = boundOobText(redactToken(url.host, token), OOB_HOST_MAX_BYTES);
  const summaryPath = boundOobText(redactToken(url.pathname, token), OOB_PATH_MAX_BYTES);
  const summaryQuery = boundOobText(redactToken(url.search.replace(/^\?/, ''), token), OOB_QUERY_MAX_BYTES);
  const summaryUserAgent = boundOobText(redactToken(rawUserAgent, token), OOB_USER_AGENT_MAX_BYTES);
  const { headers, count: headerCount } = boundOobHeaders(request.headers);
  const body = await readCapturedBody(request, method);

  const cf = request.cf as IncomingRequestCfProperties | undefined;
  const ip = request.headers.get('CF-Connecting-IP') ?? '';
  const country = String(cf?.country ?? '');

  const summary: OobInteractionSummary = {
    method,
    host: summaryHost,
    path: summaryPath,
    query: summaryQuery,
    matchedBy,
    ip,
    country,
    userAgent: summaryUserAgent,
    headerCount,
    bodyBytes: body.byteLength,
    bodyTruncated: body.truncated,
    receivedAt: current,
  };
  const detail = {
    schemaVersion: 1 as const,
    method,
    host,
    path,
    query,
    matchedBy,
    headers,
    body: body.body,
    bodyEncoding: body.encoding,
    bodyBytes: body.byteLength,
    bodyTruncated: body.truncated,
    network: {
      ip,
      country,
      city: String(cf?.city ?? ''),
      colo: String(cf?.colo ?? ''),
      asn: Number(cf?.asn ?? 0),
      tlsVersion: String(cf?.tlsVersion ?? ''),
    },
    serverReceivedAt: current,
  };

  const interactionId = randomId();
  const sealedSummary = await sealJson(env, `oob:${interactionId}:summary`, summary);
  const detailObject = packSealed(await sealJson(env, `oob:${interactionId}:detail`, detail));
  const totalBytes = detailObject.byteLength;
  const maxStorageBytes = intSetting(env.MAX_STORAGE_BYTES, 8_053_063_680, 10_485_760, 9_000_000_000);
  const reservation = await env.DB.prepare(
    `UPDATE app_state
        SET storage_bytes = storage_bytes + ?, updated_at = ?
      WHERE id = 1 AND storage_bytes + ? <= ?
      RETURNING storage_bytes`,
  )
    .bind(totalBytes, current, totalBytes, maxStorageBytes)
    .first<{ storage_bytes: number }>();
  if (!reservation) return respond();

  const detailKey = `oob/${probe.id}/${interactionId}/detail.bin`;
  try {
    await env.VAULT.put(detailKey, detailObject, {
      httpMetadata: { contentType: 'application/octet-stream' },
      customMetadata: { schema: '1', kind: 'oob-detail' },
    });
    const inserted = await env.DB.prepare(
      `INSERT INTO oob_interactions
        (id, probe_id, received_at, summary_ciphertext, summary_iv, detail_key, detail_bytes, created_day)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM oob_probes WHERE token_hash = ? AND id = ? AND enabled = 1
        )`,
    )
      .bind(
        interactionId,
        probe.id,
        current,
        sealedSummary.ciphertext,
        sealedSummary.iv,
        detailKey,
        detailObject.byteLength,
        createdDay,
        tokenHash,
        probe.id,
      )
      .run();
    if (Number(inserted.meta?.changes ?? 0) !== 1) {
      await env.VAULT.delete(detailKey);
      await env.DB.prepare(
        'UPDATE app_state SET storage_bytes = MAX(0, storage_bytes - ?), updated_at = ? WHERE id = 1',
      )
        .bind(totalBytes, current)
        .run();
      return respond();
    }
    if (probe.discord_notifications === 1 && discordWebhookConfigured(env)) {
      ctx.waitUntil(
        sendDiscordOobNotification(env, {
          interactionId,
          probeName: probe.name,
          method,
          receivedAt: current,
        }).then(() => undefined),
      );
    }
    return respond();
  } catch {
    await env.VAULT.delete(detailKey).catch(() => undefined);
    await env.DB.prepare(
      'UPDATE app_state SET storage_bytes = MAX(0, storage_bytes - ?), updated_at = ? WHERE id = 1',
    )
      .bind(totalBytes, current)
      .run();
    return respond();
  }
}

async function handlePathCapture(c: OobContext): Promise<Response> {
  const token = oobTokenFromPath(new URL(c.req.url).pathname);
  if (!token) return oobResponse();
  return captureOob(c.req.raw, c.env, c.executionCtx, token, 'path');
}

app.all('/o/:token', handlePathCapture);
app.all('/o/:token/*', handlePathCapture);

export default app;
