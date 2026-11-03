import type { Context } from 'hono';
import { Hono } from 'hono';
import { z } from 'zod';
import { audit, prepareRecoveryCodes, requireStepUp } from '../lib/auth';
import { createCollectorAlias, isCollectorAlias } from '../lib/collector-identifiers';
import { keyedHash, openBytes, openJson, sealJson, unpackSealed } from '../lib/crypto';
import { bytesToBase64Url, fromUtf8, randomId, randomToken, safeJsonParse, utf8 } from '../lib/encoding';
import { discordWebhookConfigured, sendDiscordTestNotification } from '../lib/discord';
import {
  collectorOrigin,
  intSetting,
  jsonError,
  requireJson,
  requireSameOrigin,
  validateCsrf,
} from '../lib/http';
import type { CapturedEvent, CollectorRecord, Env, EventSummary, Variables } from '../types';

type AdminContext = Context<{ Bindings: Env; Variables: Variables }>;

interface EventRow {
  id: string;
  collector_id: string;
  collector_name: string;
  received_at: number;
  summary_ciphertext: string;
  summary_iv: string;
  detail_key: string;
  detail_bytes: number;
  screenshot_key: string | null;
  screenshot_bytes: number;
  screenshot_mime: string | null;
  injection_key_hash: string | null;
  is_read: number;
}

interface InjectionRequestRow {
  id: string;
  request_ciphertext: string;
  request_iv: string;
  created_at: number;
}

interface AuditRow {
  id: number;
  action: string;
  target_type: string | null;
  target_id: string | null;
  result: 'success' | 'denied' | 'error';
  request_id: string | null;
  metadata_json: string;
  created_at: number;
}

interface KeysetCursor {
  timestamp: number;
  id: string | number;
}

interface CollectorAdminRecord extends CollectorRecord {
  alias_id: string | null;
  alias_ciphertext: string | null;
  alias_iv: string | null;
  alias_created_at: number | null;
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>();
const currentTime = (): number => Math.floor(Date.now() / 1000);

const emptyBodySchema = z.object({}).strict();
const collectorCreateSchema = z.object({ name: z.string().trim().min(1).max(80) }).strict();
const readEventSchema = z.object({ read: z.boolean().default(true) }).strict();
const bulkDeleteSchema = z
  .object({
    ids: z.array(z.string().uuid()).min(1).max(20).optional(),
    all: z.literal(true).optional(),
    confirmation: z.string().max(64).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (Boolean(value.ids) === Boolean(value.all)) {
      context.addIssue({ code: 'custom', message: 'Choose event IDs or all events.' });
    }
    if (value.all && value.confirmation !== 'DELETE ALL CAPTURES') {
      context.addIssue({ code: 'custom', message: 'Delete-all confirmation is required.' });
    }
  });
const collectorUpdateSchema = z
  .object({
    name: z.string().trim().min(1).max(80).optional(),
    enabled: z.boolean().optional(),
    captureCookies: z.boolean().optional(),
    captureDom: z.boolean().optional(),
    captureScreenshot: z.boolean().optional(),
    captureStorage: z.boolean().optional(),
    discordNotifications: z.boolean().optional(),
    probeChecks: z.boolean().optional(),
    pagePaths: z
      .array(
        z
          .string()
          .trim()
          .min(1)
          .max(256)
          .refine(
            (value) => value.startsWith('/') && !value.startsWith('//') && !/[\u0000-\u001f\u007f]/.test(value),
            'Each page path must be a local absolute path.',
          ),
      )
      .max(3)
      .refine((paths) => new Set(paths).size === paths.length, 'Page paths must be unique.')
      .optional(),
    chainloadUrl: z
      .union([
        z.null(),
        z.literal(''),
        z
          .string()
          .trim()
          .max(2048)
          .refine((value) => {
            try {
              const url = new URL(value);
              return url.protocol === 'https:' && !url.username && !url.password && !url.hash;
            } catch {
              return false;
            }
          }, 'The chainload URL must be an HTTPS URL without credentials or a fragment.'),
      ])
      .optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'At least one collector setting is required.');

function changes(result: D1Result<unknown>): number {
  return Number(result.meta?.changes ?? 0);
}

async function parseJson(request: Request): Promise<unknown> {
  return request.json().catch(() => null);
}

async function mutationChecks(c: AdminContext, stepUp: boolean): Promise<Response | null> {
  if (!requireSameOrigin(c.req.raw, c.env) || !requireJson(c.req.raw) || !validateCsrf(c)) {
    return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  }
  return stepUp ? requireStepUp(c) : null;
}

function encodeCursor(cursor: KeysetCursor): string {
  return bytesToBase64Url(utf8(JSON.stringify(cursor)));
}

function decodeCursor(value: string | undefined, idType: 'string' | 'number'): KeysetCursor | null {
  if (!value || value.length > 512) return null;
  try {
    const decoded = JSON.parse(fromUtf8(base64UrlBytes(value))) as Partial<KeysetCursor>;
    if (!Number.isSafeInteger(decoded.timestamp) || Number(decoded.timestamp) < 0) return null;
    if (idType === 'string') {
      if (typeof decoded.id !== 'string' || decoded.id.length < 1 || decoded.id.length > 128) return null;
    } else if (!Number.isSafeInteger(decoded.id) || Number(decoded.id) < 1) {
      return null;
    }
    return { timestamp: Number(decoded.timestamp), id: decoded.id as string | number };
  } catch {
    return null;
  }
}

function base64UrlBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const decoded = atob(padded);
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) bytes[index] = decoded.charCodeAt(index);
  return bytes;
}

function listLimit(value: string | undefined): number | null {
  if (value === undefined || value === '') return 50;
  if (!/^\d{1,3}$/.test(value)) return null;
  const parsed = Number(value);
  return parsed >= 1 && parsed <= 100 ? parsed : null;
}

function publicEvent(row: EventRow, summary: EventSummary | null) {
  return {
    id: row.id,
    collectorId: row.collector_id,
    collectorName: row.collector_name,
    receivedAt: Number(row.received_at),
    isRead: row.is_read === 1,
    detailBytes: Number(row.detail_bytes),
    screenshotBytes: Number(row.screenshot_bytes),
    hasScreenshot: Boolean(row.screenshot_key),
    summary,
  };
}

async function decryptSummary(env: Env, row: EventRow): Promise<EventSummary | null> {
  try {
    return await openJson<EventSummary>(env, `event:${row.id}:summary`, {
      ciphertext: row.summary_ciphertext,
      iv: row.summary_iv,
    });
  } catch {
    return null;
  }
}

async function ownedEvent(env: Env, userId: string, eventId: string): Promise<EventRow | null> {
  return env.DB.prepare(
    `SELECT e.id, e.collector_id, c.name AS collector_name, e.received_at,
            e.summary_ciphertext, e.summary_iv, e.detail_key, e.detail_bytes,
            e.screenshot_key, e.screenshot_bytes, e.screenshot_mime,
            e.injection_key_hash, e.is_read
       FROM events e
       JOIN collectors c ON c.id = e.collector_id
      WHERE e.id = ? AND c.user_id = ?`,
  )
    .bind(eventId, userId)
    .first<EventRow>();
}

async function decryptCollector(env: Env, collector: CollectorAdminRecord, publicOrigin: string) {
  const token = await openJson<string>(env, `collector:${collector.id}:token`, {
    ciphertext: collector.token_ciphertext,
    iv: collector.token_iv,
  });
  let alias: string | null = null;
  if (collector.alias_id) {
    if (!collector.alias_ciphertext || !collector.alias_iv) throw new Error('Invalid active collector alias');
    alias = await openJson<string>(env, `collector:${collector.id}:alias:${collector.alias_id}`, {
      ciphertext: collector.alias_ciphertext,
      iv: collector.alias_iv,
    });
    if (!isCollectorAlias(alias)) throw new Error('Invalid active collector alias');
  }
  return {
    id: collector.id,
    name: collector.name,
    token,
    loaderUrl: `${publicOrigin}/p/${encodeURIComponent(token)}.js`,
    alias,
    aliasLoaderUrl: alias ? `${publicOrigin}/a/${encodeURIComponent(alias)}.js` : null,
    aliasCreatedAt: collector.alias_created_at === null ? null : Number(collector.alias_created_at),
    enabled: collector.enabled === 1,
    captureCookies: collector.capture_cookies === 1,
    captureDom: collector.capture_dom === 1,
    captureScreenshot: collector.capture_screenshot === 1,
    captureStorage: collector.capture_storage === 1,
    discordNotifications: collector.discord_notifications === 1,
    discordConfigured: discordWebhookConfigured(env),
    probeChecks: collector.probe_checks === 1,
    pagePaths: validPagePaths(safeJsonParse<unknown>(collector.page_paths, [])),
    chainloadUrl: collector.chainload_url,
    createdAt: Number(collector.created_at),
    updatedAt: Number(collector.updated_at),
  };
}

async function ownedCollectorAdmin(
  env: Env,
  userId: string,
  collectorId: string,
): Promise<CollectorAdminRecord | null> {
  return env.DB.prepare(
    `SELECT c.id, c.user_id, c.name, c.token_hash, c.token_ciphertext, c.token_iv,
            c.enabled, c.capture_cookies, c.capture_dom, c.capture_screenshot,
            c.capture_storage, c.discord_notifications, c.probe_checks,
            c.page_paths, c.chainload_url, c.created_at, c.updated_at,
            a.id AS alias_id, a.alias_ciphertext, a.alias_iv, a.created_at AS alias_created_at
       FROM collectors c
       LEFT JOIN collector_aliases a ON a.collector_id = c.id AND a.revoked_at IS NULL
      WHERE c.id = ? AND c.user_id = ?`,
  )
    .bind(collectorId, userId)
    .first<CollectorAdminRecord>();
}

async function ownedCollector(env: Env, userId: string, collectorId: string): Promise<CollectorRecord | null> {
  return env.DB.prepare(
    `SELECT id, user_id, name, token_hash, token_ciphertext, token_iv, enabled,
            capture_cookies, capture_dom, capture_screenshot, capture_storage,
            discord_notifications, probe_checks, page_paths, chainload_url,
            created_at, updated_at
       FROM collectors
      WHERE id = ? AND user_id = ?`,
  )
    .bind(collectorId, userId)
    .first<CollectorRecord>();
}

function validPagePaths(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((path): path is string => typeof path === 'string');
}

function isAliasUniquenessConflict(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('UNIQUE constraint failed: collector_aliases.alias_hash')
    || message.includes('UNIQUE constraint failed: collector_aliases.collector_id')
    || message.includes('collector_aliases_one_active');
}

function imageType(bytes: Uint8Array): { mime: string; extension: string } | null {
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return { mime: 'image/png', extension: 'png' };
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return { mime: 'image/jpeg', extension: 'jpg' };
  }
  return null;
}

function normalizedImageMime(value: string | null): string | null {
  if (!value) return null;
  const mime = value.split(';', 1)[0].trim().toLowerCase();
  return mime === 'image/jpg' ? 'image/jpeg' : mime;
}

app.get('/events', async (c) => {
  const session = c.get('session');
  const limit = listLimit(c.req.query('limit'));
  if (!limit) return jsonError(c, 422, 'invalid_pagination', 'Invalid pagination parameters.');

  const requestedCursor = c.req.query('cursor');
  const cursor = requestedCursor ? decodeCursor(requestedCursor, 'string') : null;
  if (requestedCursor && !cursor) return jsonError(c, 422, 'invalid_cursor', 'Invalid pagination cursor.');

  const collectorId = c.req.query('collectorId')?.trim() || null;
  if (collectorId && collectorId.length > 128) {
    return jsonError(c, 422, 'invalid_collector', 'Invalid collector filter.');
  }

  const result = await c.env.DB.prepare(
    `SELECT e.id, e.collector_id, c.name AS collector_name, e.received_at,
            e.summary_ciphertext, e.summary_iv, e.detail_key, e.detail_bytes,
            e.screenshot_key, e.screenshot_bytes, e.screenshot_mime,
            e.injection_key_hash, e.is_read
       FROM events e
       JOIN collectors c ON c.id = e.collector_id
      WHERE c.user_id = ?
        AND (? IS NULL OR e.collector_id = ?)
        AND (? IS NULL OR e.received_at < ? OR (e.received_at = ? AND e.id < ?))
      ORDER BY e.received_at DESC, e.id DESC
      LIMIT ?`,
  )
    .bind(
      session.userId,
      collectorId,
      collectorId,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.id ?? null,
      limit + 1,
    )
    .all<EventRow>();

  const page = result.results.slice(0, limit);
  const events = await Promise.all(page.map(async (row) => publicEvent(row, await decryptSummary(c.env, row))));
  const last = page.at(-1);
  const nextCursor = result.results.length > limit && last
    ? encodeCursor({ timestamp: Number(last.received_at), id: last.id })
    : null;
  return c.json({ events, nextCursor });
});

app.get('/export/events', async (c) => {
  const stepUp = await requireStepUp(c);
  if (stepUp) return stepUp;
  const session = c.get('session');
  const requestedCursor = c.req.query('cursor');
  const cursor = requestedCursor ? decodeCursor(requestedCursor, 'string') : null;
  if (requestedCursor && !cursor) return jsonError(c, 422, 'invalid_cursor', 'Invalid export cursor.');
  // One capture per response keeps AES-GCM, base64 encoding, and response size
  // inside the Free-plan CPU/memory envelope even at the 2 MiB capture cap.
  const batchSize = 1;

  const result = await c.env.DB.prepare(
    `SELECT e.id, e.collector_id, c.name AS collector_name, e.received_at,
            e.summary_ciphertext, e.summary_iv, e.detail_key, e.detail_bytes,
            e.screenshot_key, e.screenshot_bytes, e.screenshot_mime,
            e.injection_key_hash, e.is_read
       FROM events e
       JOIN collectors c ON c.id = e.collector_id
      WHERE c.user_id = ?
        AND (? IS NULL OR e.received_at < ? OR (e.received_at = ? AND e.id < ?))
      ORDER BY e.received_at DESC, e.id DESC
      LIMIT ?`,
  )
    .bind(
      session.userId,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.id ?? null,
      batchSize + 1,
    )
    .all<EventRow>();

  try {
    const page = result.results.slice(0, batchSize);
    const exportedEvents = await Promise.all(
      page.map(async (event) => {
        const detailObject = await c.env.VAULT.get(event.detail_key);
        if (!detailObject) throw new Error('Missing event detail');
        const detail = await openJson<unknown>(
          c.env,
          `event:${event.id}:detail`,
          unpackSealed(await detailObject.arrayBuffer()),
        );
        const summary = await decryptSummary(c.env, event);
        if (!summary) throw new Error('Invalid event summary');

        let screenshot: { mime: string; extension: string; data: string } | null = null;
        if (event.screenshot_key) {
          const imageObject = await c.env.VAULT.get(event.screenshot_key);
          if (!imageObject) throw new Error('Missing screenshot');
          const image = await openBytes(
            c.env,
            `event:${event.id}:screenshot`,
            unpackSealed(await imageObject.arrayBuffer()),
          );
          const detected = imageType(image);
          const recorded = normalizedImageMime(event.screenshot_mime);
          if (!detected || (recorded && recorded !== detected.mime)) throw new Error('Invalid screenshot');
          screenshot = { ...detected, data: bytesToBase64Url(image) };
        }

        let correlatedRequest: unknown = null;
        if (event.injection_key_hash) {
          const request = await c.env.DB.prepare(
            `SELECT ir.id, ir.request_ciphertext, ir.request_iv, ir.created_at
               FROM injection_requests ir
               JOIN collectors owned ON owned.id = ir.collector_id
              WHERE ir.collector_id = ? AND ir.injection_key_hash = ? AND owned.user_id = ?
              LIMIT 1`,
          )
            .bind(event.collector_id, event.injection_key_hash, session.userId)
            .first<InjectionRequestRow>();
          if (request) {
            correlatedRequest = await openJson<unknown>(c.env, `injection:${request.id}:request`, {
              ciphertext: request.request_ciphertext,
              iv: request.request_iv,
            });
          }
        }

        return {
          id: event.id,
          collectorId: event.collector_id,
          collectorName: event.collector_name,
          receivedAt: Number(event.received_at),
          isRead: event.is_read === 1,
          summary,
          detail,
          correlatedRequest,
          screenshot,
        };
      }),
    );

    let manifest: unknown = null;
    if (!cursor) {
      const collectors = await c.env.DB.prepare(
        `SELECT c.id, c.user_id, c.name, c.token_hash, c.token_ciphertext, c.token_iv,
                c.enabled, c.capture_cookies, c.capture_dom, c.capture_screenshot,
                c.capture_storage, c.discord_notifications, c.probe_checks,
                c.page_paths, c.chainload_url, c.created_at, c.updated_at,
                a.id AS alias_id, a.alias_ciphertext, a.alias_iv, a.created_at AS alias_created_at
           FROM collectors c
           LEFT JOIN collector_aliases a ON a.collector_id = c.id AND a.revoked_at IS NULL
          WHERE c.user_id = ? ORDER BY c.created_at ASC, c.id ASC`,
      )
        .bind(session.userId)
        .all<CollectorAdminRecord>();
      const publicOrigin = collectorOrigin(c.req.raw, c.env);
      manifest = {
        format: 'bxss-vault-plaintext-v1',
        warning: 'PLAINTEXT EXPORT - encrypt and protect this archive immediately',
        exportedAt: currentTime(),
        user: { id: session.userId, email: session.email, displayName: session.displayName },
        collectors: await Promise.all(
          collectors.results.map((collector) => decryptCollector(c.env, collector, publicOrigin)),
        ),
      };
    }

    const last = page.at(-1);
    const nextCursor = result.results.length > batchSize && last
      ? encodeCursor({ timestamp: Number(last.received_at), id: last.id })
      : null;
    await audit(c.req.raw, c.env, {
      userId: session.userId,
      action: 'vault.export.batch',
      targetType: 'event',
      metadata: { count: exportedEvents.length },
    });
    return c.json({ manifest, events: exportedEvents, nextCursor });
  } catch {
    await audit(c.req.raw, c.env, {
      userId: session.userId,
      action: 'vault.export.batch',
      targetType: 'event',
      result: 'error',
    }).catch(() => undefined);
    return jsonError(c, 500, 'export_failed', 'A capture could not be authenticated for export. Nothing was skipped.');
  }
});

app.get('/export/injections', async (c) => {
  const stepUp = await requireStepUp(c);
  if (stepUp) return stepUp;
  const session = c.get('session');
  const requestedCursor = c.req.query('cursor');
  const cursor = requestedCursor ? decodeCursor(requestedCursor, 'string') : null;
  if (requestedCursor && !cursor) return jsonError(c, 422, 'invalid_cursor', 'Invalid export cursor.');
  const batchSize = 25;
  const result = await c.env.DB.prepare(
    `SELECT ir.id, ir.collector_id, ir.injection_key_hash, ir.request_ciphertext,
            ir.request_iv, ir.created_at
       FROM injection_requests ir
       JOIN collectors c ON c.id = ir.collector_id
      WHERE c.user_id = ?
        AND (? IS NULL OR ir.created_at < ? OR (ir.created_at = ? AND ir.id < ?))
      ORDER BY ir.created_at DESC, ir.id DESC
      LIMIT ?`,
  )
    .bind(
      session.userId,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.id ?? null,
      batchSize + 1,
    )
    .all<{
      id: string;
      collector_id: string;
      injection_key_hash: string;
      request_ciphertext: string;
      request_iv: string;
      created_at: number;
    }>();
  try {
    const page = result.results.slice(0, batchSize);
    const requests = await Promise.all(
      page.map(async (request) => ({
        id: request.id,
        collectorId: request.collector_id,
        injectionKeyHash: request.injection_key_hash,
        createdAt: Number(request.created_at),
        data: await openJson<unknown>(c.env, `injection:${request.id}:request`, {
          ciphertext: request.request_ciphertext,
          iv: request.request_iv,
        }),
      })),
    );
    const last = page.at(-1);
    const nextCursor = result.results.length > batchSize && last
      ? encodeCursor({ timestamp: Number(last.created_at), id: last.id })
      : null;
    await audit(c.req.raw, c.env, {
      userId: session.userId,
      action: 'vault.export.injections',
      targetType: 'injection_request',
      metadata: { count: requests.length },
    });
    return c.json({ requests, nextCursor });
  } catch {
    return jsonError(c, 500, 'export_failed', 'An injection request could not be authenticated for export.');
  }
});

app.delete('/events', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const parsed = bulkDeleteSchema.safeParse(await parseJson(c.req.raw));
  if (!parsed.success) return jsonError(c, 422, 'invalid_input', 'Invalid bulk-delete request.');
  const session = c.get('session');
  const ids = parsed.data.ids ?? [];
  const placeholders = ids.map(() => '?').join(', ');
  const query = parsed.data.all
    ? `SELECT e.id, e.detail_key, e.detail_bytes, e.screenshot_key, e.screenshot_bytes
         FROM events e JOIN collectors c ON c.id = e.collector_id
        WHERE c.user_id = ? ORDER BY e.received_at ASC, e.id ASC LIMIT 20`
    : `SELECT e.id, e.detail_key, e.detail_bytes, e.screenshot_key, e.screenshot_bytes
         FROM events e JOIN collectors c ON c.id = e.collector_id
        WHERE c.user_id = ? AND e.id IN (${placeholders})`;
  const selected = await c.env.DB.prepare(query)
    .bind(session.userId, ...ids)
    .all<Pick<EventRow, 'id' | 'detail_key' | 'detail_bytes' | 'screenshot_key' | 'screenshot_bytes'>>();

  if (selected.results.length === 0) return c.json({ ok: true, deletedIds: [], remaining: false });
  const objectKeys = selected.results.flatMap((event) =>
    [event.detail_key, event.screenshot_key].filter((key): key is string => Boolean(key)),
  );
  try {
    if (objectKeys.length > 0) await c.env.VAULT.delete(objectKeys);
  } catch {
    return jsonError(c, 500, 'storage_delete_failed', 'Encrypted event objects could not be deleted.');
  }

  const now = currentTime();
  const statements: D1PreparedStatement[] = [];
  for (const event of selected.results) {
    const bytes = Math.max(0, Number(event.detail_bytes)) + Math.max(0, Number(event.screenshot_bytes));
    statements.push(
      c.env.DB.prepare(
        `DELETE FROM events
          WHERE id = ? AND collector_id IN (SELECT id FROM collectors WHERE user_id = ?)`,
      ).bind(event.id, session.userId),
      c.env.DB.prepare(
        `UPDATE app_state
            SET storage_bytes = MAX(0, storage_bytes - (? * changes())),
                event_count = MAX(0, event_count - changes()), updated_at = ?
          WHERE id = 1`,
      ).bind(bytes, now),
    );
  }
  const results = await c.env.DB.batch(statements);
  const deletedIds = selected.results
    .filter((_, index) => changes(results[index * 2]) === 1)
    .map((event) => event.id);
  const remaining = parsed.data.all
    ? Boolean(
        await c.env.DB.prepare(
          `SELECT 1 AS present FROM events e JOIN collectors c ON c.id = e.collector_id
            WHERE c.user_id = ? LIMIT 1`,
        )
          .bind(session.userId)
          .first<{ present: number }>(),
      )
    : false;
  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: parsed.data.all ? 'event.delete_all.batch' : 'event.delete_bulk',
    targetType: 'event',
    metadata: { count: deletedIds.length },
  }).catch(() => undefined);
  return c.json({ ok: true, deletedIds, remaining });
});

app.get('/events/:id', async (c) => {
  const stepUp = await requireStepUp(c);
  if (stepUp) return stepUp;
  const session = c.get('session');
  const event = await ownedEvent(c.env, session.userId, c.req.param('id'));
  if (!event) return jsonError(c, 404, 'event_not_found', 'Event not found.');

  const object = await c.env.VAULT.get(event.detail_key);
  if (!object) return jsonError(c, 404, 'event_data_missing', 'Event data is unavailable.');

  let detail: CapturedEvent;
  try {
    detail = await openJson<CapturedEvent>(
      c.env,
      `event:${event.id}:detail`,
      unpackSealed(await object.arrayBuffer()),
    );
  } catch {
    await audit(c.req.raw, c.env, {
      userId: session.userId,
      action: 'event.view',
      targetType: 'event',
      targetId: event.id,
      result: 'error',
    }).catch(() => undefined);
    return jsonError(c, 500, 'event_data_invalid', 'Event data could not be authenticated.');
  }

  let correlatedRequest: unknown = null;
  if (event.injection_key_hash) {
    const request = await c.env.DB.prepare(
      `SELECT ir.id, ir.request_ciphertext, ir.request_iv, ir.created_at
         FROM injection_requests ir
         JOIN collectors c ON c.id = ir.collector_id
        WHERE ir.collector_id = ? AND ir.injection_key_hash = ? AND c.user_id = ?
        LIMIT 1`,
    )
      .bind(event.collector_id, event.injection_key_hash, session.userId)
      .first<InjectionRequestRow>();
    if (request) {
      try {
        correlatedRequest = await openJson<unknown>(c.env, `injection:${request.id}:request`, {
          ciphertext: request.request_ciphertext,
          iv: request.request_iv,
        });
      } catch {
        correlatedRequest = null;
      }
    }
  }

  const summary = await decryptSummary(c.env, event);
  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'event.view',
    targetType: 'event',
    targetId: event.id,
  }).catch(() => undefined);
  return c.json({ event: { ...publicEvent(event, summary), detail, correlatedRequest } });
});

app.get('/events/:id/screenshot', async (c) => {
  const stepUp = await requireStepUp(c);
  if (stepUp) return stepUp;
  const session = c.get('session');
  const event = await ownedEvent(c.env, session.userId, c.req.param('id'));
  if (!event || !event.screenshot_key) return jsonError(c, 404, 'screenshot_not_found', 'Screenshot not found.');

  const object = await c.env.VAULT.get(event.screenshot_key);
  if (!object) return jsonError(c, 404, 'screenshot_not_found', 'Screenshot not found.');
  let image: Uint8Array;
  try {
    image = await openBytes(c.env, `event:${event.id}:screenshot`, unpackSealed(await object.arrayBuffer()));
  } catch {
    return jsonError(c, 500, 'screenshot_invalid', 'Screenshot could not be authenticated.');
  }

  const detected = imageType(image);
  const recordedMime = normalizedImageMime(event.screenshot_mime);
  if (!detected || (recordedMime && recordedMime !== detected.mime)) {
    await audit(c.req.raw, c.env, {
      userId: session.userId,
      action: 'event.screenshot.view',
      targetType: 'event',
      targetId: event.id,
      result: 'error',
    }).catch(() => undefined);
    return jsonError(c, 500, 'screenshot_invalid', 'Screenshot has an invalid image format.');
  }

  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'event.screenshot.view',
    targetType: 'event',
    targetId: event.id,
  }).catch(() => undefined);
  return new Response(image as BodyInit, {
    status: 200,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Disposition': `inline; filename="event-${event.id}.${detected.extension}"`,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Content-Type': detected.mime,
      'X-Content-Type-Options': 'nosniff',
    },
  });
});

app.post('/events/:id/read', async (c) => {
  const rejected = await mutationChecks(c, false);
  if (rejected) return rejected;
  const body = readEventSchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'Invalid read state.');
  const session = c.get('session');
  const result = await c.env.DB.prepare(
    `UPDATE events
        SET is_read = ?
      WHERE id = ?
        AND collector_id IN (SELECT id FROM collectors WHERE user_id = ?)`,
  )
    .bind(body.data.read ? 1 : 0, c.req.param('id'), session.userId)
    .run();
  if (changes(result) !== 1) return jsonError(c, 404, 'event_not_found', 'Event not found.');
  return c.json({ ok: true, isRead: body.data.read });
});

app.delete('/events/:id', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const event = await ownedEvent(c.env, session.userId, c.req.param('id'));
  if (!event) return jsonError(c, 404, 'event_not_found', 'Event not found.');

  const objectKeys = [event.detail_key, event.screenshot_key].filter((key): key is string => Boolean(key));
  try {
    await c.env.VAULT.delete(objectKeys);
  } catch {
    return jsonError(c, 500, 'storage_delete_failed', 'Encrypted event objects could not be deleted.');
  }

  const bytes = Math.max(0, Number(event.detail_bytes)) + Math.max(0, Number(event.screenshot_bytes));
  const results = await c.env.DB.batch([
    c.env.DB.prepare(
      `DELETE FROM events
        WHERE id = ?
          AND collector_id IN (SELECT id FROM collectors WHERE user_id = ?)`,
    ).bind(event.id, session.userId),
    c.env.DB.prepare(
      `UPDATE app_state
          SET storage_bytes = MAX(0, storage_bytes - (? * changes())),
              event_count = MAX(0, event_count - changes()),
              updated_at = ?
        WHERE id = 1
          AND EXISTS (SELECT 1 FROM users WHERE id = ?)`,
    ).bind(bytes, currentTime(), session.userId),
  ]);
  if (changes(results[0]) !== 1) return jsonError(c, 404, 'event_not_found', 'Event not found.');

  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'event.delete',
    targetType: 'event',
    targetId: event.id,
    metadata: { bytes },
  }).catch(() => undefined);
  return c.json({ ok: true });
});

app.post('/collectors', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = collectorCreateSchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'A collector name is required.');
  const session = c.get('session');
  const existing = await c.env.DB.prepare('SELECT COUNT(*) AS count FROM collectors WHERE user_id = ?')
    .bind(session.userId)
    .first<{ count: number }>();
  if (Number(existing?.count ?? 0) >= 100) {
    return jsonError(c, 409, 'collector_limit', 'This vault already has the maximum of 100 collectors.');
  }

  const id = randomId();
  const token = randomToken();
  const createdAt = currentTime();
  const sealed = await sealJson(c.env, `collector:${id}:token`, token);
  const result = await c.env.DB.prepare(
    `INSERT INTO collectors
      (id, user_id, name, token_hash, token_ciphertext, token_iv, capture_screenshot, created_at, updated_at)
     SELECT ?, id, ?, ?, ?, ?, 0, ?, ?
       FROM users
      WHERE id = ? AND enabled = 1
        AND (SELECT COUNT(*) FROM collectors WHERE user_id = ?) < 100`,
  )
    .bind(
      id,
      body.data.name,
      await keyedHash(c.env, 'collector-token', token),
      sealed.ciphertext,
      sealed.iv,
      createdAt,
      createdAt,
      session.userId,
      session.userId,
    )
    .run();
  if (changes(result) !== 1) {
    return jsonError(c, 409, 'collector_limit', 'This vault already has the maximum of 100 collectors.');
  }

  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'collector.create',
    targetType: 'collector',
    targetId: id,
  }).catch(() => undefined);
  const collector = await ownedCollectorAdmin(c.env, session.userId, id);
  if (!collector) return jsonError(c, 500, 'collector_create_failed', 'The collector could not be loaded.');
  return c.json(
    { collector: await decryptCollector(c.env, collector, collectorOrigin(c.req.raw, c.env)) },
    201,
  );
});

app.get('/collectors', async (c) => {
  const stepUp = await requireStepUp(c);
  if (stepUp) return stepUp;
  const session = c.get('session');
  const result = await c.env.DB.prepare(
    `SELECT c.id, c.user_id, c.name, c.token_hash, c.token_ciphertext, c.token_iv,
            c.enabled, c.capture_cookies, c.capture_dom, c.capture_screenshot,
            c.capture_storage, c.discord_notifications, c.probe_checks,
            c.page_paths, c.chainload_url, c.created_at, c.updated_at,
            a.id AS alias_id, a.alias_ciphertext, a.alias_iv, a.created_at AS alias_created_at
       FROM collectors c
       LEFT JOIN collector_aliases a ON a.collector_id = c.id AND a.revoked_at IS NULL
      WHERE c.user_id = ?
      ORDER BY c.created_at ASC, c.id ASC`,
  )
    .bind(session.userId)
    .all<CollectorAdminRecord>();
  try {
    const publicOrigin = collectorOrigin(c.req.raw, c.env);
    return c.json({
      collectors: await Promise.all(
        result.results.map((collector) => decryptCollector(c.env, collector, publicOrigin)),
      ),
    });
  } catch {
    return jsonError(c, 500, 'collector_token_invalid', 'A collector token could not be authenticated.');
  }
});

app.patch('/collectors/:id', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = collectorUpdateSchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'Invalid collector settings.');
  if (body.data.discordNotifications === true && !discordWebhookConfigured(c.env)) {
    return jsonError(c, 409, 'discord_not_configured', 'Configure the Discord webhook secret before enabling notifications.');
  }
  const session = c.get('session');
  const collector = await ownedCollector(c.env, session.userId, c.req.param('id'));
  if (!collector) return jsonError(c, 404, 'collector_not_found', 'Collector not found.');

  const updatedAt = currentTime();
  const updated = {
    name: body.data.name ?? collector.name,
    enabled: body.data.enabled ?? collector.enabled === 1,
    captureCookies: body.data.captureCookies ?? collector.capture_cookies === 1,
    captureDom: body.data.captureDom ?? collector.capture_dom === 1,
    captureScreenshot: body.data.captureScreenshot ?? collector.capture_screenshot === 1,
    captureStorage: body.data.captureStorage ?? collector.capture_storage === 1,
    discordNotifications: body.data.discordNotifications ?? collector.discord_notifications === 1,
    probeChecks: body.data.probeChecks ?? collector.probe_checks === 1,
    pagePaths: body.data.pagePaths ?? validPagePaths(safeJsonParse<unknown>(collector.page_paths, [])),
    chainloadUrl:
      body.data.chainloadUrl === undefined
        ? collector.chainload_url
        : body.data.chainloadUrl === ''
          ? null
          : body.data.chainloadUrl,
  };

  const result = await c.env.DB.prepare(
    `UPDATE collectors
        SET name = ?, enabled = ?, capture_cookies = ?, capture_dom = ?,
            capture_screenshot = ?, capture_storage = ?, discord_notifications = ?,
            probe_checks = ?, page_paths = ?, chainload_url = ?, updated_at = ?
      WHERE id = ? AND user_id = ?`,
  )
    .bind(
      updated.name,
      updated.enabled ? 1 : 0,
      updated.captureCookies ? 1 : 0,
      updated.captureDom ? 1 : 0,
      updated.captureScreenshot ? 1 : 0,
      updated.captureStorage ? 1 : 0,
      updated.discordNotifications ? 1 : 0,
      updated.probeChecks ? 1 : 0,
      JSON.stringify(updated.pagePaths),
      updated.chainloadUrl,
      updatedAt,
      collector.id,
      session.userId,
    )
    .run();
  if (changes(result) !== 1) return jsonError(c, 404, 'collector_not_found', 'Collector not found.');

  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'collector.update',
    targetType: 'collector',
    targetId: collector.id,
  }).catch(() => undefined);
  const refreshed = await ownedCollectorAdmin(c.env, session.userId, collector.id);
  if (!refreshed) return jsonError(c, 404, 'collector_not_found', 'Collector not found.');
  try {
    return c.json({
      ok: true,
      collector: await decryptCollector(c.env, refreshed, collectorOrigin(c.req.raw, c.env)),
    });
  } catch {
    return jsonError(c, 500, 'collector_token_invalid', 'The collector token could not be authenticated.');
  }
});

app.post('/collectors/:id/discord/test', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const collector = await ownedCollector(c.env, session.userId, c.req.param('id'));
  if (!collector) return jsonError(c, 404, 'collector_not_found', 'Collector not found.');
  if (!discordWebhookConfigured(c.env)) {
    return jsonError(c, 409, 'discord_not_configured', 'The Discord webhook secret is not configured.');
  }
  const sent = await sendDiscordTestNotification(c.env, collector.name);
  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'discord.notification.test',
    targetType: 'collector',
    targetId: collector.id,
    result: sent ? 'success' : 'error',
  }).catch(() => undefined);
  if (!sent) return jsonError(c, 500, 'discord_delivery_failed', 'Discord rejected or did not receive the test notification.');
  return c.json({ ok: true });
});

app.post('/collectors/:id/rotate', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const collectorId = c.req.param('id');
  const token = randomToken();
  const sealed = await sealJson(c.env, `collector:${collectorId}:token`, token);
  const result = await c.env.DB.prepare(
    `UPDATE collectors
        SET token_hash = ?, token_ciphertext = ?, token_iv = ?, updated_at = ?
      WHERE id = ? AND user_id = ?`,
  )
    .bind(
      await keyedHash(c.env, 'collector-token', token),
      sealed.ciphertext,
      sealed.iv,
      currentTime(),
      collectorId,
      session.userId,
    )
    .run();
  if (changes(result) !== 1) return jsonError(c, 404, 'collector_not_found', 'Collector not found.');

  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'collector.token.rotate',
    targetType: 'collector',
    targetId: collectorId,
  }).catch(() => undefined);
  return c.json({ ok: true, token });
});

app.post('/collectors/:id/alias/rotate', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const collectorId = c.req.param('id');
  if (!(await ownedCollector(c.env, session.userId, collectorId))) {
    return jsonError(c, 404, 'collector_not_found', 'Collector not found.');
  }

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const alias = createCollectorAlias();
    const aliasId = randomId();
    const createdAt = currentTime();
    const sealed = await sealJson(c.env, `collector:${collectorId}:alias:${aliasId}`, alias);
    try {
      const results = await c.env.DB.batch([
        c.env.DB.prepare(
          `UPDATE collector_aliases
              SET alias_ciphertext = NULL, alias_iv = NULL, revoked_at = ?
            WHERE collector_id IN (
                    SELECT id FROM collectors WHERE id = ? AND user_id = ?
                  )
              AND revoked_at IS NULL`,
        ).bind(createdAt, collectorId, session.userId),
        c.env.DB.prepare(
          `INSERT INTO collector_aliases
            (id, collector_id, alias_hash, alias_ciphertext, alias_iv, created_at)
           SELECT ?, id, ?, ?, ?, ?
             FROM collectors
            WHERE id = ? AND user_id = ?`,
        ).bind(
          aliasId,
          await keyedHash(c.env, 'collector-alias', alias),
          sealed.ciphertext,
          sealed.iv,
          createdAt,
          collectorId,
          session.userId,
        ),
      ]);
      if (changes(results[1]) !== 1) {
        return jsonError(c, 404, 'collector_not_found', 'Collector not found.');
      }
      const publicOrigin = collectorOrigin(c.req.raw, c.env);
      await audit(c.req.raw, c.env, {
        userId: session.userId,
        action: 'collector.alias.rotate',
        targetType: 'collector',
        targetId: collectorId,
        metadata: { aliasId },
      }).catch(() => undefined);
      return c.json({
        ok: true,
        alias,
        aliasLoaderUrl: `${publicOrigin}/a/${encodeURIComponent(alias)}.js`,
        aliasCreatedAt: createdAt,
      });
    } catch (error) {
      if (attempt < 2 && isAliasUniquenessConflict(error)) continue;
      throw error;
    }
  }
  return jsonError(c, 500, 'alias_rotation_failed', 'Collector alias rotation failed.');
});

app.post('/collectors/:id/alias/revoke', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const collectorId = c.req.param('id');
  if (!(await ownedCollector(c.env, session.userId, collectorId))) {
    return jsonError(c, 404, 'collector_not_found', 'Collector not found.');
  }
  const revokedAt = currentTime();
  const result = await c.env.DB.prepare(
    `UPDATE collector_aliases
        SET alias_ciphertext = NULL, alias_iv = NULL, revoked_at = ?
      WHERE collector_id IN (
              SELECT id FROM collectors WHERE id = ? AND user_id = ?
            )
        AND revoked_at IS NULL`,
  )
    .bind(revokedAt, collectorId, session.userId)
    .run();
  const revoked = changes(result) === 1;
  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'collector.alias.revoke',
    targetType: 'collector',
    targetId: collectorId,
    metadata: { revoked },
  }).catch(() => undefined);
  return c.json({ ok: true, revoked });
});

app.get('/passkeys', async (c) => {
  const session = c.get('session');
  const result = await c.env.DB.prepare(
    `SELECT id, name, device_type, backed_up, created_at, last_used_at
       FROM passkeys
      WHERE user_id = ?
      ORDER BY created_at ASC, id ASC`,
  )
    .bind(session.userId)
    .all<{
      id: string;
      name: string;
      device_type: string;
      backed_up: number;
      created_at: number;
      last_used_at: number | null;
    }>();
  return c.json({
    passkeys: result.results.map((passkey) => ({
      id: passkey.id,
      name: passkey.name,
      deviceType: passkey.device_type,
      backedUp: passkey.backed_up === 1,
      createdAt: Number(passkey.created_at),
      lastUsedAt: passkey.last_used_at === null ? null : Number(passkey.last_used_at),
    })),
  });
});

app.delete('/passkeys/:id', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const passkeyId = c.req.param('id');
  const result = await c.env.DB.prepare(
    `DELETE FROM passkeys
      WHERE id = ? AND user_id = ?
        AND (SELECT COUNT(*) FROM passkeys WHERE user_id = ?) > 1`,
  )
    .bind(passkeyId, session.userId, session.userId)
    .run();
  if (changes(result) !== 1) {
    const state = await c.env.DB.prepare(
      `SELECT COUNT(*) AS key_count,
              COALESCE(MAX(CASE WHEN id = ? THEN 1 ELSE 0 END), 0) AS target_exists
         FROM passkeys
        WHERE user_id = ?`,
    )
      .bind(passkeyId, session.userId)
      .first<{ key_count: number; target_exists: number }>();
    if (Number(state?.target_exists ?? 0) === 1 && Number(state?.key_count ?? 0) <= 1) {
      return jsonError(c, 409, 'last_passkey', 'The final passkey cannot be deleted.');
    }
    return jsonError(c, 404, 'passkey_not_found', 'Passkey not found.');
  }

  // A credential-set change invalidates every other browser session. Keep the
  // step-up-authenticated session so the administrator is not locked out.
  await c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?')
    .bind(session.userId, session.tokenHash)
    .run();

  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'passkey.delete',
    targetType: 'passkey',
    targetId: passkeyId,
  }).catch(() => undefined);
  return c.json({ ok: true });
});

app.post('/recovery-codes/rotate', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const recovery = await prepareRecoveryCodes(c.env, session.userId);
  await c.env.DB.batch([
    ...recovery.statements,
    c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').bind(
      session.userId,
      session.tokenHash,
    ),
  ]);
  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'recovery_codes.rotate',
    targetType: 'user',
    targetId: session.userId,
  }).catch(() => undefined);
  return c.json({ ok: true, recoveryCodes: recovery.codes });
});

app.post('/injection-token/rotate', async (c) => {
  const rejected = await mutationChecks(c, true);
  if (rejected) return rejected;
  const body = emptyBodySchema.safeParse(await parseJson(c.req.raw));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'An empty JSON object is required.');
  const session = c.get('session');
  const token = `bxi_${randomToken()}`;
  const tokenId = randomId();
  const createdAt = currentTime();
  await c.env.DB.batch([
    c.env.DB.prepare(
      `UPDATE api_tokens
          SET revoked_at = ?
        WHERE user_id = ? AND scope = ? AND revoked_at IS NULL`,
    ).bind(createdAt, session.userId, 'injection:write'),
    c.env.DB.prepare(
      `INSERT INTO api_tokens
        (id, user_id, name, token_hash, scope, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      tokenId,
      session.userId,
      'Injection API',
      await keyedHash(c.env, 'injection-api-token', token),
      'injection:write',
      createdAt,
    ),
  ]);
  await audit(c.req.raw, c.env, {
    userId: session.userId,
    action: 'api_token.rotate',
    targetType: 'api_token',
    targetId: tokenId,
  }).catch(() => undefined);
  return c.json({ ok: true, token, createdAt });
});

app.get('/audit', async (c) => {
  const session = c.get('session');
  const limit = listLimit(c.req.query('limit'));
  if (!limit) return jsonError(c, 422, 'invalid_pagination', 'Invalid pagination parameters.');
  const requestedCursor = c.req.query('cursor');
  const cursor = requestedCursor ? decodeCursor(requestedCursor, 'number') : null;
  if (requestedCursor && !cursor) return jsonError(c, 422, 'invalid_cursor', 'Invalid pagination cursor.');

  const result = await c.env.DB.prepare(
    `SELECT id, action, target_type, target_id, result, request_id, metadata_json, created_at
       FROM audit_log
      WHERE user_id = ?
        AND (? IS NULL OR created_at < ? OR (created_at = ? AND id < ?))
      ORDER BY created_at DESC, id DESC
      LIMIT ?`,
  )
    .bind(
      session.userId,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.timestamp ?? null,
      cursor?.id ?? null,
      limit + 1,
    )
    .all<AuditRow>();
  const page = result.results.slice(0, limit);
  const entries = page.map((entry) => ({
    id: Number(entry.id),
    action: entry.action,
    targetType: entry.target_type,
    targetId: entry.target_id,
    result: entry.result,
    requestId: entry.request_id,
    metadata: safeJsonParse<unknown>(entry.metadata_json, {}),
    createdAt: Number(entry.created_at),
  }));
  const last = page.at(-1);
  const nextCursor = result.results.length > limit && last
    ? encodeCursor({ timestamp: Number(last.created_at), id: Number(last.id) })
    : null;
  return c.json({ entries, nextCursor });
});

app.get('/stats', async (c) => {
  const session = c.get('session');
  const today = new Date().toISOString().slice(0, 10);
  const stats = await c.env.DB.prepare(
    `SELECT
       (SELECT COUNT(*)
          FROM events e JOIN collectors c ON c.id = e.collector_id
         WHERE c.user_id = ?) AS event_count,
       (SELECT COUNT(*)
          FROM events e JOIN collectors c ON c.id = e.collector_id
         WHERE c.user_id = ? AND e.is_read = 0) AS unread_count,
       (SELECT COALESCE(SUM(MAX(0, e.detail_bytes) + MAX(0, e.screenshot_bytes)), 0)
          FROM events e JOIN collectors c ON c.id = e.collector_id
         WHERE c.user_id = ?) AS storage_bytes,
       (SELECT COUNT(*) FROM collectors WHERE user_id = ?) AS collector_count,
       (SELECT COUNT(*) FROM passkeys WHERE user_id = ?) AS passkey_count,
       (SELECT COUNT(*)
          FROM events e JOIN collectors c ON c.id = e.collector_id
         WHERE c.user_id = ? AND e.created_day = ?) AS events_today`,
  )
    .bind(
      session.userId,
      session.userId,
      session.userId,
      session.userId,
      session.userId,
      session.userId,
      today,
    )
    .first<{
      event_count: number;
      unread_count: number;
      storage_bytes: number;
      collector_count: number;
      passkey_count: number;
      events_today: number;
    }>();

  return c.json({
    stats: {
      eventCount: Number(stats?.event_count ?? 0),
      unreadCount: Number(stats?.unread_count ?? 0),
      storageBytes: Number(stats?.storage_bytes ?? 0),
      storageLimitBytes: intSetting(c.env.MAX_STORAGE_BYTES, 8_053_063_680, 1_048_576, 1_000_000_000_000),
      collectorCount: Number(stats?.collector_count ?? 0),
      passkeyCount: Number(stats?.passkey_count ?? 0),
      eventsToday: Number(stats?.events_today ?? 0),
      retentionDays: intSetting(c.env.RETENTION_DAYS, 30, 1, 365),
    },
  });
});

export default app;
