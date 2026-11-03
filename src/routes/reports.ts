import type { Context } from 'hono';
import { Hono } from 'hono';
import { keyedHash, openBytes, openJson, unpackSealed } from '../lib/crypto';
import { jsonError, REPORT_PAGE_CSP } from '../lib/http';
import {
  detectImageType,
  emptyReportHtml,
  isReportToken,
  renderReportHtml,
  type SharedReportPayload,
} from '../lib/reports';
import type { Env, Variables } from '../types';

type ReportContext = Context<{ Bindings: Env; Variables: Variables }>;

interface SharedReportRow {
  id: string;
  payload_key: string;
  expires_at: number;
  revoked_at: number | null;
}

const app = new Hono<{ Bindings: Env; Variables: Variables }>();
const currentTime = (): number => Math.floor(Date.now() / 1000);

function reportUnavailable(c: ReportContext, status: 404 | 429 = 404): Response {
  return c.html(emptyReportHtml(status === 429 ? 'Too many requests.' : 'This report link is invalid, expired, or revoked.'), status);
}

async function loadActiveReport(
  c: ReportContext,
  token: string,
): Promise<{ row: SharedReportRow; token: string } | Response> {
  if (!isReportToken(token)) return reportUnavailable(c);
  const tokenHash = await keyedHash(c.env, 'shared-report', token);
  const allowed = await c.env.COLLECTOR_RATE_LIMITER.limit({ key: `report:${tokenHash}` });
  if (!allowed.success) return reportUnavailable(c, 429);
  const row = await c.env.DB.prepare(
    `SELECT id, payload_key, expires_at, revoked_at
       FROM shared_reports
      WHERE token_hash = ?`,
  )
    .bind(tokenHash)
    .first<SharedReportRow>();
  const now = currentTime();
  if (!row || row.revoked_at !== null || Number(row.expires_at) <= now) return reportUnavailable(c);
  return { row, token };
}

function touchLastViewed(c: ReportContext, reportId: string): void {
  const now = currentTime();
  c.executionCtx.waitUntil(
    c.env.DB.prepare(
      `UPDATE shared_reports
          SET last_viewed_at = ?
        WHERE id = ?
          AND revoked_at IS NULL
          AND (last_viewed_at IS NULL OR last_viewed_at <= ?)`,
    )
      .bind(now, reportId, now - 60)
      .run()
      .then(() => undefined),
  );
}

app.get('/r/:token/s/:eventId', async (c) => {
  const loaded = await loadActiveReport(c, c.req.param('token'));
  if (loaded instanceof Response) return loaded;
  const eventId = c.req.param('eventId');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(eventId)) {
    return jsonError(c, 404, 'not_found', 'Not found.');
  }

  const object = await c.env.VAULT.get(`reports/${loaded.row.id}/shots/${eventId}.bin`);
  if (!object) return jsonError(c, 404, 'not_found', 'Not found.');

  let image: Uint8Array;
  try {
    image = await openBytes(
      c.env,
      `report:${loaded.row.id}:screenshot:${eventId}`,
      unpackSealed(await object.arrayBuffer()),
    );
  } catch {
    return jsonError(c, 404, 'not_found', 'Not found.');
  }

  const detected = detectImageType(image);
  if (!detected) return jsonError(c, 404, 'not_found', 'Not found.');
  touchLastViewed(c, loaded.row.id);
  return new Response(image as BodyInit, {
    status: 200,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Disposition': `inline; filename="capture-${eventId}.${detected.extension}"`,
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Content-Type': detected.mime,
      'X-Content-Type-Options': 'nosniff',
    },
  });
});

app.get('/r/:token', async (c) => {
  const loaded = await loadActiveReport(c, c.req.param('token'));
  if (loaded instanceof Response) return loaded;

  const object = await c.env.VAULT.get(loaded.row.payload_key);
  if (!object) return reportUnavailable(c);

  let payload: SharedReportPayload;
  try {
    payload = await openJson<SharedReportPayload>(
      c.env,
      `report:${loaded.row.id}:payload`,
      unpackSealed(await object.arrayBuffer()),
    );
  } catch {
    return reportUnavailable(c);
  }
  if (payload.schemaVersion !== 1 || payload.id !== loaded.row.id || !Array.isArray(payload.events)) {
    return reportUnavailable(c);
  }

  touchLastViewed(c, loaded.row.id);
  return c.html(renderReportHtml(payload, loaded.token), 200, {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': REPORT_PAGE_CSP,
  });
});

export default app;
