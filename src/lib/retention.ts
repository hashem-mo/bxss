import type { Env } from '../types';
import { intSetting } from './http';

interface ExpiredEventRow {
  id: string;
  detail_key: string;
  detail_bytes: number;
  screenshot_key: string | null;
  screenshot_bytes: number;
}

const BATCH_SIZE = 20;

function changes(result: D1Result<unknown>): number {
  return Number(result.meta?.changes ?? 0);
}

/**
 * Delete one bounded batch on each cron invocation. The five-minute schedule
 * drains more than the maximum configured daily ingest rate without risking
 * the Workers/D1 per-invocation subrequest and query limits.
 */
export async function runRetention(env: Env): Promise<void> {
  const now = Math.floor(Date.now() / 1_000);
  const retentionDays = intSetting(env.RETENTION_DAYS, 30, 1, 365);
  const cutoff = now - retentionDays * 86_400;
  const expired = await env.DB.prepare(
    `SELECT id, detail_key, detail_bytes, screenshot_key, screenshot_bytes
       FROM events
      WHERE received_at < ?
      ORDER BY received_at ASC, id ASC
      LIMIT ?`,
  )
    .bind(cutoff, BATCH_SIZE)
    .all<ExpiredEventRow>();

  if (expired.results.length > 0) {
    const keys = expired.results.flatMap((event) =>
      [event.detail_key, event.screenshot_key].filter((key): key is string => Boolean(key)),
    );

    // R2 deletion is idempotent. Database rows are retained if object deletion
    // fails, allowing the next scheduled run to safely retry.
    if (keys.length > 0) await env.VAULT.delete(keys);

    const statements: D1PreparedStatement[] = [];
    for (const event of expired.results) {
      const bytes = Math.max(0, Number(event.detail_bytes)) + Math.max(0, Number(event.screenshot_bytes));
      statements.push(
        env.DB.prepare('DELETE FROM events WHERE id = ?').bind(event.id),
        env.DB.prepare(
          `UPDATE app_state
              SET storage_bytes = MAX(0, storage_bytes - (? * changes())),
                  event_count = MAX(0, event_count - changes()),
                  updated_at = ?
            WHERE id = 1`,
        ).bind(bytes, now),
      );
    }
    const results = await env.DB.batch(statements);
    const deleted = results.filter((_, index) => index % 2 === 0).reduce((count, result) => count + changes(result), 0);

    if (deleted > 0) {
      await env.DB.prepare(
        `INSERT INTO audit_log
          (user_id, action, target_type, target_id, result, metadata_json, created_at)
         VALUES (NULL, 'retention.sweep', 'event', NULL, 'success', ?, ?)`,
      )
        .bind(JSON.stringify({ deleted }), now)
        .run();
    }
  }

  // Authentication artifacts and encrypted unmatched requests must not live
  // forever either. These deletes are bounded by indexed timestamps.
  await env.DB.batch([
    env.DB.prepare('DELETE FROM auth_challenges WHERE expires_at < ?').bind(now),
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
    env.DB.prepare('DELETE FROM injection_requests WHERE created_at < ?').bind(cutoff),
  ]);
}
