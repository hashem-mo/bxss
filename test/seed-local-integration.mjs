import { createCipheriv, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const vars = Object.fromEntries(
  (await readFile(new URL('../.dev.vars', import.meta.url), 'utf8'))
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const separator = line.indexOf('=');
      return [line.slice(0, separator), line.slice(separator + 1)];
    }),
);

for (const name of ['AUTH_PEPPER', 'DATA_ENCRYPTION_KEY']) {
  if (!vars[name]) throw new Error(`${name} is missing from .dev.vars`);
}

const sqlValue = (value) => `'${String(value).replaceAll("'", "''")}'`;
const token = () => randomBytes(32).toString('base64url');
const keyedHash = (namespace, value) =>
  createHmac('sha256', Buffer.from(vars.AUTH_PEPPER, 'base64url'))
    .update(`${namespace}\0${value}`)
    .digest('base64url');
const sealJson = (context, value) => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(vars.DATA_ENCRYPTION_KEY, 'base64url'), iv);
  cipher.setAAD(Buffer.from(`bxss-vault:v1:${context}`));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { ciphertext: encrypted.toString('base64url'), iv: iv.toString('base64url') };
};

const current = Math.floor(Date.now() / 1_000);
const userId = randomUUID();
const collectorId = randomUUID();
const collectorToken = token();
const injectionToken = `bxi_${token()}`;
const sessionToken = token();
const csrf = token();
const userAgent = 'bxss-local-integration/1.0';
const collectorSecret = sealJson(`collector:${collectorId}:token`, collectorToken);

const sql = `
DELETE FROM audit_log;
DELETE FROM events;
DELETE FROM injection_requests;
DELETE FROM api_tokens;
DELETE FROM recovery_codes;
DELETE FROM sessions;
DELETE FROM auth_challenges;
DELETE FROM passkeys;
DELETE FROM collector_aliases;
DELETE FROM collectors;
DELETE FROM users;
UPDATE app_state SET storage_bytes = 0, event_count = 0, updated_at = ${current} WHERE id = 1;
INSERT INTO users
  (id, email, display_name, webauthn_user_id, role, enabled, session_version, created_at, updated_at)
VALUES
  (${sqlValue(userId)}, 'integration@example.invalid', 'Integration Owner', ${sqlValue(token())}, 'owner', 1, 1, ${current}, ${current});
INSERT INTO collectors
  (id, user_id, name, token_hash, token_ciphertext, token_iv, enabled, capture_cookies,
   capture_dom, capture_screenshot, capture_storage, probe_checks, page_paths, created_at, updated_at)
VALUES
  (${sqlValue(collectorId)}, ${sqlValue(userId)}, 'Integration collector',
   ${sqlValue(keyedHash('collector-token', collectorToken))}, ${sqlValue(collectorSecret.ciphertext)},
   ${sqlValue(collectorSecret.iv)}, 1, 1, 1, 1, 1, 0, '[]', ${current}, ${current});
INSERT INTO sessions
  (token_hash, user_id, csrf_token, user_agent_hash, session_version, created_at,
   last_seen_at, expires_at, step_up_until)
VALUES
  (${sqlValue(keyedHash('session', sessionToken))}, ${sqlValue(userId)}, ${sqlValue(csrf)},
   ${sqlValue(keyedHash('user-agent', userAgent))}, 1, ${current}, ${current}, ${current + 3600}, ${current + 600});
INSERT INTO api_tokens
  (id, user_id, name, token_hash, scope, created_at)
VALUES
  (${sqlValue(randomUUID())}, ${sqlValue(userId)}, 'Integration injection API',
   ${sqlValue(keyedHash('injection-api-token', injectionToken))}, 'injection:write', ${current});
`;

const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
const executed = spawnSync(process.execPath, [wrangler, 'd1', 'execute', 'DB', '--local', '--command', sql], {
  cwd: new URL('..', import.meta.url),
  encoding: 'utf8',
  windowsHide: true,
});
if (executed.status !== 0) {
  process.stderr.write(executed.stdout ?? '');
  process.stderr.write(executed.stderr ?? '');
  throw new Error('Local D1 integration seed failed');
}

await writeFile(
  new URL('./.integration-secrets.json', import.meta.url),
  JSON.stringify({ userId, collectorId, collectorToken, injectionToken, sessionToken, csrf, userAgent }, null, 2),
  { encoding: 'utf8', mode: 0o600 },
);
console.log('Seeded isolated local integration fixtures.');
