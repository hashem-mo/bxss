import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { Hono } from 'hono';
import { z } from 'zod';
import type { Env, Variables } from '../types';
import {
  audit,
  authenticationOptions,
  clearFlowCookie,
  consumeChallenge,
  createChallenge,
  createDefaultCollector,
  credentialStatement,
  deleteChallenge,
  flowCookie,
  passkeyById,
  passkeysForUser,
  prepareRecoveryCodes,
  prepareSession,
  registrationOptions,
  revokeSession,
  sessionCookieCleared,
  verifyAuthentication,
  verifyRegistration,
} from '../lib/auth';
import { keyedHash } from '../lib/crypto';
import { constantTimeEqual, randomId, randomToken, safeJsonParse } from '../lib/encoding';
import {
  SESSION_COOKIE,
  authConfig,
  clearCookie,
  jsonError,
  requireJson,
  requireSameOrigin,
  validateCsrf,
} from '../lib/http';

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

const bootstrapSchema = z.object({
  email: z.string().email().max(254).transform((value) => value.trim().toLowerCase()),
  displayName: z.string().trim().min(1).max(80),
  passkeyName: z.string().trim().min(1).max(80).default('Primary passkey'),
});

const registrationResponseSchema = z.object({
  response: z.custom<RegistrationResponseJSON>((value) => typeof value === 'object' && value !== null),
});

const authenticationResponseSchema = z.object({
  response: z.custom<AuthenticationResponseJSON>((value) => typeof value === 'object' && value !== null),
});

const recoverySchema = z.object({
  email: z.string().email().max(254).transform((value) => value.trim().toLowerCase()),
  code: z.string().trim().min(20).max(80).transform((value) => value.toUpperCase()),
});

async function authRateAllowed(request: Request, env: Env): Promise<boolean> {
  const actor = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const key = await keyedHash(env, 'auth-rate', actor);
  return (await env.AUTH_RATE_LIMITER.limit({ key })).success;
}

function appendCookie(response: Response, cookie: string): Response {
  response.headers.append('Set-Cookie', cookie);
  return response;
}

function baseChecks(request: Request, env: Env): string | null {
  if (!requireSameOrigin(request, env)) return 'origin';
  if (!requireJson(request)) return 'content_type';
  return null;
}

function bootstrapTokenValid(request: Request, env: Env): boolean {
  const token = request.headers.get('X-BXSS-Bootstrap') ?? '';
  return token.length >= 32 && constantTimeEqual(token, env.BOOTSTRAP_TOKEN);
}

app.get('/status', async (c) => {
  const owner = await c.env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'owner'").first<{
    count: number;
  }>();
  return c.json({ initialized: Number(owner?.count ?? 0) > 0, rp: authConfig(c.req.raw, c.env).rpName });
});

app.post('/bootstrap/options', async (c) => {
  if (baseChecks(c.req.raw, c.env)) return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  if (!(await authRateAllowed(c.req.raw, c.env))) return jsonError(c, 429, 'rate_limited', 'Try again later.');
  if (!bootstrapTokenValid(c.req.raw, c.env)) return jsonError(c, 403, 'bootstrap_denied', 'Bootstrap denied.');

  const owner = await c.env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'owner'").first<{
    count: number;
  }>();
  if (Number(owner?.count ?? 0) > 0) return jsonError(c, 409, 'already_initialized', 'Vault is already initialized.');

  const parsed = bootstrapSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return jsonError(c, 422, 'invalid_input', 'Check the submitted owner details.');

  const userId = randomId();
  const webauthnUserId = randomToken();
  const options = await registrationOptions(c.req.raw, c.env, {
    id: userId,
    email: parsed.data.email,
    displayName: parsed.data.displayName,
    webauthnUserId,
  });
  const flow = await createChallenge(c.env, 'bootstrap', options.challenge, null, {
    userId,
    webauthnUserId,
    ...parsed.data,
  });
  return appendCookie(c.json({ options }), flowCookie(flow.flowToken));
});

app.post('/bootstrap/verify', async (c) => {
  if (baseChecks(c.req.raw, c.env)) return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  if (!(await authRateAllowed(c.req.raw, c.env))) return jsonError(c, 429, 'rate_limited', 'Try again later.');
  if (!bootstrapTokenValid(c.req.raw, c.env)) return jsonError(c, 403, 'bootstrap_denied', 'Bootstrap denied.');

  const challenge = await consumeChallenge(c.req.raw, c.env, 'bootstrap');
  if (!challenge) return jsonError(c, 403, 'challenge_expired', 'Registration challenge expired.');
  const body = registrationResponseSchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 422, 'invalid_response', 'Invalid passkey response.');

  const context = safeJsonParse<{
    userId: string;
    webauthnUserId: string;
    email: string;
    displayName: string;
    passkeyName: string;
  }>(challenge.context_json, {} as never);

  try {
    const verification = await verifyRegistration(c.req.raw, c.env, body.data.response, challenge.challenge);
    if (!verification.verified || !verification.registrationInfo) throw new Error('Passkey was not verified');

    const current = Math.floor(Date.now() / 1000);
    const collector = await createDefaultCollector(c.env, context.userId);
    const recovery = await prepareRecoveryCodes(c.env, context.userId);
    const session = await prepareSession(c.req.raw, c.env, { id: context.userId, sessionVersion: 1 });

    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO users
          (id, email, display_name, webauthn_user_id, role, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'owner', ?, ?)`,
      ).bind(context.userId, context.email, context.displayName, context.webauthnUserId, current, current),
      credentialStatement(c.env, context.userId, context.passkeyName, verification.registrationInfo),
      collector.statement,
      ...recovery.statements,
      session.statement,
      c.env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(challenge.flow_hash),
    ]);

    await audit(c.req.raw, c.env, { userId: context.userId, action: 'owner.bootstrap' });
    const response = c.json({
      ok: true,
      csrfToken: session.csrfToken,
      recoveryCodes: recovery.codes,
      collectorToken: collector.token,
    });
    appendCookie(response, session.cookie);
    appendCookie(response, clearFlowCookie());
    return response;
  } catch {
    await deleteChallenge(c.env, challenge.flow_hash);
    await audit(c.req.raw, c.env, { action: 'owner.bootstrap', result: 'denied' }).catch(() => undefined);
    return jsonError(c, 403, 'registration_failed', 'Passkey registration failed.');
  }
});

app.post('/login/options', async (c) => {
  if (baseChecks(c.req.raw, c.env)) return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  if (!(await authRateAllowed(c.req.raw, c.env))) return jsonError(c, 429, 'rate_limited', 'Try again later.');
  const options = await authenticationOptions(c.req.raw, c.env);
  const flow = await createChallenge(c.env, 'login', options.challenge, null, {});
  return appendCookie(c.json({ options }), flowCookie(flow.flowToken));
});

app.post('/login/verify', async (c) => {
  if (baseChecks(c.req.raw, c.env)) return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  if (!(await authRateAllowed(c.req.raw, c.env))) return jsonError(c, 429, 'rate_limited', 'Try again later.');
  const challenge = await consumeChallenge(c.req.raw, c.env, 'login');
  if (!challenge) return jsonError(c, 403, 'challenge_expired', 'Login challenge expired.');
  const body = authenticationResponseSchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 422, 'invalid_response', 'Invalid passkey response.');

  const passkey = await passkeyById(c.env, body.data.response.id);
  if (!passkey || passkey.enabled !== 1 || !passkey.role || !passkey.email || !passkey.display_name) {
    await deleteChallenge(c.env, challenge.flow_hash);
    return jsonError(c, 403, 'login_failed', 'Passkey login failed.');
  }

  try {
    const verification = await verifyAuthentication(c.req.raw, c.env, body.data.response, challenge.challenge, passkey);
    if (!verification.verified) throw new Error('Passkey was not verified');
    const current = Math.floor(Date.now() / 1000);
    const session = await prepareSession(c.req.raw, c.env, {
      id: passkey.user_id,
      sessionVersion: Number(passkey.session_version),
    });
    await c.env.DB.batch([
      c.env.DB.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?').bind(
        verification.authenticationInfo.newCounter,
        current,
        passkey.id,
      ),
      session.statement,
      c.env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(challenge.flow_hash),
    ]);
    await audit(c.req.raw, c.env, { userId: passkey.user_id, action: 'session.login' });
    const response = c.json({
      ok: true,
      csrfToken: session.csrfToken,
      user: { email: passkey.email, displayName: passkey.display_name, role: passkey.role },
    });
    appendCookie(response, session.cookie);
    appendCookie(response, clearFlowCookie());
    return response;
  } catch {
    await deleteChallenge(c.env, challenge.flow_hash);
    await audit(c.req.raw, c.env, {
      userId: passkey.user_id,
      action: 'session.login',
      result: 'denied',
    }).catch(() => undefined);
    return jsonError(c, 403, 'login_failed', 'Passkey login failed.');
  }
});

app.post('/recovery', async (c) => {
  if (baseChecks(c.req.raw, c.env)) return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  if (!(await authRateAllowed(c.req.raw, c.env))) return jsonError(c, 429, 'rate_limited', 'Try again later.');
  const body = recoverySchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 403, 'recovery_failed', 'Recovery credentials were not accepted.');

  const codeHash = await keyedHash(c.env, 'recovery-code', body.data.code);
  const consumed = await c.env.DB.prepare(
    `DELETE FROM recovery_codes
      WHERE code_hash = ?
        AND user_id = (SELECT id FROM users WHERE email = ? AND enabled = 1)
      RETURNING user_id`,
  )
    .bind(codeHash, body.data.email)
    .first<{ user_id: string }>();
  if (!consumed) {
    await audit(c.req.raw, c.env, { action: 'account.recovery', result: 'denied' }).catch(() => undefined);
    return jsonError(c, 403, 'recovery_failed', 'Recovery credentials were not accepted.');
  }

  const user = await c.env.DB.prepare(
    'SELECT id, email, display_name, webauthn_user_id FROM users WHERE id = ? AND enabled = 1',
  )
    .bind(consumed.user_id)
    .first<{ id: string; email: string; display_name: string; webauthn_user_id: string }>();
  if (!user) return jsonError(c, 403, 'recovery_failed', 'Recovery credentials were not accepted.');
  const existing = await passkeysForUser(c.env, user.id);
  const options = await registrationOptions(
    c.req.raw,
    c.env,
    { id: user.id, email: user.email, displayName: user.display_name, webauthnUserId: user.webauthn_user_id },
    existing.map((key) => ({ id: key.id, transports: JSON.parse(key.transports) })),
  );
  const flow = await createChallenge(c.env, 'recovery', options.challenge, user.id, { name: 'Recovery passkey' });
  await audit(c.req.raw, c.env, { userId: user.id, action: 'recovery_code.consume' });
  return appendCookie(c.json({ options }), flowCookie(flow.flowToken));
});

app.post('/recovery/verify', async (c) => {
  if (baseChecks(c.req.raw, c.env)) return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  if (!(await authRateAllowed(c.req.raw, c.env))) return jsonError(c, 429, 'rate_limited', 'Try again later.');
  const challenge = await consumeChallenge(c.req.raw, c.env, 'recovery');
  if (!challenge?.user_id) return jsonError(c, 403, 'challenge_expired', 'Recovery challenge expired.');
  const body = registrationResponseSchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 422, 'invalid_response', 'Invalid passkey response.');
  const user = await c.env.DB.prepare('SELECT session_version FROM users WHERE id = ? AND enabled = 1')
    .bind(challenge.user_id)
    .first<{ session_version: number }>();
  if (!user) return jsonError(c, 403, 'recovery_failed', 'Account recovery failed.');
  try {
    const verification = await verifyRegistration(c.req.raw, c.env, body.data.response, challenge.challenge);
    if (!verification.verified || !verification.registrationInfo) throw new Error('Passkey was not verified');
    const nextSessionVersion = Number(user.session_version) + 1;
    const session = await prepareSession(
      c.req.raw,
      c.env,
      { id: challenge.user_id, sessionVersion: nextSessionVersion },
      true,
    );
    await c.env.DB.batch([
      credentialStatement(c.env, challenge.user_id, 'Recovery passkey', verification.registrationInfo),
      c.env.DB.prepare('UPDATE users SET session_version = ?, updated_at = unixepoch() WHERE id = ?').bind(
        nextSessionVersion,
        challenge.user_id,
      ),
      c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(challenge.user_id),
      session.statement,
      c.env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(challenge.flow_hash),
    ]);
    await audit(c.req.raw, c.env, { userId: challenge.user_id, action: 'account.recovery' });
    const response = c.json({ ok: true, csrfToken: session.csrfToken });
    appendCookie(response, session.cookie);
    appendCookie(response, clearFlowCookie());
    return response;
  } catch {
    await deleteChallenge(c.env, challenge.flow_hash);
    await audit(c.req.raw, c.env, {
      userId: challenge.user_id,
      action: 'account.recovery',
      result: 'denied',
    }).catch(() => undefined);
    return jsonError(c, 403, 'recovery_failed', 'Account recovery failed.');
  }
});

app.get('/me', (c) => {
  const session = c.get('session');
  return c.json({
    user: { id: session.userId, email: session.email, displayName: session.displayName, role: session.role },
    csrfToken: session.csrfToken,
    expiresAt: session.expiresAt,
    stepUpUntil: session.stepUpUntil,
  });
});

app.post('/logout', async (c) => {
  if (!requireSameOrigin(c.req.raw, c.env) || !requireJson(c.req.raw) || !validateCsrf(c)) {
    return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  }
  const session = c.get('session');
  await revokeSession(c.env, session.tokenHash);
  await audit(c.req.raw, c.env, { userId: session.userId, action: 'session.logout' });
  return appendCookie(c.json({ ok: true }), sessionCookieCleared());
});

app.post('/step-up/options', async (c) => {
  if (!requireSameOrigin(c.req.raw, c.env) || !requireJson(c.req.raw) || !validateCsrf(c)) {
    return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  }
  const session = c.get('session');
  const passkeys = await passkeysForUser(c.env, session.userId);
  const options = await authenticationOptions(
    c.req.raw,
    c.env,
    passkeys.map((key) => ({ id: key.id, transports: JSON.parse(key.transports) })),
  );
  const flow = await createChallenge(c.env, 'step_up', options.challenge, session.userId, {});
  return appendCookie(c.json({ options }), flowCookie(flow.flowToken));
});

app.post('/step-up/verify', async (c) => {
  if (!requireSameOrigin(c.req.raw, c.env) || !requireJson(c.req.raw) || !validateCsrf(c)) {
    return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  }
  const session = c.get('session');
  const challenge = await consumeChallenge(c.req.raw, c.env, 'step_up');
  if (!challenge || challenge.user_id !== session.userId) {
    return jsonError(c, 403, 'challenge_expired', 'Verification challenge expired.');
  }
  const body = authenticationResponseSchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 422, 'invalid_response', 'Invalid passkey response.');
  const passkey = await passkeyById(c.env, body.data.response.id);
  if (!passkey || passkey.user_id !== session.userId) return jsonError(c, 403, 'verification_failed', 'Verification failed.');

  try {
    const verification = await verifyAuthentication(c.req.raw, c.env, body.data.response, challenge.challenge, passkey);
    if (!verification.verified) throw new Error('Passkey was not verified');
    const current = Math.floor(Date.now() / 1000);
    await c.env.DB.batch([
      c.env.DB.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?').bind(
        verification.authenticationInfo.newCounter,
        current,
        passkey.id,
      ),
      c.env.DB.prepare('UPDATE sessions SET step_up_until = ? WHERE token_hash = ?').bind(current + 300, session.tokenHash),
      c.env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(challenge.flow_hash),
    ]);
    await audit(c.req.raw, c.env, { userId: session.userId, action: 'session.step_up' });
    const response = c.json({ ok: true, stepUpUntil: current + 300 });
    appendCookie(response, clearFlowCookie());
    return response;
  } catch {
    await deleteChallenge(c.env, challenge.flow_hash);
    return jsonError(c, 403, 'verification_failed', 'Verification failed.');
  }
});

app.post('/passkeys/options', async (c) => {
  if (!requireSameOrigin(c.req.raw, c.env) || !requireJson(c.req.raw) || !validateCsrf(c)) {
    return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  }
  const session = c.get('session');
  if (session.stepUpUntil < Math.floor(Date.now() / 1000)) {
    return jsonError(c, 428, 'step_up_required', 'A fresh passkey verification is required.');
  }
  const body = z.object({ name: z.string().trim().min(1).max(80) }).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 422, 'invalid_input', 'Passkey name is required.');
  const user = await c.env.DB.prepare('SELECT webauthn_user_id FROM users WHERE id = ?')
    .bind(session.userId)
    .first<{ webauthn_user_id: string }>();
  const existing = await passkeysForUser(c.env, session.userId);
  if (!user) return jsonError(c, 404, 'user_not_found', 'User not found.');
  const options = await registrationOptions(
    c.req.raw,
    c.env,
    { id: session.userId, email: session.email, displayName: session.displayName, webauthnUserId: user.webauthn_user_id },
    existing.map((key) => ({ id: key.id, transports: JSON.parse(key.transports) })),
  );
  const flow = await createChallenge(c.env, 'add_passkey', options.challenge, session.userId, { name: body.data.name });
  return appendCookie(c.json({ options }), flowCookie(flow.flowToken));
});

app.post('/passkeys/verify', async (c) => {
  if (!requireSameOrigin(c.req.raw, c.env) || !requireJson(c.req.raw) || !validateCsrf(c)) {
    return jsonError(c, 403, 'request_rejected', 'Request rejected.');
  }
  const session = c.get('session');
  if (session.stepUpUntil < Math.floor(Date.now() / 1000)) {
    return jsonError(c, 428, 'step_up_required', 'A fresh passkey verification is required.');
  }
  const challenge = await consumeChallenge(c.req.raw, c.env, 'add_passkey');
  if (!challenge || challenge.user_id !== session.userId) return jsonError(c, 403, 'challenge_expired', 'Challenge expired.');
  const body = registrationResponseSchema.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return jsonError(c, 422, 'invalid_response', 'Invalid passkey response.');
  const context = safeJsonParse<{ name: string }>(challenge.context_json, { name: 'Backup passkey' });
  try {
    const verification = await verifyRegistration(c.req.raw, c.env, body.data.response, challenge.challenge);
    if (!verification.verified || !verification.registrationInfo) throw new Error('Passkey was not verified');
    await c.env.DB.batch([
      credentialStatement(c.env, session.userId, context.name, verification.registrationInfo),
      c.env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').bind(
        session.userId,
        session.tokenHash,
      ),
      c.env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(challenge.flow_hash),
    ]);
    await audit(c.req.raw, c.env, { userId: session.userId, action: 'passkey.add' });
    const response = c.json({ ok: true });
    appendCookie(response, clearFlowCookie());
    return response;
  } catch {
    await deleteChallenge(c.env, challenge.flow_hash);
    return jsonError(c, 403, 'registration_failed', 'Passkey registration failed.');
  }
});

export default app;
