import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { Context } from 'hono';
import type { Env, SessionContext, Variables } from '../types';
import { keyedHash, sealJson } from './crypto';
import { base64UrlToBytes, bytesToBase64Url, constantTimeEqual, randomBytes, randomId, randomToken } from './encoding';
import {
  FLOW_COOKIE,
  SESSION_COOKIE,
  authConfig,
  clearCookie,
  cookieValue,
  intSetting,
  secureCookie,
} from './http';

export const CHALLENGE_TTL_SECONDS = 300;
export const STEP_UP_TTL_SECONDS = 300;

interface ChallengeRow {
  flow_hash: string;
  purpose: string;
  challenge: string;
  user_id: string | null;
  context_json: string;
  expires_at: number;
}

interface PasskeyRow {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  transports: string;
  device_type: string;
  backed_up: number;
  webauthn_user_id?: string;
  enabled?: number;
  session_version?: number;
  email?: string;
  display_name?: string;
  role?: 'owner' | 'analyst';
}

interface SessionRow {
  token_hash: string;
  user_id: string;
  csrf_token: string;
  user_agent_hash: string;
  session_version: number;
  created_at: number;
  last_seen_at: number;
  expires_at: number;
  step_up_until: number;
  email: string;
  display_name: string;
  role: 'owner' | 'analyst';
  enabled: number;
  current_session_version: number;
}

const now = (): number => Math.floor(Date.now() / 1000);

export async function createChallenge(
  env: Env,
  purpose: ChallengeRow['purpose'],
  challenge: string,
  userId: string | null,
  context: Record<string, unknown>,
): Promise<{ flowToken: string; expiresAt: number }> {
  const flowToken = randomToken();
  const flowHash = await keyedHash(env, 'auth-flow', flowToken);
  const createdAt = now();
  const expiresAt = createdAt + CHALLENGE_TTL_SECONDS;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM auth_challenges WHERE expires_at < ?').bind(createdAt),
    env.DB.prepare(
      `INSERT INTO auth_challenges
        (flow_hash, purpose, challenge, user_id, context_json, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(flowHash, purpose, challenge, userId, JSON.stringify(context), expiresAt, createdAt),
  ]);
  return { flowToken, expiresAt };
}

export async function consumeChallenge(
  request: Request,
  env: Env,
  purpose: ChallengeRow['purpose'],
): Promise<ChallengeRow | null> {
  const flowToken = cookieValue(request, FLOW_COOKIE);
  if (!flowToken) return null;
  const flowHash = await keyedHash(env, 'auth-flow', flowToken);
  const challenge = await env.DB.prepare(
    `SELECT flow_hash, purpose, challenge, user_id, context_json, expires_at
       FROM auth_challenges WHERE flow_hash = ? AND purpose = ?`,
  )
    .bind(flowHash, purpose)
    .first<ChallengeRow>();
  if (!challenge || challenge.expires_at < now()) {
    await env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(flowHash).run();
    return null;
  }
  return challenge;
}

export async function deleteChallenge(env: Env, flowHash: string): Promise<void> {
  await env.DB.prepare('DELETE FROM auth_challenges WHERE flow_hash = ?').bind(flowHash).run();
}

export function flowCookie(token: string): string {
  return secureCookie(FLOW_COOKIE, token, CHALLENGE_TTL_SECONDS);
}

export function clearFlowCookie(): string {
  return clearCookie(FLOW_COOKIE);
}

export async function registrationOptions(
  request: Request,
  env: Env,
  user: { id: string; email: string; displayName: string; webauthnUserId: string },
  existing: Array<{ id: string; transports: AuthenticatorTransportFuture[] }> = [],
) {
  const config = authConfig(request, env);
  return generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userID: base64UrlToBytes(user.webauthnUserId),
    userName: user.email,
    userDisplayName: user.displayName,
    timeout: 120_000,
    attestationType: 'none',
    excludeCredentials: existing,
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    supportedAlgorithmIDs: [-7, -257],
  });
}

export async function verifyRegistration(
  request: Request,
  env: Env,
  response: RegistrationResponseJSON,
  challenge: string,
) {
  const config = authConfig(request, env);
  return verifyRegistrationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    requireUserPresence: true,
    requireUserVerification: true,
    supportedAlgorithmIDs: [-7, -257],
  });
}

export async function authenticationOptions(
  request: Request,
  env: Env,
  allowed?: Array<{ id: string; transports: AuthenticatorTransportFuture[] }>,
) {
  const config = authConfig(request, env);
  return generateAuthenticationOptions({
    rpID: config.rpID,
    timeout: 120_000,
    userVerification: 'required',
    ...(allowed ? { allowCredentials: allowed } : {}),
  });
}

export async function verifyAuthentication(
  request: Request,
  env: Env,
  response: AuthenticationResponseJSON,
  challenge: string,
  passkey: PasskeyRow,
) {
  const config = authConfig(request, env);
  if (response.response.userHandle && passkey.webauthn_user_id) {
    if (!constantTimeEqual(response.response.userHandle, passkey.webauthn_user_id)) {
      throw new Error('Passkey user handle mismatch');
    }
  }
  return verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    requireUserVerification: true,
    credential: {
      id: passkey.id,
      publicKey: base64UrlToBytes(passkey.public_key),
      counter: Number(passkey.counter),
      transports: JSON.parse(passkey.transports) as AuthenticatorTransportFuture[],
    },
  });
}

export async function passkeyById(env: Env, credentialId: string): Promise<PasskeyRow | null> {
  return env.DB.prepare(
    `SELECT p.*, u.webauthn_user_id, u.enabled, u.session_version,
            u.email, u.display_name, u.role
       FROM passkeys p JOIN users u ON u.id = p.user_id
      WHERE p.id = ?`,
  )
    .bind(credentialId)
    .first<PasskeyRow>();
}

export async function passkeysForUser(env: Env, userId: string): Promise<PasskeyRow[]> {
  const result = await env.DB.prepare(
    `SELECT id, user_id, public_key, counter, transports, device_type, backed_up
       FROM passkeys WHERE user_id = ? ORDER BY created_at ASC`,
  )
    .bind(userId)
    .all<PasskeyRow>();
  return result.results;
}

export interface NewSession {
  token: string;
  tokenHash: string;
  csrfToken: string;
  cookie: string;
  statement: D1PreparedStatement;
}

export async function prepareSession(
  request: Request,
  env: Env,
  user: { id: string; sessionVersion: number },
  fresh = true,
): Promise<NewSession> {
  const token = randomToken();
  const tokenHash = await keyedHash(env, 'session', token);
  const csrfToken = randomToken();
  const userAgentHash = await keyedHash(env, 'user-agent', request.headers.get('User-Agent') ?? '');
  const createdAt = now();
  const absolute = intSetting(env.SESSION_ABSOLUTE_SECONDS, 14_400, 900, 86_400);
  const expiresAt = createdAt + absolute;
  return {
    token,
    tokenHash,
    csrfToken,
    cookie: secureCookie(SESSION_COOKIE, token, absolute),
    statement: env.DB.prepare(
      `INSERT INTO sessions
        (token_hash, user_id, csrf_token, user_agent_hash, session_version,
         created_at, last_seen_at, expires_at, step_up_until)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      tokenHash,
      user.id,
      csrfToken,
      userAgentHash,
      user.sessionVersion,
      createdAt,
      createdAt,
      expiresAt,
      fresh ? createdAt + STEP_UP_TTL_SECONDS : 0,
    ),
  };
}

export async function resolveSession(request: Request, env: Env): Promise<SessionContext | null> {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await keyedHash(env, 'session', token);
  const row = await env.DB.prepare(
    `SELECT s.*, u.email, u.display_name, u.role, u.enabled,
            u.session_version AS current_session_version
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`,
  )
    .bind(tokenHash)
    .first<SessionRow>();
  const current = now();
  const idleSeconds = intSetting(env.SESSION_IDLE_SECONDS, 900, 60, 14_400);
  if (
    !row ||
    row.enabled !== 1 ||
    row.expires_at < current ||
    row.last_seen_at + idleSeconds < current ||
    row.session_version !== row.current_session_version
  ) {
    if (row) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
    return null;
  }
  const expectedAgent = await keyedHash(env, 'user-agent', request.headers.get('User-Agent') ?? '');
  if (!constantTimeEqual(row.user_agent_hash, expectedAgent)) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
    return null;
  }
  if (current - row.last_seen_at >= 60) {
    await env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?')
      .bind(current, tokenHash)
      .run();
  }
  return {
    tokenHash,
    userId: row.user_id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    csrfToken: row.csrf_token,
    createdAt: row.created_at,
    lastSeenAt: current,
    expiresAt: row.expires_at,
    stepUpUntil: row.step_up_until,
    sessionVersion: row.session_version,
  };
}

export async function revokeSession(env: Env, tokenHash: string): Promise<void> {
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
}

export function sessionCookieCleared(): string {
  return clearCookie(SESSION_COOKIE);
}

const recoveryAlphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function recoveryCode(): string {
  const source = randomBytes(24);
  let encoded = '';
  for (const byte of source) encoded += recoveryAlphabet[byte % recoveryAlphabet.length];
  return `BV1-${encoded.match(/.{1,4}/g)?.join('-')}`;
}

export async function prepareRecoveryCodes(
  env: Env,
  userId: string,
): Promise<{ codes: string[]; statements: D1PreparedStatement[] }> {
  const codes = Array.from({ length: 8 }, recoveryCode);
  const createdAt = now();
  const statements: D1PreparedStatement[] = [
    env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(userId),
  ];
  for (const code of codes) {
    statements.push(
      env.DB.prepare('INSERT INTO recovery_codes (code_hash, user_id, created_at) VALUES (?, ?, ?)').bind(
        await keyedHash(env, 'recovery-code', code.toUpperCase()),
        userId,
        createdAt,
      ),
    );
  }
  return { codes, statements };
}

export async function audit(
  request: Request,
  env: Env,
  entry: {
    userId?: string | null;
    action: string;
    targetType?: string | null;
    targetId?: string | null;
    result?: 'success' | 'denied' | 'error';
    metadata?: Record<string, string | number | boolean | null>;
  },
): Promise<void> {
  const ip = request.headers.get('CF-Connecting-IP') ?? '';
  const agent = request.headers.get('User-Agent') ?? '';
  await env.DB.prepare(
    `INSERT INTO audit_log
      (user_id, action, target_type, target_id, result, request_id,
       ip_hash, user_agent_hash, metadata_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      entry.userId ?? null,
      entry.action,
      entry.targetType ?? null,
      entry.targetId ?? null,
      entry.result ?? 'success',
      request.headers.get('CF-Ray') ?? crypto.randomUUID(),
      await keyedHash(env, 'audit-ip', ip),
      await keyedHash(env, 'audit-ua', agent),
      JSON.stringify(entry.metadata ?? {}),
      now(),
    )
    .run();
}

export async function createDefaultCollector(env: Env, userId: string) {
  const id = randomId();
  const token = randomToken();
  const sealed = await sealJson(env, `collector:${id}:token`, token);
  const createdAt = now();
  return {
    id,
    token,
    statement: env.DB.prepare(
      `INSERT INTO collectors
        (id, user_id, name, token_hash, token_ciphertext, token_iv, capture_screenshot, created_at, updated_at)
       VALUES (?, ?, 'Default collector', ?, ?, ?, 0, ?, ?)`,
    ).bind(
      id,
      userId,
      await keyedHash(env, 'collector-token', token),
      sealed.ciphertext,
      sealed.iv,
      createdAt,
      createdAt,
    ),
  };
}

export function credentialStatement(
  env: Env,
  userId: string,
  name: string,
  registrationInfo: Awaited<ReturnType<typeof verifyRegistration>>['registrationInfo'],
): D1PreparedStatement {
  if (!registrationInfo) throw new Error('Missing verified registration info');
  const credential = registrationInfo.credential;
  return env.DB.prepare(
    `INSERT INTO passkeys
      (id, user_id, public_key, counter, transports, device_type, backed_up, name, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    credential.id,
    userId,
    bytesToBase64Url(credential.publicKey),
    credential.counter,
    JSON.stringify(credential.transports ?? []),
    registrationInfo.credentialDeviceType,
    registrationInfo.credentialBackedUp ? 1 : 0,
    name,
    now(),
  );
}

export async function requireStepUp(c: Context<{ Bindings: Env; Variables: Variables }>): Promise<Response | null> {
  if (c.get('session').stepUpUntil >= now()) return null;
  return c.json(
    { error: { code: 'step_up_required', message: 'A fresh passkey verification is required.' } },
    428,
  );
}
