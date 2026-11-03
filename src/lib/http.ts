import type { Context } from 'hono';
import type { Env, Variables } from '../types';
import { constantTimeEqual } from './encoding';

export const SESSION_COOKIE = '__Host-bxss_session';
export const FLOW_COOKIE = '__Host-bxss_auth_flow';

export function intSetting(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

export function authConfig(request: Request, env: Env): { origin: string; rpID: string; rpName: string } {
  const url = new URL(request.url);
  const origin = (env.APP_ORIGIN || url.origin).replace(/\/$/, '');
  return {
    origin,
    rpID: env.RP_ID || new URL(origin).hostname,
    rpName: env.RP_NAME || 'BXSS Vault',
  };
}

export function collectorOrigin(request: Request, env: Env): string {
  return (env.COLLECTOR_ORIGIN || new URL(request.url).origin).replace(/\/$/, '');
}

export function cookieValue(request: Request, name: string): string | null {
  const cookie = request.headers.get('Cookie') ?? '';
  for (const item of cookie.split(';')) {
    const index = item.indexOf('=');
    if (index === -1) continue;
    if (item.slice(0, index).trim() === name) return decodeURIComponent(item.slice(index + 1).trim());
  }
  return null;
}

export function secureCookie(
  name: string,
  value: string,
  maxAge: number,
  options: { httpOnly?: boolean } = { httpOnly: true },
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'Secure', 'SameSite=Strict', `Max-Age=${maxAge}`];
  if (options.httpOnly !== false) parts.push('HttpOnly');
  return parts.join('; ');
}

export function clearCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;
}

export function requireSameOrigin(request: Request, env: Env): boolean {
  const expected = authConfig(request, env).origin;
  const origin = request.headers.get('Origin');
  const fetchSite = request.headers.get('Sec-Fetch-Site');
  return origin === expected && (!fetchSite || fetchSite === 'same-origin');
}

export function requireJson(request: Request): boolean {
  return (request.headers.get('Content-Type') ?? '').split(';', 1)[0].trim().toLowerCase() === 'application/json';
}

export function validateCsrf(c: Context<{ Bindings: Env; Variables: Variables }>): boolean {
  const provided = c.req.header('X-BXSS-CSRF') ?? '';
  const session = c.get('session');
  return provided.length >= 32 && constantTimeEqual(provided, session.csrfToken);
}

export function securityHeaders(response: Response, admin = true): Response {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Cross-Origin-Resource-Policy', admin ? 'same-origin' : 'cross-origin');
  if (admin) {
    headers.set('Cache-Control', 'no-store');
    headers.set(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'self'",
    );
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export const REPORT_PAGE_CSP =
  "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; worker-src 'none'; manifest-src 'none'";

export function reportSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
  if (!headers.has('Content-Security-Policy')) headers.set('Content-Security-Policy', REPORT_PAGE_CSP);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function jsonError(c: Context, status: 400 | 401 | 403 | 404 | 409 | 413 | 422 | 428 | 429 | 500, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}
