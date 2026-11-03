import { randomBytes, truncateUtf8, utf8, bytesToBase64Url, type Bytes } from './encoding';

/**
 * Out-of-band (OOB) interaction helpers.
 *
 * An OOB listener is addressed by a token that must survive both a URL path and
 * a DNS label. DNS labels are case-insensitive and restricted to a narrow
 * character set, so the token uses lowercase RFC 4648 base32 (`a-z2-7`). Sixteen
 * random bytes encode to a fixed 26-character token: 128 bits of entropy, 26
 * characters (well within the 63-character DNS label limit) and safe to place
 * verbatim in a path segment.
 *
 * Nothing here performs I/O; everything is pure and unit tested so the capture
 * route can stay a thin, auditable shell over bounded, deterministic logic.
 */

export const OOB_TOKEN_BYTES = 16;
export const OOB_TOKEN_LENGTH = 26;

export const MAX_OOB_HEADERS = 64;
export const OOB_HEADER_NAME_MAX_BYTES = 256;
export const OOB_HEADER_VALUE_MAX_BYTES = 4_096;
export const OOB_METHOD_MAX_BYTES = 16;
export const OOB_PATH_MAX_BYTES = 4_096;
export const OOB_QUERY_MAX_BYTES = 4_096;
export const OOB_HOST_MAX_BYTES = 256;
export const OOB_USER_AGENT_MAX_BYTES = 1_024;
export const MAX_OOB_BODY_BYTES = 65_536;

const BASE32_LOWER_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const oobTokenPattern = /^[a-z2-7]{26}$/;

export interface OobHeader {
  name: string;
  value: string;
}

export interface OobBody {
  body: string;
  encoding: 'utf-8' | 'base64url';
  byteLength: number;
  truncated: boolean;
}

/** Encodes bytes as unpadded lowercase RFC 4648 base32. */
export function base32LowerEncode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let index = 0; index < bytes.length; index += 1) {
    value = (value << 8) | bytes[index];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_LOWER_ALPHABET[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) output += BASE32_LOWER_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function createOobToken(): string {
  return base32LowerEncode(randomBytes(OOB_TOKEN_BYTES));
}

export function isOobToken(value: string): boolean {
  return oobTokenPattern.test(value);
}

/**
 * Extracts an OOB token from a `/o/<token>` path. Anything after the token is a
 * free-form capture path and does not affect the lookup.
 */
export function oobTokenFromPath(pathname: string): string | null {
  const parts = pathname.split('/').filter(Boolean);
  if (parts[0] !== 'o' || parts.length < 2) return null;
  const token = parts[1];
  return isOobToken(token) ? token : null;
}

/** Normalizes an operator-supplied wildcard capture host (`oob.example.com`). */
export function normalizeOobWildcardHost(value: string | undefined | null): string {
  if (!value) return '';
  const withoutScheme = value.trim().replace(/^https?:\/\//i, '');
  const host = withoutScheme.split('/', 1)[0].replace(/\.+$/, '').toLowerCase();
  return /^[a-z0-9.-]{1,253}$/.test(host) && host.includes('.') ? host : '';
}

/**
 * Extracts an OOB token when the request arrives at `<token>.<wildcardHost>`.
 * The token must be the immediate leftmost label of the configured host.
 */
export function oobTokenFromHost(hostname: string, wildcardHost: string): string | null {
  if (!wildcardHost) return null;
  const host = hostname.toLowerCase();
  const suffix = `.${wildcardHost}`;
  if (!host.endsWith(suffix)) return null;
  const label = host.slice(0, host.length - suffix.length);
  return isOobToken(label) ? label : null;
}

/** A single-segment loader path for path-based capture. */
export function oobPathLoader(origin: string, token: string): string {
  return `${origin.replace(/\/$/, '')}/o/${token}`;
}

/** The capture host for subdomain-based capture, when a wildcard host is set. */
export function oobHostLoader(wildcardHost: string, token: string): string {
  return wildcardHost ? `${token}.${wildcardHost}` : '';
}

/**
 * Removes a listener token from a captured value so it can be shown in the
 * non-step-up interaction list without disclosing the secret. The full request
 * line, including the token, is retained only in the step-up-gated detail.
 */
export function redactToken(value: string, token: string): string {
  return token ? value.split(token).join('…') : value;
}

/** Collapses a raw header/metadata string to bounded, inert single-line text. */
export function boundOobText(value: string, maxBytes: number): string {
  const cleaned = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ');
  return truncateUtf8(cleaned, maxBytes);
}

/**
 * Captures request headers as bounded, ordered, inert text. Order and duplicate
 * header names are preserved. The count is the true number of headers so the
 * dashboard can show when the bound dropped some.
 */
export function boundOobHeaders(headers: Headers): { headers: OobHeader[]; count: number } {
  const collected: OobHeader[] = [];
  let count = 0;
  for (const [name, value] of headers) {
    count += 1;
    if (collected.length >= MAX_OOB_HEADERS) continue;
    collected.push({
      name: boundOobText(name, OOB_HEADER_NAME_MAX_BYTES),
      value: boundOobText(value, OOB_HEADER_VALUE_MAX_BYTES),
    });
  }
  return { headers: collected, count };
}

/**
 * Represents a captured request body as inert text. UTF-8 bodies are stored as
 * text; anything else is stored as base64url so binary callbacks round-trip
 * without corrupting the encrypted record or the dashboard.
 */
export function encodeOobBody(bytes: Uint8Array): OobBody {
  const byteLength = bytes.byteLength;
  const truncated = byteLength > MAX_OOB_BODY_BYTES;
  const slice = truncated ? bytes.subarray(0, MAX_OOB_BODY_BYTES) : bytes;
  if (slice.byteLength === 0) {
    return { body: '', encoding: 'utf-8', byteLength, truncated };
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(slice);
    return { body: text, encoding: 'utf-8', byteLength, truncated };
  } catch {
    return { body: bytesToBase64Url(slice as Bytes), encoding: 'base64url', byteLength, truncated };
  }
}

// --- Per-listener response control ------------------------------------------

export const OOB_RESPONSE_BODY_MAX_BYTES = 8_192;
export const OOB_RESPONSE_HEADER_MAX_COUNT = 16;
export const OOB_RESPONSE_HEADER_NAME_MAX = 128;
export const OOB_RESPONSE_HEADER_VALUE_MAX = 2_048;

// RFC 7230 header field-name token, and a field-value limited to visible ASCII
// plus space/tab. Restricting the value to a ByteString with no CR/LF/NUL
// prevents response-header injection and runtime encoding errors.
const headerNamePattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const headerValuePattern = /^[\t\x20-\x7e]*$/;

// Headers whose value the runtime derives from the response itself. Letting an
// operator set these would corrupt message framing, so they are never accepted.
const FORBIDDEN_RESPONSE_HEADERS = new Set([
  'content-length',
  'content-encoding',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'te',
  'trailer',
  'trailers',
]);

// Applied to every OOB response and overridden only by an explicit operator
// header of the same name. The worker additionally enforces a fixed set of
// security headers (nosniff, framing, CORP) on top of these.
export const OOB_DEFAULT_RESPONSE_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['Content-Type', 'text/plain; charset=utf-8'],
  ['Cache-Control', 'no-store'],
  ['Access-Control-Allow-Origin', '*'],
  ['Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD'],
  ['Access-Control-Allow-Headers', '*'],
  ['Access-Control-Max-Age', '600'],
  ['X-Content-Type-Options', 'nosniff'],
];

export interface OobResponseHeader {
  name: string;
  value: string;
}

export interface OobResponsePolicy {
  status: number;
  body: string;
  headers: OobResponseHeader[];
}

export interface OobResponseSpec {
  status: number;
  headers: Array<[string, string]>;
  body: string;
}

export function isForbiddenResponseHeader(name: string): boolean {
  return FORBIDDEN_RESPONSE_HEADERS.has(name.toLowerCase());
}

function validResponseHeader(name: string, value: string): boolean {
  return (
    name.length >= 1
    && name.length <= OOB_RESPONSE_HEADER_NAME_MAX
    && value.length <= OOB_RESPONSE_HEADER_VALUE_MAX
    && headerNamePattern.test(name)
    && headerValuePattern.test(value)
    && !isForbiddenResponseHeader(name)
  );
}

/**
 * Validates an operator-supplied response policy into a canonical shape, or
 * returns null if anything is out of bounds. Rejecting (rather than silently
 * dropping) keeps the admin API honest about what it stored.
 */
export function canonicalOobResponse(value: unknown): OobResponsePolicy | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (key !== 'status' && key !== 'body' && key !== 'headers') return null;
  }
  const { status } = record;
  if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 599) return null;
  const body = record.body === undefined ? '' : record.body;
  if (typeof body !== 'string' || utf8(body).byteLength > OOB_RESPONSE_BODY_MAX_BYTES) return null;
  const rawHeaders = record.headers === undefined ? [] : record.headers;
  if (!Array.isArray(rawHeaders) || rawHeaders.length > OOB_RESPONSE_HEADER_MAX_COUNT) return null;
  const headers: OobResponseHeader[] = [];
  for (const item of rawHeaders) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
    const entry = item as Record<string, unknown>;
    if (Object.keys(entry).length !== 2 || typeof entry.name !== 'string' || typeof entry.value !== 'string') {
      return null;
    }
    if (!validResponseHeader(entry.name, entry.value)) return null;
    headers.push({ name: entry.name, value: entry.value });
  }
  return { status, body, headers };
}

/**
 * Builds the concrete response spec served to a caller. A null policy yields the
 * inert default (empty body, 200, permissive CORS). A policy overrides the
 * status and body and merges its headers over the defaults by name; forbidden
 * or malformed headers are skipped defensively even though the admin API should
 * have rejected them already.
 */
export function oobResponseSpec(policy: OobResponsePolicy | null, fallbackStatus = 200): OobResponseSpec {
  const merged = new Map<string, [string, string]>();
  for (const [name, value] of OOB_DEFAULT_RESPONSE_HEADERS) merged.set(name.toLowerCase(), [name, value]);
  if (!policy) {
    return { status: fallbackStatus, headers: [...merged.values()], body: '' };
  }
  for (const header of policy.headers) {
    if (!validResponseHeader(header.name, header.value)) continue;
    merged.set(header.name.toLowerCase(), [header.name, header.value]);
  }
  return { status: policy.status, headers: [...merged.values()], body: policy.body };
}
