import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { createPayloadSnippets } from './payload-snippets';
import './styles.css';

type JsonMap = Record<string, unknown>;
type View = 'events' | 'collectors' | 'oob' | 'security' | 'audit';
type Notice = { id: number; tone: 'success' | 'danger' | 'info'; message: string };

interface SessionUser {
  id: string;
  email: string;
  displayName: string;
  role: string;
}

interface Session {
  user: SessionUser;
  expiresAt: number;
  stepUpUntil: number;
}

interface OneTimeData {
  title: string;
  message: string;
  recoveryCodes?: string[];
  token?: string;
  tokenLabel?: string;
}

interface EventRow {
  id: string;
  collectorId: string;
  collectorName: string;
  receivedAt: number;
  isRead: boolean;
  detailBytes: number;
  screenshotBytes: number;
  hasScreenshot: boolean;
  summary: JsonMap;
}

interface Collector {
  id: string;
  name: string;
  token: string;
  loaderUrl: string;
  alias: string;
  aliasLoaderUrl: string;
  aliasCreatedAt: number | null;
  enabled: boolean;
  captureCookies: boolean;
  captureDom: boolean;
  captureScreenshot: boolean;
  captureStorage: boolean;
  discordNotifications: boolean;
  discordConfigured: boolean;
  probeChecks: boolean;
  pagePaths: string[];
  chainloadUrl: string;
  createdAt: number;
  updatedAt: number;
}

interface OobProbe {
  id: string;
  name: string;
  token: string;
  pathLoaderUrl: string;
  hostLoaderUrl: string;
  wildcardHost: string;
  enabled: boolean;
  discordNotifications: boolean;
  discordConfigured: boolean;
  createdAt: number;
  updatedAt: number;
}

interface OobInteraction {
  id: string;
  probeId: string;
  probeName: string;
  receivedAt: number;
  isRead: boolean;
  detailBytes: number;
  summary: JsonMap;
}

interface Passkey {
  id: string;
  name: string;
  deviceType: string;
  backedUp: boolean;
  createdAt: number;
  lastUsedAt: number | null;
}

interface AuditEntry {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  result: string;
  requestId: string;
  metadata: unknown;
  createdAt: number;
}

const AUTH = '/api/auth';
const API = '/api';

function asMap(value: unknown): JsonMap {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonMap)
    : {};
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : value === null || value === undefined ? fallback : String(value);
}

function numberValue(value: unknown, fallback = 0): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function booleanValue(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value;
  if (value === 1 || value === '1') return true;
  if (value === 0 || value === '0') return false;
  return fallback;
}

function timeMillis(value: number): number {
  return value > 10_000_000_000 ? value : value * 1000;
}

function formatDate(value: number): string {
  if (!value) return 'Never';
  const date = new Date(timeMillis(value));
  return Number.isNaN(date.getTime())
    ? 'Unknown'
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
      }).format(date);
}

function relativeTime(value: number): string {
  if (!value) return 'unknown time';
  const seconds = Math.round((timeMillis(value) - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, 'second');
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, 'minute');
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, 'hour');
  return formatter.format(Math.round(hours / 24), 'day');
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / Math.pow(1024, power)).toFixed(power === 0 ? 0 : 1) + ' ' + units[power];
}

type FileWriter = {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
};

type SaveFilePicker = (options: {
  suggestedName: string;
  types: Array<{ description: string; accept: Record<string, string[]> }>;
}) => Promise<{ createWritable(): Promise<FileWriter> }>;

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function tarHeader(path: string, size: number): Uint8Array {
  if (!/^[\x20-\x7e]{1,100}$/.test(path)) throw new Error('Export path is not TAR-safe.');
  const header = new Uint8Array(512);
  const write = (offset: number, length: number, value: string) => {
    const encoded = new TextEncoder().encode(value);
    header.set(encoded.subarray(0, length), offset);
  };
  const octal = (value: number, length: number) => value.toString(8).padStart(length - 1, '0') + '\0';
  write(0, 100, path);
  write(100, 8, octal(0o600, 8));
  write(108, 8, octal(0, 8));
  write(116, 8, octal(0, 8));
  write(124, 12, octal(size, 12));
  write(136, 12, octal(Math.floor(Date.now() / 1_000), 12));
  write(148, 8, '        ');
  header[156] = '0'.charCodeAt(0);
  write(257, 6, 'ustar\0');
  write(263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  write(148, 8, checksum.toString(8).padStart(6, '0') + '\0 ');
  return header;
}

async function writeTarEntry(writer: FileWriter, path: string, data: Uint8Array): Promise<void> {
  await writer.write(tarHeader(path, data.byteLength));
  await writer.write(data);
  const padding = (512 - (data.byteLength % 512)) % 512;
  if (padding) await writer.write(new Uint8Array(padding));
}

const jsonBytes = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value, null, 2) + '\n');

function pretty(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function hasContent(value: unknown): boolean {
  if (value === undefined || value === null || value === '') return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value as object).length > 0;
  return true;
}

class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

let csrfToken = '';
let authExpiredHandler: (() => void) | null = null;
let stepUpStateHandler: ((active: boolean) => void) | null = null;
let stepUpPromise: Promise<void> | null = null;

function setCsrf(value: string): void {
  csrfToken = value;
}

async function parseJson(response: Response): Promise<unknown> {
  const type = response.headers.get('Content-Type') || '';
  if (!type.includes('application/json')) return null;
  return response.json().catch(() => null);
}

interface ApiOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  allowStepUp?: boolean;
  signal?: AbortSignal;
}

async function apiResponse(path: string, options: ApiOptions = {}): Promise<Response> {
  const method = options.method || 'GET';
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');
  if (method !== 'GET') {
    headers.set('Content-Type', 'application/json');
    if (csrfToken) headers.set('X-BXSS-CSRF', csrfToken);
  }

  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    signal: options.signal,
    body: method === 'GET' ? undefined : JSON.stringify(options.body === undefined ? {} : options.body),
  });

  if (response.status === 428 && options.allowStepUp !== false) {
    await freshPasskeyVerification();
    return apiResponse(path, { ...options, allowStepUp: false });
  }

  if (response.status === 401) authExpiredHandler?.();
  if (!response.ok) {
    const payload = asMap(await parseJson(response));
    const error = asMap(payload.error);
    throw new ApiError(
      response.status,
      stringValue(error.code, 'request_failed'),
      stringValue(error.message, 'The request could not be completed.'),
    );
  }
  return response;
}

async function apiJson<T = JsonMap>(path: string, options: ApiOptions = {}): Promise<T> {
  const response = await apiResponse(path, options);
  if (response.status === 204) return {} as T;
  return (await parseJson(response)) as T;
}

async function apiBlob(path: string): Promise<Blob> {
  const response = await apiResponse(path);
  return response.blob();
}

async function freshPasskeyVerification(): Promise<void> {
  if (stepUpPromise) return stepUpPromise;
  stepUpPromise = (async () => {
    stepUpStateHandler?.(true);
    try {
      const optionsPayload = asMap(
        await apiJson(AUTH + '/step-up/options', {
          method: 'POST',
          body: {},
          allowStepUp: false,
        }),
      );
      const assertion = await startAuthentication({
        optionsJSON: optionsPayload.options as Parameters<typeof startAuthentication>[0]['optionsJSON'],
      });
      await apiJson(AUTH + '/step-up/verify', {
        method: 'POST',
        body: { response: assertion },
        allowStepUp: false,
      });
    } finally {
      stepUpStateHandler?.(false);
      stepUpPromise = null;
    }
  })();
  return stepUpPromise;
}

function friendlyError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof DOMException && error.name === 'NotAllowedError') {
    return 'Passkey verification was cancelled or timed out.';
  }
  if (error instanceof Error) return error.message;
  return 'Something went wrong. Please try again.';
}

type IconName =
  | 'activity'
  | 'audit'
  | 'check'
  | 'chevron'
  | 'clipboard'
  | 'close'
  | 'code'
  | 'download'
  | 'events'
  | 'eye'
  | 'eyeOff'
  | 'globe'
  | 'key'
  | 'lock'
  | 'logout'
  | 'menu'
  | 'refresh'
  | 'search'
  | 'security'
  | 'shield'
  | 'trash';

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.8,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
  };
  const paths: Record<IconName, React.ReactNode> = {
    activity: <><path d="M3 12h4l2.4-7 4.2 14 2.3-7H21" /></>,
    audit: <><path d="M9 5h10M9 12h10M9 19h10" /><path d="M4 5h.01M4 12h.01M4 19h.01" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    chevron: <path d="m9 18 6-6-6-6" />,
    clipboard: <><rect x="7" y="7" width="13" height="13" rx="2" /><path d="M16 7V5a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h1" /></>,
    close: <><path d="M18 6 6 18M6 6l12 12" /></>,
    code: <><path d="m8 9-3 3 3 3M16 9l3 3-3 3M14 5l-4 14" /></>,
    download: <><path d="M12 3v12M7 10l5 5 5-5" /><path d="M5 21h14" /></>,
    events: <><path d="M4 17V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2Z" /><path d="M8 12h2l1.5-3 2.5 6 1.5-3H18" /></>,
    eye: <><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" /><circle cx="12" cy="12" r="2.5" /></>,
    eyeOff: <><path d="m3 3 18 18M10.6 10.7a2 2 0 0 0 2.7 2.7M9.9 5.2A11 11 0 0 1 12 5c6.5 0 10 7 10 7a16 16 0 0 1-2.2 3M6.6 6.7C3.6 8.4 2 12 2 12s3.5 7 10 7a10 10 0 0 0 4-.8" /></>,
    globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18" /></>,
    key: <><circle cx="8" cy="15" r="4" /><path d="m11 12 8-8M15 8l3 3M17 6l2 2" /></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>,
    logout: <><path d="M10 17l5-5-5-5M15 12H3" /><path d="M14 4h4a3 3 0 0 1 3 3v10a3 3 0 0 1-3 3h-4" /></>,
    menu: <path d="M4 7h16M4 12h16M4 17h16" />,
    refresh: <><path d="M20 6v5h-5M4 18v-5h5" /><path d="M18.5 9A7 7 0 0 0 6 6.5L4 11m16 2-2 4.5A7 7 0 0 1 5.5 15" /></>,
    search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
    security: <><path d="M12 3 4 6v5c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10V6l-8-3Z" /><path d="m9 12 2 2 4-5" /></>,
    shield: <><path d="M12 3 4 6v5c0 5 3.4 8.4 8 10 4.6-1.6 8-5 8-10V6l-8-3Z" /><path d="M12 8v4M12 16h.01" /></>,
    trash: <><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6" /></>,
  };
  return <svg {...common}>{paths[name]}</svg>;
}

function Spinner({ label = 'Loading' }: { label?: string }) {
  return <span className="spinner" role="status" aria-label={label} />;
}

function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }
  return (
    <button className="button button-quiet button-small" type="button" onClick={copy}>
      <Icon name={copied ? 'check' : 'clipboard'} size={15} />
      {copied ? 'Copied' : label}
    </button>
  );
}

function EmptyState({
  icon,
  title,
  message,
  action,
}: {
  icon: IconName;
  title: string;
  message: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon"><Icon name={icon} size={24} /></span>
      <h3>{title}</h3>
      <p>{message}</p>
      {action}
    </div>
  );
}

function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  useEffect(() => {
    function keydown(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [onClose]);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <section className={'modal ' + (wide ? 'modal-wide' : '')} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close">
            <Icon name="close" />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}

function ErrorBanner({ message, onDismiss }: { message: string; onDismiss?: () => void }) {
  return (
    <div className="error-banner" role="alert">
      <Icon name="shield" />
      <span>{message}</span>
      {onDismiss && (
        <button className="icon-button" type="button" onClick={onDismiss} aria-label="Dismiss">
          <Icon name="close" size={16} />
        </button>
      )}
    </div>
  );
}

function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark"><Icon name="activity" size={22} /></span>
      <span><strong>BXSS</strong><small>Vault</small></span>
    </div>
  );
}

function AuthLayout({ children, rpName }: { children: React.ReactNode; rpName: string }) {
  return (
    <main className="auth-layout">
      <div className="auth-glow auth-glow-one" />
      <div className="auth-glow auth-glow-two" />
      <section className="auth-story">
        <Brand />
        <div className="story-copy">
          <span className="eyebrow"><span className="status-dot" /> Private capture infrastructure</span>
          <h1>Signals arrive.<br /><em>Nothing leaks.</em></h1>
          <p>A hardened, Cloudflare-native blind XSS vault built to keep sensitive findings under your control.</p>
        </div>
        <div className="security-strip">
          <span><Icon name="key" size={16} /> Passkey only</span>
          <span><Icon name="lock" size={16} /> Encrypted at rest</span>
          <span><Icon name="shield" size={16} /> Same-origin locked</span>
        </div>
      </section>
      <section className="auth-pane">
        <div className="auth-card-wrap">
          {children}
          <p className="auth-footnote"><Icon name="lock" size={13} /> {rpName} never accepts passwords.</p>
        </div>
      </section>
    </main>
  );
}

function Login({
  rpName,
  onAuthenticated,
}: {
  rpName: string;
  onAuthenticated: (session: Session) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [recovering, setRecovering] = useState(false);
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');

  async function finishAuthentication(csrf: string) {
    setCsrf(csrf);
    const me = asMap(await apiJson(AUTH + '/me', { allowStepUp: false }));
    onAuthenticated(normalizeSession(me));
  }

  async function login() {
    setBusy(true);
    setError('');
    try {
      const payload = asMap(await apiJson(AUTH + '/login/options', {
        method: 'POST',
        body: {},
        allowStepUp: false,
      }));
      const assertion = await startAuthentication({
        optionsJSON: payload.options as Parameters<typeof startAuthentication>[0]['optionsJSON'],
      });
      const verified = asMap(await apiJson(AUTH + '/login/verify', {
        method: 'POST',
        body: { response: assertion },
        allowStepUp: false,
      }));
      await finishAuthentication(stringValue(verified.csrfToken));
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setBusy(false);
    }
  }

  async function recover(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const payload = asMap(await apiJson(AUTH + '/recovery', {
        method: 'POST',
        body: { email: email.trim(), code: code.trim().toUpperCase() },
        allowStepUp: false,
      }));
      const credential = await startRegistration({
        optionsJSON: payload.options as Parameters<typeof startRegistration>[0]['optionsJSON'],
      });
      const verified = asMap(await apiJson(AUTH + '/recovery/verify', {
        method: 'POST',
        body: { response: credential },
        allowStepUp: false,
      }));
      await finishAuthentication(stringValue(verified.csrfToken));
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout rpName={rpName}>
      <div className="auth-card">
        <span className="card-icon"><Icon name={recovering ? 'shield' : 'key'} size={24} /></span>
        <p className="eyebrow">{recovering ? 'Emergency access' : 'Authorized access'}</p>
        <h2>{recovering ? 'Recover your vault' : 'Unlock your vault'}</h2>
        <p className="card-lead">
          {recovering
            ? 'Use one offline recovery code to register a replacement passkey.'
            : 'Use a registered passkey. Biometric verification stays on your device.'}
        </p>
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        {recovering ? (
          <form onSubmit={recover} className="auth-form">
            <label>
              <span>Email</span>
              <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            <label>
              <span>Recovery code</span>
              <input
                className="mono-input"
                type="text"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="BV1-••••-••••-••••"
                required
              />
            </label>
            <button className="button button-primary button-full" type="submit" disabled={busy}>
              {busy ? <Spinner label="Starting recovery" /> : <Icon name="key" />}
              {busy ? 'Waiting for passkey…' : 'Register replacement passkey'}
            </button>
          </form>
        ) : (
          <button className="button button-primary button-full auth-action" type="button" onClick={login} disabled={busy}>
            {busy ? <Spinner label="Verifying passkey" /> : <Icon name="key" />}
            {busy ? 'Waiting for passkey…' : 'Continue with passkey'}
          </button>
        )}
        <button className="text-button" type="button" onClick={() => {
          setRecovering(!recovering);
          setError('');
        }} disabled={busy}>
          {recovering ? 'Back to passkey sign in' : 'Lost your passkey? Use a recovery code'}
        </button>
      </div>
    </AuthLayout>
  );
}

function Bootstrap({
  rpName,
  onComplete,
}: {
  rpName: string;
  onComplete: (data: OneTimeData, csrf: string) => void;
}) {
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [passkeyName, setPasskeyName] = useState('Primary passkey');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    const headers = { 'X-BXSS-Bootstrap': bootstrapToken.trim() };
    try {
      const payload = asMap(await apiJson(AUTH + '/bootstrap/options', {
        method: 'POST',
        headers,
        body: { email: email.trim(), displayName: displayName.trim(), passkeyName: passkeyName.trim() },
        allowStepUp: false,
      }));
      const credential = await startRegistration({
        optionsJSON: payload.options as Parameters<typeof startRegistration>[0]['optionsJSON'],
      });
      const verified = asMap(await apiJson(AUTH + '/bootstrap/verify', {
        method: 'POST',
        headers,
        body: { response: credential },
        allowStepUp: false,
      }));
      onComplete(
        {
          title: 'Your vault is ready',
          message: 'These recovery codes and the initial collector token are shown once. Save them in separate, secure locations now.',
          recoveryCodes: asList(verified.recoveryCodes).map((item) => stringValue(item)),
          token: stringValue(verified.collectorToken),
          tokenLabel: 'Initial collector token',
        },
        stringValue(verified.csrfToken),
      );
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout rpName={rpName}>
      <div className="auth-card bootstrap-card">
        <span className="card-icon"><Icon name="shield" size={24} /></span>
        <p className="eyebrow">First-run security ceremony</p>
        <h2>Initialize the owner</h2>
        <p className="card-lead">The bootstrap secret works once. Your first passkey becomes the vault owner.</p>
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        <form className="auth-form form-grid" onSubmit={submit}>
          <label className="field-span">
            <span>Bootstrap token</span>
            <input
              className="mono-input"
              type="password"
              autoComplete="off"
              value={bootstrapToken}
              onChange={(e) => setBootstrapToken(e.target.value)}
              minLength={32}
              required
            />
            <small>Use the value configured as the BOOTSTRAP_TOKEN secret.</small>
          </label>
          <label>
            <span>Owner name</span>
            <input autoComplete="name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
          </label>
          <label>
            <span>Owner email</span>
            <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <label className="field-span">
            <span>Passkey name</span>
            <input value={passkeyName} onChange={(e) => setPasskeyName(e.target.value)} maxLength={80} required />
          </label>
          <button className="button button-primary button-full field-span" type="submit" disabled={busy}>
            {busy ? <Spinner label="Creating vault" /> : <Icon name="key" />}
            {busy ? 'Waiting for passkey…' : 'Create owner passkey'}
          </button>
        </form>
      </div>
    </AuthLayout>
  );
}

function OneTimeSecrets({ data, onDone, modal = false }: { data: OneTimeData; onDone: () => void; modal?: boolean }) {
  const [confirmed, setConfirmed] = useState(false);
  const all = [
    ...(data.recoveryCodes || []),
    ...(data.token ? [data.tokenLabel + ': ' + data.token] : []),
  ].join('\n');
  const content = (
    <div className="one-time-content">
      <div className="success-seal"><Icon name="check" size={28} /></div>
      <p className="eyebrow">One-time display</p>
      <h2>{data.title}</h2>
      <p className="card-lead">{data.message}</p>
      {data.recoveryCodes && data.recoveryCodes.length > 0 && (
        <section className="secret-section">
          <div className="section-title-row">
            <div>
              <h3>Recovery codes</h3>
              <p>Each code can be used only once.</p>
            </div>
            <CopyButton value={data.recoveryCodes.join('\n')} label="Copy codes" />
          </div>
          <div className="recovery-grid">
            {data.recoveryCodes.map((code, index) => <code key={code}>{String(index + 1).padStart(2, '0')} · {code}</code>)}
          </div>
        </section>
      )}
      {data.token && (
        <section className="secret-section">
          <div className="section-title-row">
            <div>
              <h3>{data.tokenLabel || 'Secret token'}</h3>
              <p>Treat this value like a password.</p>
            </div>
            <CopyButton value={data.token} />
          </div>
          <div className="secret-value"><code>{data.token}</code></div>
        </section>
      )}
      {all && <CopyButton value={all} label="Copy everything" />}
      <label className="confirm-save">
        <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
        <span>I saved these secrets in a secure offline location.</span>
      </label>
      <button className="button button-primary button-full" type="button" disabled={!confirmed} onClick={onDone}>
        <Icon name="check" /> I have saved them
      </button>
    </div>
  );
  if (modal) return content;
  return <main className="one-time-page"><div className="one-time-card"><Brand />{content}</div></main>;
}

function normalizeSession(payload: JsonMap): Session {
  const user = asMap(payload.user);
  return {
    user: {
      id: stringValue(user.id),
      email: stringValue(user.email),
      displayName: stringValue(user.displayName || user.display_name, 'Owner'),
      role: stringValue(user.role, 'owner'),
    },
    expiresAt: numberValue(payload.expiresAt || payload.expires_at),
    stepUpUntil: numberValue(payload.stepUpUntil || payload.step_up_until),
  };
}

function normalizeEvent(value: unknown): EventRow {
  const row = asMap(value);
  return {
    id: stringValue(row.id),
    collectorId: stringValue(row.collectorId || row.collector_id),
    collectorName: stringValue(row.collectorName || row.collector_name, 'Collector'),
    receivedAt: numberValue(row.receivedAt || row.received_at),
    isRead: booleanValue(row.isRead ?? row.is_read),
    detailBytes: numberValue(row.detailBytes || row.detail_bytes),
    screenshotBytes: numberValue(row.screenshotBytes || row.screenshot_bytes),
    hasScreenshot: booleanValue(row.hasScreenshot ?? row.has_screenshot),
    summary: asMap(row.summary),
  };
}

function normalizeCollector(value: unknown): Collector {
  const row = asMap(value);
  const aliasCreatedAt = row.aliasCreatedAt ?? row.alias_created_at;
  return {
    id: stringValue(row.id),
    name: stringValue(row.name, 'Collector'),
    token: stringValue(row.token),
    loaderUrl: stringValue(row.loaderUrl || row.loader_url),
    alias: stringValue(row.alias),
    aliasLoaderUrl: stringValue(row.aliasLoaderUrl || row.alias_loader_url),
    aliasCreatedAt: aliasCreatedAt === null || aliasCreatedAt === undefined ? null : numberValue(aliasCreatedAt),
    enabled: booleanValue(row.enabled, true),
    captureCookies: booleanValue(row.captureCookies ?? row.capture_cookies, true),
    captureDom: booleanValue(row.captureDom ?? row.capture_dom, true),
    captureScreenshot: booleanValue(row.captureScreenshot ?? row.capture_screenshot, true),
    captureStorage: booleanValue(row.captureStorage ?? row.capture_storage),
    discordNotifications: booleanValue(row.discordNotifications ?? row.discord_notifications),
    discordConfigured: booleanValue(row.discordConfigured ?? row.discord_configured),
    probeChecks: booleanValue(row.probeChecks ?? row.probe_checks),
    pagePaths: asList(row.pagePaths || row.page_paths).map((item) => stringValue(item)).filter(Boolean),
    chainloadUrl: stringValue(row.chainloadUrl || row.chainload_url),
    createdAt: numberValue(row.createdAt || row.created_at),
    updatedAt: numberValue(row.updatedAt || row.updated_at),
  };
}

function normalizeOobProbe(value: unknown): OobProbe {
  const row = asMap(value);
  return {
    id: stringValue(row.id),
    name: stringValue(row.name, 'Listener'),
    token: stringValue(row.token),
    pathLoaderUrl: stringValue(row.pathLoaderUrl || row.path_loader_url),
    hostLoaderUrl: stringValue(row.hostLoaderUrl || row.host_loader_url),
    wildcardHost: stringValue(row.wildcardHost || row.wildcard_host),
    enabled: booleanValue(row.enabled, true),
    discordNotifications: booleanValue(row.discordNotifications ?? row.discord_notifications),
    discordConfigured: booleanValue(row.discordConfigured ?? row.discord_configured),
    createdAt: numberValue(row.createdAt || row.created_at),
    updatedAt: numberValue(row.updatedAt || row.updated_at),
  };
}

function normalizeOobInteraction(value: unknown): OobInteraction {
  const row = asMap(value);
  return {
    id: stringValue(row.id),
    probeId: stringValue(row.probeId || row.probe_id),
    probeName: stringValue(row.probeName || row.probe_name, 'Listener'),
    receivedAt: numberValue(row.receivedAt || row.received_at),
    isRead: booleanValue(row.isRead ?? row.is_read),
    detailBytes: numberValue(row.detailBytes || row.detail_bytes),
    summary: asMap(row.summary),
  };
}

function normalizePasskey(value: unknown): Passkey {
  const row = asMap(value);
  const last = row.lastUsedAt ?? row.last_used_at;
  return {
    id: stringValue(row.id),
    name: stringValue(row.name, 'Passkey'),
    deviceType: stringValue(row.deviceType || row.device_type, 'multi-device'),
    backedUp: booleanValue(row.backedUp ?? row.backed_up),
    createdAt: numberValue(row.createdAt || row.created_at),
    lastUsedAt: last === null || last === undefined ? null : numberValue(last),
  };
}

function normalizeAudit(value: unknown): AuditEntry {
  const row = asMap(value);
  return {
    id: stringValue(row.id),
    action: stringValue(row.action, 'unknown'),
    targetType: stringValue(row.targetType || row.target_type),
    targetId: stringValue(row.targetId || row.target_id),
    result: stringValue(row.result, 'success'),
    requestId: stringValue(row.requestId || row.request_id),
    metadata: row.metadata ?? row.metadata_json ?? {},
    createdAt: numberValue(row.createdAt || row.created_at),
  };
}

function eventHeadline(event: EventRow): string {
  return stringValue(event.summary.title || event.summary.url || event.summary.origin, 'Untitled capture');
}

function eventUrl(event: EventRow): string {
  return stringValue(event.summary.url || event.summary.origin, 'No URL reported');
}

function captureSourceLabel(...records: JsonMap[]): string {
  const keys = ['placementLabel', 'sourceLabel', 'placement', 'source'];
  for (const record of records) {
    for (const key of keys) {
      const value = record[key];
      if (typeof value === 'string' && value.trim()) return value.trim();
    }
  }
  return '';
}

function EventDetails({
  event,
  onClose,
  onDeleted,
  onRead,
}: {
  event: EventRow;
  onClose: () => void;
  onDeleted: (id: string) => void;
  onRead: (id: string) => void;
}) {
  const [payload, setPayload] = useState<JsonMap | null>(null);
  const [screenshotUrl, setScreenshotUrl] = useState('');
  const [loadingShot, setLoadingShot] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const screenshotObjectUrl = useRef('');

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    apiJson(API + '/events/' + encodeURIComponent(event.id), { signal: controller.signal })
      .then((result) => {
        if (!alive) return;
        const map = asMap(result);
        setPayload(asMap(map.event || map));
        setLoading(false);
        if (!event.isRead) {
          apiJson(API + '/events/' + encodeURIComponent(event.id) + '/read', {
            method: 'POST',
            body: { read: true },
          }).then(() => onRead(event.id)).catch(() => undefined);
        }
      })
      .catch((caught) => {
        if (alive) {
          setError(friendlyError(caught));
          setLoading(false);
        }
      });
    return () => {
      alive = false;
      controller.abort();
    };
  }, [event.id, onRead]);

  useEffect(() => {
    return () => {
      if (screenshotObjectUrl.current) URL.revokeObjectURL(screenshotObjectUrl.current);
    };
  }, []);

  async function loadScreenshot() {
    if (loadingShot || screenshotUrl) return;
    setLoadingShot(true);
    setError('');
    try {
      const blob = await apiBlob(API + '/events/' + encodeURIComponent(event.id) + '/screenshot');
      const url = URL.createObjectURL(blob);
      if (screenshotObjectUrl.current) URL.revokeObjectURL(screenshotObjectUrl.current);
      screenshotObjectUrl.current = url;
      setScreenshotUrl(url);
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setLoadingShot(false);
    }
  }

  async function remove() {
    setDeleting(true);
    setError('');
    try {
      await apiJson(API + '/events/' + encodeURIComponent(event.id), { method: 'DELETE', body: {} });
      onDeleted(event.id);
      onClose();
    } catch (caught) {
      setError(friendlyError(caught));
      setDeleting(false);
    }
  }

  const full = payload || {};
  const summary = asMap(full.summary || event.summary);
  const detailEnvelope = asMap(full.detail || full.capture);
  const detail = asMap(detailEnvelope.event || detailEnvelope.capture || detailEnvelope);
  const network = asMap(detailEnvelope.network);
  const correlated = full.correlatedRequest ?? full.correlated_request;
  const sourceLabel = captureSourceLabel(full, summary, detailEnvelope, detail);
  const payloadParams = asList(
    full.payloadParams
      || full.payload_params
      || summary.payloadParams
      || summary.payload_params
      || detailEnvelope.payloadParams
      || detailEnvelope.payload_params
      || detail.payloadParams
      || detail.payload_params,
  );
  const capturedBlocks = [
    { title: 'Location and browser', value: {
      placement: sourceLabel || undefined,
      url: detail.url ?? summary.url,
      origin: detail.origin ?? summary.origin,
      title: detail.title ?? summary.title,
      referrer: detail.referrer ?? summary.referrer,
      userAgent: detail.userAgent ?? summary.userAgent,
      browserTime: detail.browserTime,
      wasIframe: detail.wasIframe ?? summary.wasIframe,
      viewport: detail.viewport,
      screenshotDiagnostics: detail.screenshotDiagnostics,
      network,
      country: network.country ?? summary.country,
    } },
    { title: 'Payload parameters', value: payloadParams },
    { title: 'Cookies', value: detail.cookies },
    { title: 'Detected secrets', value: detail.secrets },
    { title: 'DOM text', value: detail.domText },
    { title: 'DOM snapshot (inert text)', value: detail.domHtml },
    { title: 'Local storage', value: detail.localStorage ?? detail.local_storage },
    { title: 'Session storage', value: detail.sessionStorage ?? detail.session_storage },
    { title: 'Page checks', value: detail.pages },
    { title: 'Probe checks', value: { cors: detail.cors, gitExposed: detail.gitExposed } },
    { title: 'Correlated injection request', value: correlated },
  ].filter((block) => hasContent(block.value) && (!(typeof block.value === 'object') || Object.values(block.value as object).some(hasContent)));

  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={(e) => {
      if (e.currentTarget === e.target) onClose();
    }}>
      <aside className="event-drawer" role="dialog" aria-modal="true" aria-label="Capture details">
        <header className="drawer-header">
          <div>
            <span className="eyebrow">Capture detail</span>
            <h2>{eventHeadline(event)}</h2>
            <p>{formatDate(event.receivedAt)} · {event.collectorName}</p>
            {sourceLabel && <span className="capture-source-label"><Icon name="code" size={12} /> {sourceLabel}</span>}
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close details"><Icon name="close" /></button>
        </header>
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        {loading ? (
          <div className="drawer-loading"><Spinner /><span>Decrypting capture…</span></div>
        ) : (
          <div className="drawer-body">
            <div className="capture-warning">
              <Icon name="shield" size={17} />
              Captured values are rendered as inert text. Links and markup are never executed.
            </div>
            {event.hasScreenshot && (
              <section className="detail-section">
                <div className="section-title-row">
                  <div><h3>Screenshot</h3><p>{formatBytes(event.screenshotBytes)}</p></div>
                  {!screenshotUrl && (
                    <button className="button button-secondary button-small" type="button" onClick={loadScreenshot} disabled={loadingShot}>
                      {loadingShot ? <Spinner /> : <Icon name="eye" size={15} />}
                      {loadingShot ? 'Decrypting…' : 'View screenshot'}
                    </button>
                  )}
                </div>
                {screenshotUrl && (
                  <div className="screenshot-frame">
                    <img src={screenshotUrl} alt="Captured browser screenshot" />
                  </div>
                )}
              </section>
            )}
            {capturedBlocks.map((block) => (
              <section className="detail-section" key={block.title}>
                <h3>{block.title}</h3>
                <pre className="capture-pre">{pretty(block.value)}</pre>
              </section>
            ))}
            <section className="detail-section record-section">
              <h3>Record</h3>
              <pre className="capture-pre">{pretty({
                eventId: event.id,
                collectorId: event.collectorId,
                receivedAt: event.receivedAt,
                detailBytes: event.detailBytes,
                screenshotBytes: event.screenshotBytes,
              })}</pre>
            </section>
          </div>
        )}
        <footer className="drawer-footer">
          {confirmDelete ? (
            <div className="delete-confirm">
              <span>Delete this capture permanently?</span>
              <button className="button button-danger button-small" type="button" onClick={remove} disabled={deleting}>
                {deleting ? <Spinner /> : <Icon name="trash" size={15} />} Delete
              </button>
              <button className="button button-quiet button-small" type="button" onClick={() => setConfirmDelete(false)} disabled={deleting}>Cancel</button>
            </div>
          ) : (
            <button className="button button-danger-quiet button-small" type="button" onClick={() => setConfirmDelete(true)}>
              <Icon name="trash" size={15} /> Delete capture
            </button>
          )}
        </footer>
      </aside>
    </div>
  );
}

function StatsStrip({ refreshKey }: { refreshKey: number }) {
  const [stats, setStats] = useState<JsonMap>({});
  useEffect(() => {
    apiJson(API + '/stats')
      .then((payload) => {
        const map = asMap(payload);
        setStats(asMap(map.stats || map));
      })
      .catch(() => undefined);
  }, [refreshKey]);
  const used = numberValue(stats.storageBytes);
  const limit = numberValue(stats.storageLimitBytes);
  const percent = limit > 0 ? Math.min(100, used / limit * 100) : 0;
  return (
    <div className="stats-strip">
      <div className="stat-card">
        <span>All captures</span>
        <strong>{numberValue(stats.eventCount).toLocaleString()}</strong>
        <small>{numberValue(stats.unreadCount).toLocaleString()} unread</small>
      </div>
      <div className="stat-card">
        <span>Today</span>
        <strong>{numberValue(stats.eventsToday).toLocaleString()}</strong>
        <small>incoming signals</small>
      </div>
      <div className="stat-card">
        <span>Private storage</span>
        <strong>{formatBytes(used)}</strong>
        <progress className="meter" max={100} value={percent} aria-label="Encrypted storage usage" />
        <small>{limit ? percent.toFixed(1) + '% of ' + formatBytes(limit) : 'R2 encrypted objects'}</small>
      </div>
      <div className="stat-card">
        <span>Retention</span>
        <strong>{numberValue(stats.retentionDays)} days</strong>
        <small>{numberValue(stats.collectorCount)} collector · {numberValue(stats.passkeyCount)} passkeys</small>
      </div>
    </div>
  );
}

function EventsPage({ notify }: { notify: (tone: Notice['tone'], message: string) => void }) {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [nextCursor, setNextCursor] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<EventRow | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [deletingAll, setDeletingAll] = useState(false);

  const load = useCallback(async (cursor = '', append = false) => {
    append ? setLoadingMore(true) : setLoading(true);
    setError('');
    try {
      const query = new URLSearchParams({ limit: '50' });
      if (cursor) query.set('cursor', cursor);
      const payload = asMap(await apiJson(API + '/events?' + query.toString()));
      const rows = asList(payload.events).map(normalizeEvent).filter((row) => row.id);
      setEvents((current) => append ? [...current, ...rows] : rows);
      setNextCursor(stringValue(payload.nextCursor || payload.next_cursor));
      if (!append) setRefreshKey((key) => key + 1);
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return events;
    return events.filter((event) => {
      const haystack = [
        event.id,
        event.collectorName,
        stringValue(event.summary.url),
        stringValue(event.summary.origin),
        stringValue(event.summary.title),
        stringValue(event.summary.country),
      ].join(' ').toLowerCase();
      return haystack.includes(query);
    });
  }, [events, search]);

  const markRead = useCallback((id: string) => {
    setEvents((rows) => {
      if (!rows.some((row) => row.id === id && !row.isRead)) return rows;
      return rows.map((row) => row.id === id ? { ...row, isRead: true } : row);
    });
    setSelected((current) => current?.id === id && !current.isRead ? { ...current, isRead: true } : current);
  }, []);

  function removeEvent(id: string) {
    setEvents((rows) => rows.filter((row) => row.id !== id));
    setRefreshKey((key) => key + 1);
    notify('success', 'Capture deleted.');
  }

  async function exportAll() {
    if (!window.confirm('Export every capture and screenshot as PLAINTEXT? Store the archive in an encrypted location.')) return;
    const picker = (window as unknown as { showSaveFilePicker?: SaveFilePicker }).showSaveFilePicker;
    if (!picker) {
      setError('Streaming export requires a current Chromium-based browser with the File System Access API.');
      return;
    }
    let writer: FileWriter | null = null;
    setExporting(true);
    setError('');
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const handle = await picker({
        suggestedName: `bxss-vault-plaintext-${stamp}.tar`,
        types: [{ description: 'Plaintext TAR archive', accept: { 'application/x-tar': ['.tar'] } }],
      });
      writer = await handle.createWritable();
      let cursor = '';
      let eventCount = 0;
      let manifestWritten = false;
      do {
        const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
        const payload = asMap(await apiJson(API + '/export/events' + query));
        if (!manifestWritten && payload.manifest) {
          await writeTarEntry(writer, 'manifest.json', jsonBytes(payload.manifest));
          manifestWritten = true;
        }
        for (const raw of asList(payload.events)) {
          const exported = asMap(raw);
          const id = stringValue(exported.id);
          if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('Export returned an invalid event ID.');
          const screenshot = asMap(exported.screenshot);
          let screenshotFile: string | null = null;
          if (screenshot.data) {
            const extension = stringValue(screenshot.extension);
            if (extension !== 'jpg' && extension !== 'png') throw new Error('Export returned an invalid image type.');
            screenshotFile = `events/${id}/screenshot.${extension}`;
            await writeTarEntry(writer, screenshotFile, base64UrlDecode(stringValue(screenshot.data)));
          }
          const record = { ...exported, screenshot: screenshotFile ? { mime: screenshot.mime, file: screenshotFile } : null };
          await writeTarEntry(writer, `events/${id}/event.json`, jsonBytes(record));
          eventCount += 1;
        }
        cursor = stringValue(payload.nextCursor || payload.next_cursor);
      } while (cursor);

      let injectionCursor = '';
      let injectionPage = 0;
      do {
        const query = injectionCursor ? `?cursor=${encodeURIComponent(injectionCursor)}` : '';
        const payload = asMap(await apiJson(API + '/export/injections' + query));
        injectionPage += 1;
        await writeTarEntry(
          writer,
          `injection-requests/page-${String(injectionPage).padStart(6, '0')}.json`,
          jsonBytes(asList(payload.requests)),
        );
        injectionCursor = stringValue(payload.nextCursor || payload.next_cursor);
      } while (injectionCursor);

      let oobCursor = '';
      let oobCount = 0;
      do {
        const query = oobCursor ? `?cursor=${encodeURIComponent(oobCursor)}` : '';
        const payload = asMap(await apiJson(API + '/export/oob' + query));
        for (const raw of asList(payload.interactions)) {
          const exported = asMap(raw);
          const id = stringValue(exported.id);
          if (!/^[0-9a-f-]{36}$/i.test(id)) throw new Error('Export returned an invalid interaction ID.');
          await writeTarEntry(writer, `oob/${id}/interaction.json`, jsonBytes(exported));
          oobCount += 1;
        }
        oobCursor = stringValue(payload.nextCursor || payload.next_cursor);
      } while (oobCursor);

      let auditCursor = '';
      let auditPage = 0;
      do {
        const query = new URLSearchParams({ limit: '100' });
        if (auditCursor) query.set('cursor', auditCursor);
        const payload = asMap(await apiJson(API + '/audit?' + query.toString()));
        auditPage += 1;
        await writeTarEntry(
          writer,
          `audit/page-${String(auditPage).padStart(6, '0')}.json`,
          jsonBytes(asList(payload.entries)),
        );
        auditCursor = stringValue(payload.nextCursor || payload.next_cursor);
      } while (auditCursor);
      await writeTarEntry(
        writer,
        'export-complete.json',
        jsonBytes({ eventCount, oobCount, injectionPages: injectionPage, auditPages: auditPage, completedAt: Date.now() }),
      );
      await writer.write(new Uint8Array(1_024));
      await writer.close();
      writer = null;
      notify('success', `Plaintext migration archive saved with ${eventCount.toLocaleString()} captures.`);
    } catch (caught) {
      if (writer) await writer.abort(caught).catch(() => undefined);
      setError(friendlyError(caught));
    } finally {
      setExporting(false);
    }
  }

  async function deleteAll() {
    const confirmation = window.prompt('This permanently deletes every capture and screenshot. Type DELETE ALL CAPTURES to continue.');
    if (confirmation !== 'DELETE ALL CAPTURES') return;
    setDeletingAll(true);
    setError('');
    let deleted = 0;
    try {
      let remaining = true;
      while (remaining) {
        const payload = asMap(await apiJson(API + '/events', {
          method: 'DELETE',
          body: { all: true, confirmation },
        }));
        deleted += asList(payload.deletedIds || payload.deleted_ids).length;
        remaining = booleanValue(payload.remaining);
      }
      setSelected(null);
      await load();
      notify('success', `Deleted ${deleted.toLocaleString()} captures and their encrypted objects.`);
    } catch (caught) {
      setError(`${friendlyError(caught)} ${deleted.toLocaleString()} captures were deleted before the failure.`);
      await load();
    } finally {
      setDeletingAll(false);
    }
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Signal inbox</p>
          <h1>Events</h1>
          <p>Encrypted browser callbacks from your collectors.</p>
        </div>
        <div className="heading-actions">
          <button className="button button-secondary" type="button" onClick={exportAll} disabled={exporting || deletingAll}>
            {exporting ? <Spinner /> : <Icon name="download" />} {exporting ? 'Exporting…' : 'Export all'}
          </button>
          <button className="button button-danger-quiet" type="button" onClick={deleteAll} disabled={deletingAll || exporting || events.length === 0}>
            {deletingAll ? <Spinner /> : <Icon name="trash" />} {deletingAll ? 'Deleting…' : 'Delete all'}
          </button>
          <button className="button button-secondary" type="button" onClick={() => load()} disabled={loading || exporting || deletingAll}>
            {loading ? <Spinner /> : <Icon name="refresh" />} Refresh
          </button>
        </div>
      </div>
      <StatsStrip refreshKey={refreshKey} />
      <section className="panel event-panel">
        <div className="panel-toolbar">
          <label className="search-field">
            <Icon name="search" size={17} />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search loaded captures" aria-label="Search events" />
          </label>
          <span className="record-count">{visible.length} loaded</span>
        </div>
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        {loading ? (
          <div className="table-loading"><Spinner /><span>Loading encrypted event index…</span></div>
        ) : visible.length === 0 ? (
          <EmptyState
            icon="events"
            title={search ? 'No matching captures' : 'Waiting for the first signal'}
            message={search ? 'Try a different URL, origin, country, or collector.' : 'Deploy a collector payload and new callbacks will appear here.'}
          />
        ) : (
          <div className="event-list" role="list">
            {visible.map((event) => (
              <button className={'event-row ' + (!event.isRead ? 'event-unread' : '')} type="button" key={event.id} onClick={() => setSelected(event)} role="listitem">
                <span className="event-state">{!event.isRead && <i />}</span>
                <span className="event-main">
                  <span className="event-title">{eventHeadline(event)}</span>
                  <span className="event-url">{eventUrl(event)}</span>
                </span>
                <span className="event-badges">
                  {captureSourceLabel(event.summary) && (
                    <span className="badge badge-source"><Icon name="code" size={12} /> {captureSourceLabel(event.summary)}</span>
                  )}
                  {numberValue(event.summary.secretCount || event.summary.secret_count) > 0 && (
                    <span className="badge badge-alert"><Icon name="key" size={12} /> {numberValue(event.summary.secretCount || event.summary.secret_count)} secrets</span>
                  )}
                  {event.hasScreenshot && <span className="badge"><Icon name="eye" size={12} /> shot</span>}
                  {booleanValue(event.summary.wasIframe ?? event.summary.was_iframe) && <span className="badge">iframe</span>}
                </span>
                <span className="event-meta">
                  <strong>{event.collectorName}</strong>
                  <span title={formatDate(event.receivedAt)}>{relativeTime(event.receivedAt)}</span>
                </span>
                <Icon name="chevron" size={17} />
              </button>
            ))}
          </div>
        )}
        {nextCursor && !search && (
          <div className="load-more">
            <button className="button button-secondary" type="button" onClick={() => load(nextCursor, true)} disabled={loadingMore}>
              {loadingMore ? <Spinner /> : null}{loadingMore ? 'Loading…' : 'Load older captures'}
            </button>
          </div>
        )}
      </section>
      {selected && (
        <EventDetails
          event={selected}
          onClose={() => setSelected(null)}
          onDeleted={removeEvent}
          onRead={markRead}
        />
      )}
    </>
  );
}

function Toggle({
  checked,
  onChange,
  label,
  detail,
  disabled = false,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  detail: string;
  disabled?: boolean;
}) {
  return (
    <label className={'toggle-row' + (disabled ? ' disabled' : '')}>
      <span><strong>{label}</strong><small>{detail}</small></span>
      <span className="toggle">
        <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} disabled={disabled} />
        <i />
      </span>
    </label>
  );
}

function Snippet({ label, value }: { label: string; value: string }) {
  return (
    <div className="snippet">
      <div><span>{label}</span><CopyButton value={value} /></div>
      <pre>{value}</pre>
    </div>
  );
}

function CollectorsPage({ notify }: { notify: (tone: Notice['tone'], message: string) => void }) {
  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [aliasBusy, setAliasBusy] = useState(false);
  const [discordTestBusy, setDiscordTestBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newCollectorName, setNewCollectorName] = useState('New payload');
  const [error, setError] = useState('');
  const [reveal, setReveal] = useState(false);
  const [pathsText, setPathsText] = useState('');
  const [payloadParamsText, setPayloadParamsText] = useState('');

  const selected = collectors.find((collector) => collector.id === selectedId) || collectors[0] || null;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/collectors'));
      const rows = asList(payload.collectors).map(normalizeCollector).filter((row) => row.id);
      setCollectors(rows);
      setSelectedId((current) => rows.some((row) => row.id === current) ? current : rows[0]?.id || '');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setPathsText(selected?.pagePaths.join('\n') || '');
    setReveal(false);
    setPayloadParamsText('');
  }, [selected?.id]);

  function patchLocal(patch: Partial<Collector>) {
    if (!selected) return;
    setCollectors((rows) => rows.map((row) => row.id === selected.id ? { ...row, ...patch } : row));
  }

  async function save() {
    if (!selected) return;
    setSaving(true);
    setError('');
    const pagePaths = pathsText.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    const body = {
      name: selected.name.trim(),
      enabled: selected.enabled,
      captureCookies: selected.captureCookies,
      captureDom: selected.captureDom,
      captureScreenshot: selected.captureScreenshot,
      captureStorage: selected.captureStorage,
      discordNotifications: selected.discordConfigured ? selected.discordNotifications : false,
      probeChecks: selected.probeChecks,
      pagePaths,
      chainloadUrl: selected.chainloadUrl.trim() || null,
    };
    try {
      await apiJson(API + '/collectors/' + encodeURIComponent(selected.id), {
        method: 'PATCH',
        body,
      });
      patchLocal({ pagePaths, discordNotifications: body.discordNotifications });
      notify('success', 'Collector settings saved.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setSaving(false);
    }
  }

  async function rotate() {
    if (!selected) return;
    setRotating(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/collectors/' + encodeURIComponent(selected.id) + '/rotate', {
        method: 'POST',
        body: {},
      }));
      const token = stringValue(payload.token);
      let loaderOrigin = window.location.origin;
      try {
        if (selected.loaderUrl) loaderOrigin = new URL(selected.loaderUrl).origin;
      } catch {
        // Fall back to the current console origin.
      }
      patchLocal({ token, loaderUrl: loaderOrigin + '/p/' + encodeURIComponent(token) + '.js' });
      setReveal(true);
      notify('success', 'Collector token rotated. Old payloads stopped working immediately.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setRotating(false);
    }
  }

  async function createCollector(event: React.FormEvent) {
    event.preventDefault();
    if (!newCollectorName.trim()) return;
    setCreating(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/collectors', {
        method: 'POST',
        body: { name: newCollectorName.trim() },
      }));
      const collector = normalizeCollector(payload.collector);
      if (!collector.id) throw new Error('The new payload response was incomplete.');
      setCollectors((rows) => [...rows, collector]);
      setSelectedId(collector.id);
      setReveal(true);
      setCreateOpen(false);
      setNewCollectorName('New payload');
      notify('success', 'New collector payload created.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setCreating(false);
    }
  }

  async function rotateAlias() {
    if (!selected) return;
    setAliasBusy(true);
    setError('');
    try {
      const payload = asMap(await apiJson(
        API + '/collectors/' + encodeURIComponent(selected.id) + '/alias/rotate',
        { method: 'POST', body: {} },
      ));
      patchLocal({
        alias: stringValue(payload.alias),
        aliasLoaderUrl: stringValue(payload.aliasLoaderUrl || payload.alias_loader_url),
        aliasCreatedAt: numberValue(payload.aliasCreatedAt || payload.alias_created_at),
      });
      notify('success', selected.alias ? 'Short payload rotated.' : 'Short payload created.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setAliasBusy(false);
    }
  }

  async function revokeAlias() {
    if (!selected?.alias) return;
    setAliasBusy(true);
    setError('');
    try {
      await apiJson(API + '/collectors/' + encodeURIComponent(selected.id) + '/alias/revoke', {
        method: 'POST',
        body: {},
      });
      patchLocal({ alias: '', aliasLoaderUrl: '', aliasCreatedAt: null });
      notify('success', 'Short payload revoked. Existing short snippets stopped working.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setAliasBusy(false);
    }
  }

  async function testDiscord() {
    if (!selected?.discordConfigured) return;
    setDiscordTestBusy(true);
    setError('');
    try {
      await apiJson(API + '/collectors/' + encodeURIComponent(selected.id) + '/discord/test', {
        method: 'POST',
        body: {},
      });
      notify('success', 'Metadata-only Discord test notification sent.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setDiscordTestBusy(false);
    }
  }

  const fullScriptUrl = selected && selected.token
    ? selected.loaderUrl || window.location.origin + '/p/' + encodeURIComponent(selected.token) + '.js'
    : '';
  const shortScriptUrl = selected?.aliasLoaderUrl || '';
  const baseScriptUrl = shortScriptUrl || fullScriptUrl;
  const snippets = createPayloadSnippets(baseScriptUrl, payloadParamsText);
  const payloadParamsError = snippets.error;
  const scriptUrl = snippets.loaderUrl;
  const tagSnippet = snippets.scriptTag;
  const compactTagSnippet = snippets.compactScriptTag;
  const breakoutSnippet = snippets.attributeBreakout;
  const imageSnippet = snippets.imageErrorHandler;
  const jsSnippet = snippets.javascriptLoader;

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Payload delivery</p>
          <h1>Collectors</h1>
          <p>Control exactly what your probes capture and where they run.</p>
        </div>
        <div className="heading-actions">
          <button className="button button-primary" type="button" onClick={() => setCreateOpen(true)}>
            <Icon name="code" /> New payload
          </button>
          <button className="button button-secondary" type="button" onClick={load} disabled={loading}>
            {loading ? <Spinner /> : <Icon name="refresh" />} Refresh
          </button>
        </div>
      </div>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      {loading ? (
        <div className="page-loading"><Spinner /><span>Unlocking collector configuration…</span></div>
      ) : !selected ? (
        <EmptyState
          icon="code"
          title="No collectors"
          message="Create a payload to start receiving authorized callbacks."
          action={<button className="button button-primary" type="button" onClick={() => setCreateOpen(true)}>Create payload</button>}
        />
      ) : (
        <div className="collector-layout">
          <aside className="collector-list panel">
            <div className="panel-title"><span>Collectors</span><small>{collectors.length}</small></div>
            {collectors.map((collector) => (
              <button type="button" className={'collector-option ' + (collector.id === selected.id ? 'selected' : '')} key={collector.id} onClick={() => setSelectedId(collector.id)}>
                <span className={'collector-dot ' + (collector.enabled ? 'online' : '')} />
                <span><strong>{collector.name}</strong><small>{collector.enabled ? 'Enabled' : 'Paused'}</small></span>
                <Icon name="chevron" size={15} />
              </button>
            ))}
          </aside>
          <div className="collector-content">
            <section className="panel collector-hero">
              <div>
                <span className={'health-pill ' + (selected.enabled ? 'healthy' : '')}><i /> {selected.enabled ? 'Accepting callbacks' : 'Collector paused'}</span>
                <h2>{selected.name}</h2>
                <p>Created {formatDate(selected.createdAt)} · ID {selected.id}</p>
              </div>
              <Icon name="activity" size={36} />
            </section>
            <section className="panel section-panel">
              <div className="section-title-row">
                <div><h2>Collector secret</h2><p>Embedded in every probe. Rotate it if it may have leaked.</p></div>
                <button className="button button-danger-quiet button-small" type="button" onClick={rotate} disabled={rotating}>
                  {rotating ? <Spinner /> : <Icon name="refresh" size={15} />}
                  {rotating ? 'Rotating…' : 'Rotate token'}
                </button>
              </div>
              <div className="token-display">
                <code>{reveal ? selected.token : '••••••••••••••••••••••••••••••••••••••••••••'}</code>
                <button className="icon-button" type="button" onClick={() => setReveal(!reveal)} aria-label={reveal ? 'Hide token' : 'Reveal token'}>
                  <Icon name={reveal ? 'eyeOff' : 'eye'} size={17} />
                </button>
                <CopyButton value={selected.token} />
              </div>
            </section>
            <section className="panel section-panel">
              <div className="section-title-row">
                <div><h2>Payload snippets</h2><p>Use only in systems where you have explicit testing authorization.</p></div>
                <span className="badge"><Icon name="code" size={12} /> {shortScriptUrl ? 'compact alias' : 'full token'}</span>
              </div>
              <label className="payload-params-field">
                <span>Callback labels / query parameters</span>
                <input
                  value={payloadParamsText}
                  onChange={(event) => setPayloadParamsText(event.target.value)}
                  placeholder="url=checkout-form&aa"
                  maxLength={1_600}
                />
                <small className={payloadParamsError ? 'field-error' : ''}>
                  {payloadParamsError || <>Optional. Up to 16 parameters (1 KB total), including an empty flag such as <code>aa</code>, are signed and shown with the capture.</>}
                </small>
              </label>
              {selected.token && !payloadParamsError ? (
                <div className="snippet-list">
                  <Snippet label={shortScriptUrl ? 'Short loader URL' : 'Loader URL'} value={scriptUrl} />
                  <Snippet label="Script tag" value={tagSnippet} />
                  <Snippet label="Compact script tag" value={compactTagSnippet} />
                  <Snippet label="Attribute breakout" value={breakoutSnippet} />
                  <Snippet label="Image error handler" value={imageSnippet} />
                  <Snippet label="JavaScript loader" value={jsSnippet} />
                </div>
              ) : !selected.token ? (
                <EmptyState icon="key" title="Token unavailable" message="Rotate the collector token to issue and reveal a new one." />
              ) : null}
            </section>
            <section className="panel section-panel">
              <div className="section-title-row">
                <div>
                  <h2>Short payload</h2>
                  <p>Use a revocable 128-bit alias instead of exposing the longer collector token.</p>
                </div>
                <button className="button button-secondary button-small" type="button" onClick={rotateAlias} disabled={aliasBusy}>
                  {aliasBusy ? <Spinner /> : <Icon name="refresh" size={15} />}
                  {aliasBusy ? 'Updatingâ€¦' : selected.alias ? 'Rotate short URL' : 'Create short URL'}
                </button>
              </div>
              {selected.alias ? (
                <>
                  <div className="token-display short-url-display">
                    <code>{selected.aliasLoaderUrl}</code>
                    <CopyButton value={selected.aliasLoaderUrl} />
                  </div>
                  <div className="short-url-footer">
                    <small>Created {selected.aliasCreatedAt ? formatDate(selected.aliasCreatedAt) : 'recently'}. Rotation or revocation immediately disables the old alias.</small>
                    <button className="button button-danger-quiet button-small" type="button" onClick={revokeAlias} disabled={aliasBusy}>Revoke</button>
                  </div>
                </>
              ) : (
                <p className="section-copy">No short URL is active. The full-token payload continues to work.</p>
              )}
            </section>
            <section className="panel section-panel settings-panel">
              <div className="section-title-row">
                <div><h2>Capture policy</h2><p>Minimize collection to what your engagement requires.</p></div>
              </div>
              <label className="settings-name">
                <span>Collector name</span>
                <input value={selected.name} onChange={(e) => patchLocal({ name: e.target.value })} maxLength={80} />
              </label>
              <div className="toggle-list">
                <Toggle checked={selected.enabled} onChange={(value) => patchLocal({ enabled: value })} label="Enable collector" detail="Accept and store new callbacks." />
                <Toggle checked={selected.captureCookies} onChange={(value) => patchLocal({ captureCookies: value })} label="Capture accessible cookies" detail="Includes only cookies visible to page JavaScript." />
                <Toggle checked={selected.captureDom} onChange={(value) => patchLocal({ captureDom: value })} label="Capture DOM snapshot" detail="Stores HTML and visible text as encrypted inert data." />
                <Toggle checked={selected.captureScreenshot} onChange={(value) => patchLocal({ captureScreenshot: value })} label="Capture screenshot" detail="Adds a browser-rendered image when supported." />
                <Toggle checked={selected.captureStorage} onChange={(value) => patchLocal({ captureStorage: value })} label="Capture browser storage" detail="Encrypts bounded localStorage and sessionStorage key/value pairs. Disabled by default." />
                <Toggle checked={selected.probeChecks} onChange={(value) => patchLocal({ probeChecks: value })} label="Run exposure checks" detail="Test configured pages and same-origin security signals." />
              </div>
              <div className="notification-settings">
                <div className="section-title-row">
                  <div>
                    <h3>Discord notifications</h3>
                    <p>Only collector name, event ID, and receipt time leave the vault. Capture contents are never included.</p>
                  </div>
                  <button
                    className="button button-secondary button-small"
                    type="button"
                    onClick={testDiscord}
                    disabled={!selected.discordConfigured || discordTestBusy}
                  >
                    {discordTestBusy ? <Spinner /> : <Icon name="activity" size={15} />}
                    {discordTestBusy ? 'Sendingâ€¦' : 'Send test'}
                  </button>
                </div>
                <Toggle
                  checked={selected.discordNotifications}
                  onChange={(value) => patchLocal({ discordNotifications: value })}
                  label="Notify Discord for this payload"
                  detail={selected.discordConfigured
                    ? 'Delivery runs after encrypted storage succeeds and does not delay the callback response.'
                    : 'Set the DISCORD_WEBHOOK_URL Cloudflare secret, redeploy, then refresh this page.'}
                  disabled={!selected.discordConfigured}
                />
              </div>
              <div className="settings-grid">
                <label>
                  <span>Same-origin paths to check</span>
                  <textarea value={pathsText} onChange={(e) => setPathsText(e.target.value)} rows={5} placeholder={'/admin\n/.git/HEAD'} />
                  <small>One absolute path per line. Keep this list narrowly scoped.</small>
                </label>
                <label>
                  <span>Optional chainload URL</span>
                  <input
                    type="url"
                    value={selected.chainloadUrl}
                    onChange={(e) => patchLocal({ chainloadUrl: e.target.value })}
                    placeholder="https://authorized.example/payload.js"
                  />
                  <small>Only HTTPS is accepted. Leave empty unless your workflow requires it.</small>
                </label>
              </div>
              <div className="panel-actions">
                <button className="button button-primary" type="button" onClick={save} disabled={saving || !selected.name.trim()}>
                  {saving ? <Spinner /> : <Icon name="check" />} {saving ? 'Saving…' : 'Save policy'}
                </button>
              </div>
            </section>
          </div>
        </div>
      )}
      {createOpen && (
        <Modal title="Create payload" onClose={() => !creating && setCreateOpen(false)}>
          <form className="modal-form" onSubmit={createCollector}>
            <label>
              <span>Payload name</span>
              <input
                autoFocus
                value={newCollectorName}
                onChange={(event) => setNewCollectorName(event.target.value)}
                maxLength={80}
                required
              />
            </label>
            <p>Each payload gets an independent token, capture policy, and optional short alias.</p>
            <div className="panel-actions">
              <button className="button button-quiet" type="button" onClick={() => setCreateOpen(false)} disabled={creating}>Cancel</button>
              <button className="button button-primary" type="submit" disabled={creating || !newCollectorName.trim()}>
                {creating ? <Spinner /> : <Icon name="code" />} {creating ? 'Creatingâ€¦' : 'Create payload'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function SecurityPage({ notify }: { notify: (tone: Notice['tone'], message: string) => void }) {
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [adding, setAdding] = useState(false);
  const [newName, setNewName] = useState('Backup passkey');
  const [removing, setRemoving] = useState('');
  const [oneTime, setOneTime] = useState<OneTimeData | null>(null);
  const [rotating, setRotating] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/passkeys'));
      setPasskeys(asList(payload.passkeys).map(normalizePasskey).filter((item) => item.id));
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function addPasskey(event: React.FormEvent) {
    event.preventDefault();
    setAdding(true);
    setError('');
    try {
      const options = asMap(await apiJson(AUTH + '/passkeys/options', {
        method: 'POST',
        body: { name: newName.trim() },
      }));
      const credential = await startRegistration({
        optionsJSON: options.options as Parameters<typeof startRegistration>[0]['optionsJSON'],
      });
      await apiJson(AUTH + '/passkeys/verify', {
        method: 'POST',
        body: { response: credential },
      });
      setNewName('Backup passkey');
      await load();
      notify('success', 'Passkey added.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setAdding(false);
    }
  }

  async function removePasskey(id: string) {
    setRemoving(id);
    setError('');
    try {
      await apiJson(API + '/passkeys/' + encodeURIComponent(id), { method: 'DELETE', body: {} });
      setPasskeys((items) => items.filter((item) => item.id !== id));
      notify('success', 'Passkey removed and active sessions revalidated.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setRemoving('');
    }
  }

  async function rotateRecovery() {
    setRotating('recovery');
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/recovery-codes/rotate', { method: 'POST', body: {} }));
      setOneTime({
        title: 'New recovery codes',
        message: 'All previous recovery codes are now invalid. Save this new set offline before closing.',
        recoveryCodes: asList(payload.recoveryCodes).map((item) => stringValue(item)),
      });
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setRotating('');
    }
  }

  async function rotateInjectionToken() {
    setRotating('injection');
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/injection-token/rotate', { method: 'POST', body: {} }));
      setOneTime({
        title: 'New injection API token',
        message: 'The previous API token is revoked. Update your authorized tooling now; this token will not be shown again.',
        token: stringValue(payload.token),
        tokenLabel: 'Injection API token',
      });
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setRotating('');
    }
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Identity and access</p>
          <h1>Security</h1>
          <p>Hardware-backed access, recovery, and scoped automation credentials.</p>
        </div>
        <span className="security-grade"><Icon name="shield" size={17} /> Passwordless</span>
      </div>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      <div className="security-grid">
        <section className="panel section-panel passkey-panel">
          <div className="section-title-row">
            <div><h2>Passkeys</h2><p>Keep at least two passkeys in separate physical locations.</p></div>
            <span className="count-pill">{passkeys.length}</span>
          </div>
          {loading ? (
            <div className="table-loading"><Spinner /><span>Loading passkeys…</span></div>
          ) : (
            <div className="passkey-list">
              {passkeys.map((passkey) => (
                <div className="passkey-row" key={passkey.id}>
                  <span className="passkey-icon"><Icon name="key" /></span>
                  <span className="passkey-info">
                    <strong>{passkey.name}</strong>
                    <small>
                      {passkey.backedUp ? 'Synced passkey' : 'Device-bound'}
                      {' · Added ' + formatDate(passkey.createdAt)}
                      {' · Last used ' + (passkey.lastUsedAt ? relativeTime(passkey.lastUsedAt) : 'never')}
                    </small>
                  </span>
                  <span className="badge">{passkey.deviceType}</span>
                  <button
                    className="icon-button danger"
                    type="button"
                    onClick={() => removePasskey(passkey.id)}
                    disabled={removing === passkey.id || passkeys.length <= 1}
                    aria-label={'Remove ' + passkey.name}
                    title={passkeys.length <= 1 ? 'The last passkey cannot be removed' : 'Remove passkey'}
                  >
                    {removing === passkey.id ? <Spinner /> : <Icon name="trash" size={16} />}
                  </button>
                </div>
              ))}
            </div>
          )}
          <form className="add-passkey" onSubmit={addPasskey}>
            <label>
              <span>New passkey name</span>
              <input value={newName} onChange={(e) => setNewName(e.target.value)} maxLength={80} required />
            </label>
            <button className="button button-secondary" type="submit" disabled={adding || !newName.trim()}>
              {adding ? <Spinner /> : <Icon name="key" />} {adding ? 'Waiting…' : 'Add passkey'}
            </button>
          </form>
        </section>
        <section className="panel section-panel">
          <span className="security-card-icon"><Icon name="shield" /></span>
          <h2>Recovery codes</h2>
          <p className="security-card-copy">Replace your offline emergency codes. Rotation immediately invalidates the previous set.</p>
          <ul className="mini-checks">
            <li><Icon name="check" size={14} /> Eight single-use codes</li>
            <li><Icon name="check" size={14} /> Stored as keyed hashes</li>
            <li><Icon name="check" size={14} /> Requires fresh passkey approval</li>
          </ul>
          <button className="button button-secondary button-full" type="button" onClick={rotateRecovery} disabled={Boolean(rotating)}>
            {rotating === 'recovery' ? <Spinner /> : <Icon name="refresh" />} Rotate recovery codes
          </button>
        </section>
        <section className="panel section-panel">
          <span className="security-card-icon violet"><Icon name="code" /></span>
          <h2>Injection API token</h2>
          <p className="security-card-copy">Issue one narrow token for correlating authorized injection requests with callbacks.</p>
          <div className="scope-display">
            <span>Scope</span><code>injection:write</code>
          </div>
          <button className="button button-secondary button-full" type="button" onClick={rotateInjectionToken} disabled={Boolean(rotating)}>
            {rotating === 'injection' ? <Spinner /> : <Icon name="refresh" />} Rotate API token
          </button>
        </section>
        <section className="panel section-panel security-notes">
          <span className="security-card-icon amber"><Icon name="lock" /></span>
          <h2>Session controls</h2>
          <p>Sessions are bound to your browser signature, expire on inactivity, and require another passkey touch before sensitive reads or changes.</p>
          <div className="control-row"><span>Idle timeout</span><strong>15 minutes</strong></div>
          <div className="control-row"><span>Fresh approval window</span><strong>5 minutes</strong></div>
          <div className="control-row"><span>Cookie policy</span><strong>Host-only · Strict</strong></div>
        </section>
      </div>
      {oneTime && (
        <Modal title="Save this secret" onClose={() => undefined} wide>
          <OneTimeSecrets data={oneTime} modal onDone={() => {
            setOneTime(null);
            notify('success', 'Credential rotation completed.');
          }} />
        </Modal>
      )}
    </>
  );
}

function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [nextCursor, setNextCursor] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState('');

  const load = useCallback(async (cursor = '', append = false) => {
    append ? setLoadingMore(true) : setLoading(true);
    setError('');
    try {
      const query = new URLSearchParams({ limit: '50' });
      if (cursor) query.set('cursor', cursor);
      const payload = asMap(await apiJson(API + '/audit?' + query.toString()));
      const rows = asList(payload.entries).map(normalizeAudit);
      setEntries((current) => append ? [...current, ...rows] : rows);
      setNextCursor(stringValue(payload.nextCursor || payload.next_cursor));
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Tamper-evident trail</p>
          <h1>Audit log</h1>
          <p>Security-sensitive activity without exposing raw IP addresses or browser fingerprints.</p>
        </div>
        <button className="button button-secondary" type="button" onClick={() => load()} disabled={loading}>
          {loading ? <Spinner /> : <Icon name="refresh" />} Refresh
        </button>
      </div>
      <section className="panel audit-panel">
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        {loading ? (
          <div className="table-loading"><Spinner /><span>Loading audit trail…</span></div>
        ) : entries.length === 0 ? (
          <EmptyState icon="audit" title="No audit entries" message="Security activity will be recorded here." />
        ) : (
          <div className="audit-table">
            <div className="audit-head"><span>Result</span><span>Action</span><span>Target</span><span>Time</span><span /></div>
            {entries.map((entry, index) => (
              <React.Fragment key={entry.id || entry.requestId || String(index)}>
                <button className="audit-row" type="button" onClick={() => setExpanded(expanded === entry.id ? '' : entry.id)}>
                  <span><i className={'result-dot ' + entry.result} />{entry.result}</span>
                  <strong>{entry.action}</strong>
                  <span>{[entry.targetType, entry.targetId].filter(Boolean).join(' · ') || '—'}</span>
                  <span title={formatDate(entry.createdAt)}>{relativeTime(entry.createdAt)}</span>
                  <Icon name="chevron" size={15} />
                </button>
                {expanded === entry.id && (
                  <div className="audit-detail">
                    <div><span>Request ID</span><code>{entry.requestId || 'not recorded'}</code></div>
                    <div><span>Metadata</span><pre>{pretty(entry.metadata)}</pre></div>
                    <div><span>Recorded</span><code>{formatDate(entry.createdAt)}</code></div>
                  </div>
                )}
              </React.Fragment>
            ))}
          </div>
        )}
        {nextCursor && (
          <div className="load-more">
            <button className="button button-secondary" type="button" onClick={() => load(nextCursor, true)} disabled={loadingMore}>
              {loadingMore ? <Spinner /> : null}{loadingMore ? 'Loading…' : 'Load older entries'}
            </button>
          </div>
        )}
      </section>
    </>
  );
}

function oobInteractionHeadline(interaction: OobInteraction): string {
  const method = stringValue(interaction.summary.method, 'REQUEST');
  const path = stringValue(interaction.summary.path, '/');
  return `${method} ${path}`.trim();
}

function OobInteractionDrawer({
  interaction,
  onClose,
  onDeleted,
  onRead,
}: {
  interaction: OobInteraction;
  onClose: () => void;
  onDeleted: (id: string) => void;
  onRead: (id: string) => void;
}) {
  const [payload, setPayload] = useState<JsonMap | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    let alive = true;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    apiJson(API + '/oob/interactions/' + encodeURIComponent(interaction.id), { signal: controller.signal })
      .then((result) => {
        if (!alive) return;
        const map = asMap(result);
        setPayload(asMap(map.interaction || map));
        setLoading(false);
        if (!interaction.isRead) {
          apiJson(API + '/oob/interactions/' + encodeURIComponent(interaction.id) + '/read', {
            method: 'POST',
            body: { read: true },
          }).then(() => onRead(interaction.id)).catch(() => undefined);
        }
      })
      .catch((caught) => {
        if (alive) {
          setError(friendlyError(caught));
          setLoading(false);
        }
      });
    return () => {
      alive = false;
      controller.abort();
    };
  }, [interaction.id, interaction.isRead, onRead]);

  async function remove() {
    setDeleting(true);
    setError('');
    try {
      await apiJson(API + '/oob/interactions/' + encodeURIComponent(interaction.id), { method: 'DELETE', body: {} });
      onDeleted(interaction.id);
      onClose();
    } catch (caught) {
      setError(friendlyError(caught));
      setDeleting(false);
    }
  }

  const full = payload || {};
  const summary = asMap(full.summary || interaction.summary);
  const detail = asMap(full.detail);
  const network = asMap(detail.network);
  const headers = asList(detail.headers)
    .map((item) => asMap(item))
    .map((item) => `${stringValue(item.name)}: ${stringValue(item.value)}`)
    .join('\n');
  const bodyEncoding = stringValue(detail.bodyEncoding, 'utf-8');
  const bodyTruncated = booleanValue(detail.bodyTruncated);
  const blocks = [
    { title: 'Request', value: {
      method: detail.method ?? summary.method,
      host: detail.host ?? summary.host,
      path: detail.path ?? summary.path,
      query: detail.query ?? summary.query,
      matchedBy: detail.matchedBy ?? summary.matchedBy,
    } },
    { title: 'Network', value: {
      ip: network.ip ?? summary.ip,
      country: network.country ?? summary.country,
      city: network.city,
      colo: network.colo,
      asn: network.asn,
      tlsVersion: network.tlsVersion,
      userAgent: summary.userAgent,
    } },
    { title: 'Request headers', value: headers },
    {
      title: `Request body${bodyEncoding === 'base64url' ? ' (base64url)' : ''}${bodyTruncated ? ' · truncated' : ''}`,
      value: detail.body,
    },
  ].filter((block) => hasContent(block.value) && (!(typeof block.value === 'object') || Object.values(block.value as object).some(hasContent)));

  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={(e) => {
      if (e.currentTarget === e.target) onClose();
    }}>
      <aside className="event-drawer" role="dialog" aria-modal="true" aria-label="Interaction details">
        <header className="drawer-header">
          <div>
            <span className="eyebrow">Out-of-band interaction</span>
            <h2>{oobInteractionHeadline(interaction)}</h2>
            <p>{formatDate(interaction.receivedAt)} · {interaction.probeName}</p>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close details"><Icon name="close" /></button>
        </header>
        {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
        {loading ? (
          <div className="drawer-loading"><Spinner /><span>Decrypting interaction…</span></div>
        ) : (
          <div className="drawer-body">
            <div className="capture-warning">
              <Icon name="shield" size={17} />
              The captured request is rendered as inert text. Nothing from it is ever executed.
            </div>
            {blocks.map((block) => (
              <section className="detail-section" key={block.title}>
                <h3>{block.title}</h3>
                <pre className="capture-pre">{pretty(block.value)}</pre>
              </section>
            ))}
            <section className="detail-section record-section">
              <h3>Record</h3>
              <pre className="capture-pre">{pretty({
                interactionId: interaction.id,
                probeId: interaction.probeId,
                receivedAt: interaction.receivedAt,
                detailBytes: interaction.detailBytes,
              })}</pre>
            </section>
          </div>
        )}
        <footer className="drawer-footer">
          {confirmDelete ? (
            <div className="delete-confirm">
              <span>Delete this interaction permanently?</span>
              <button className="button button-danger button-small" type="button" onClick={remove} disabled={deleting}>
                {deleting ? <Spinner /> : <Icon name="trash" size={15} />} Delete
              </button>
              <button className="button button-quiet button-small" type="button" onClick={() => setConfirmDelete(false)} disabled={deleting}>Cancel</button>
            </div>
          ) : (
            <button className="button button-danger-quiet button-small" type="button" onClick={() => setConfirmDelete(true)}>
              <Icon name="trash" size={15} /> Delete interaction
            </button>
          )}
        </footer>
      </aside>
    </div>
  );
}

function OobPage({ notify }: { notify: (tone: Notice['tone'], message: string) => void }) {
  const [probes, setProbes] = useState<OobProbe[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newProbeName, setNewProbeName] = useState('New listener');
  const [error, setError] = useState('');
  const [reveal, setReveal] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [interactions, setInteractions] = useState<OobInteraction[]>([]);
  const [interactionCursor, setInteractionCursor] = useState('');
  const [interactionsLoading, setInteractionsLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [selectedInteraction, setSelectedInteraction] = useState<OobInteraction | null>(null);

  const selected = probes.find((probe) => probe.id === selectedId) || probes[0] || null;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/oob'));
      const rows = asList(payload.probes).map(normalizeOobProbe).filter((row) => row.id);
      setProbes(rows);
      setSelectedId((current) => rows.some((row) => row.id === current) ? current : rows[0]?.id || '');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const loadInteractions = useCallback(async (probeId: string, cursor = '', append = false) => {
    if (!probeId) {
      setInteractions([]);
      setInteractionCursor('');
      return;
    }
    append ? setLoadingMore(true) : setInteractionsLoading(true);
    try {
      const query = new URLSearchParams({ limit: '50', probeId });
      if (cursor) query.set('cursor', cursor);
      const payload = asMap(await apiJson(API + '/oob/interactions?' + query.toString()));
      const rows = asList(payload.interactions).map(normalizeOobInteraction).filter((row) => row.id);
      setInteractions((current) => append ? [...current, ...rows] : rows);
      setInteractionCursor(stringValue(payload.nextCursor || payload.next_cursor));
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setInteractionsLoading(false);
      setLoadingMore(false);
    }
  }, []);

  useEffect(() => {
    setReveal(false);
    setSelectedInteraction(null);
    if (selected?.id) void loadInteractions(selected.id);
    else {
      setInteractions([]);
      setInteractionCursor('');
    }
  }, [selected?.id, loadInteractions]);

  function patchLocal(patch: Partial<OobProbe>) {
    if (!selected) return;
    setProbes((rows) => rows.map((row) => row.id === selected.id ? { ...row, ...patch } : row));
  }

  async function createProbe(event: React.FormEvent) {
    event.preventDefault();
    if (!newProbeName.trim()) return;
    setCreating(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/oob', { method: 'POST', body: { name: newProbeName.trim() } }));
      const probe = normalizeOobProbe(payload.probe);
      if (!probe.id) throw new Error('The new listener response was incomplete.');
      setProbes((rows) => [...rows, probe]);
      setSelectedId(probe.id);
      setReveal(true);
      setCreateOpen(false);
      setNewProbeName('New listener');
      notify('success', 'New OOB listener created.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setCreating(false);
    }
  }

  async function save() {
    if (!selected) return;
    setSaving(true);
    setError('');
    const body = {
      name: selected.name.trim(),
      enabled: selected.enabled,
      discordNotifications: selected.discordConfigured ? selected.discordNotifications : false,
    };
    try {
      await apiJson(API + '/oob/' + encodeURIComponent(selected.id), { method: 'PATCH', body });
      patchLocal({ discordNotifications: body.discordNotifications });
      notify('success', 'Listener settings saved.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setSaving(false);
    }
  }

  async function rotate() {
    if (!selected) return;
    setRotating(true);
    setError('');
    try {
      const payload = asMap(await apiJson(API + '/oob/' + encodeURIComponent(selected.id) + '/rotate', {
        method: 'POST',
        body: {},
      }));
      patchLocal({
        token: stringValue(payload.token),
        pathLoaderUrl: stringValue(payload.pathLoaderUrl || payload.path_loader_url),
        hostLoaderUrl: stringValue(payload.hostLoaderUrl || payload.host_loader_url),
      });
      setReveal(true);
      notify('success', 'Listener token rotated. Old callback URLs stopped working immediately.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setRotating(false);
    }
  }

  async function removeProbe() {
    if (!selected) return;
    if (!window.confirm(`Delete the listener "${selected.name}" and every captured interaction? This cannot be undone.`)) return;
    setDeleting(true);
    setError('');
    const probeId = selected.id;
    try {
      let deleted = false;
      while (!deleted) {
        const payload = asMap(await apiJson(API + '/oob/' + encodeURIComponent(probeId), { method: 'DELETE', body: {} }));
        deleted = booleanValue(payload.deleted);
      }
      setProbes((rows) => rows.filter((row) => row.id !== probeId));
      setSelectedId((current) => current === probeId ? '' : current);
      notify('success', 'Listener and its interactions deleted.');
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setDeleting(false);
    }
  }

  async function clearInteractions() {
    if (!selected) return;
    if (!window.confirm('Permanently delete every captured interaction for this listener?')) return;
    setClearing(true);
    setError('');
    let removed = 0;
    try {
      let remaining = true;
      while (remaining) {
        const payload = asMap(await apiJson(API + '/oob/interactions', {
          method: 'DELETE',
          body: { all: true, probeId: selected.id, confirmation: 'DELETE OOB INTERACTIONS' },
        }));
        removed += asList(payload.deletedIds || payload.deleted_ids).length;
        remaining = booleanValue(payload.remaining);
      }
      setSelectedInteraction(null);
      await loadInteractions(selected.id);
      notify('success', `Deleted ${removed.toLocaleString()} interactions.`);
    } catch (caught) {
      setError(friendlyError(caught));
    } finally {
      setClearing(false);
    }
  }

  const markInteractionRead = useCallback((id: string) => {
    setInteractions((rows) => rows.map((row) => row.id === id ? { ...row, isRead: true } : row));
    setSelectedInteraction((current) => current?.id === id ? { ...current, isRead: true } : current);
  }, []);

  function removeInteraction(id: string) {
    setInteractions((rows) => rows.filter((row) => row.id !== id));
    notify('success', 'Interaction deleted.');
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Out-of-band callbacks</p>
          <h1>OOB server</h1>
          <p>Catch blind SSRF, RCE, XXE, and other server-side callbacks over HTTP(S).</p>
        </div>
        <div className="heading-actions">
          <button className="button button-primary" type="button" onClick={() => setCreateOpen(true)}>
            <Icon name="globe" /> New listener
          </button>
          <button className="button button-secondary" type="button" onClick={load} disabled={loading}>
            {loading ? <Spinner /> : <Icon name="refresh" />} Refresh
          </button>
        </div>
      </div>
      {error && <ErrorBanner message={error} onDismiss={() => setError('')} />}
      {loading ? (
        <div className="page-loading"><Spinner /><span>Unlocking listener configuration…</span></div>
      ) : !selected ? (
        <EmptyState
          icon="globe"
          title="No OOB listeners"
          message="Create a listener to get a unique callback URL for out-of-band interaction testing."
          action={<button className="button button-primary" type="button" onClick={() => setCreateOpen(true)}>Create listener</button>}
        />
      ) : (
        <div className="collector-layout">
          <aside className="collector-list panel">
            <div className="panel-title"><span>Listeners</span><small>{probes.length}</small></div>
            {probes.map((probe) => (
              <button type="button" className={'collector-option ' + (probe.id === selected.id ? 'selected' : '')} key={probe.id} onClick={() => setSelectedId(probe.id)}>
                <span className={'collector-dot ' + (probe.enabled ? 'online' : '')} />
                <span><strong>{probe.name}</strong><small>{probe.enabled ? 'Listening' : 'Paused'}</small></span>
                <Icon name="chevron" size={15} />
              </button>
            ))}
          </aside>
          <div className="collector-content">
            <section className="panel collector-hero">
              <div>
                <span className={'health-pill ' + (selected.enabled ? 'healthy' : '')}><i /> {selected.enabled ? 'Accepting callbacks' : 'Listener paused'}</span>
                <h2>{selected.name}</h2>
                <p>Created {formatDate(selected.createdAt)} · ID {selected.id}</p>
              </div>
              <Icon name="globe" size={36} />
            </section>
            <section className="panel section-panel">
              <div className="section-title-row">
                <div><h2>Listener token</h2><p>Embedded in every callback URL. Rotate it if it may have leaked.</p></div>
                <button className="button button-danger-quiet button-small" type="button" onClick={rotate} disabled={rotating}>
                  {rotating ? <Spinner /> : <Icon name="refresh" size={15} />}
                  {rotating ? 'Rotating…' : 'Rotate token'}
                </button>
              </div>
              <div className="token-display">
                <code>{reveal ? selected.token : '••••••••••••••••••••••••••'}</code>
                <button className="icon-button" type="button" onClick={() => setReveal(!reveal)} aria-label={reveal ? 'Hide token' : 'Reveal token'}>
                  <Icon name={reveal ? 'eyeOff' : 'eye'} size={17} />
                </button>
                <CopyButton value={selected.token} />
              </div>
            </section>
            <section className="panel section-panel">
              <div className="section-title-row">
                <div><h2>Callback URLs</h2><p>Use only against systems you are explicitly authorized to test. Any method and path is captured.</p></div>
                <span className="badge"><Icon name="globe" size={12} /> HTTP(S)</span>
              </div>
              <div className="snippet-list">
                <Snippet label="Path callback (works out of the box)" value={selected.pathLoaderUrl} />
                {selected.hostLoaderUrl ? (
                  <Snippet label="Subdomain callback (wildcard host configured)" value={selected.hostLoaderUrl} />
                ) : null}
              </div>
              {!selected.hostLoaderUrl && (
                <p className="section-copy">
                  Set the <code>OOB_WILDCARD_HOST</code> variable and route its wildcard to this Worker to also capture
                  bare-hostname callbacks such as <code>&lt;token&gt;.oob.example.com</code>.
                </p>
              )}
            </section>
            <section className="panel section-panel settings-panel">
              <div className="section-title-row">
                <div><h2>Listener policy</h2></div>
              </div>
              <label className="settings-name">
                <span>Listener name</span>
                <input value={selected.name} onChange={(e) => patchLocal({ name: e.target.value })} maxLength={80} />
              </label>
              <div className="toggle-list">
                <Toggle checked={selected.enabled} onChange={(value) => patchLocal({ enabled: value })} label="Enable listener" detail="Accept and store new out-of-band interactions." />
              </div>
              <div className="notification-settings">
                <div className="section-title-row">
                  <div>
                    <h3>Discord notifications</h3>
                    <p>Only listener name, interaction ID, HTTP method, and receipt time leave the vault.</p>
                  </div>
                </div>
                <Toggle
                  checked={selected.discordNotifications}
                  onChange={(value) => patchLocal({ discordNotifications: value })}
                  label="Notify Discord for this listener"
                  detail={selected.discordConfigured
                    ? 'Delivery runs after encrypted storage succeeds and does not delay the callback response.'
                    : 'Set the DISCORD_WEBHOOK_URL Cloudflare secret, redeploy, then refresh this page.'}
                  disabled={!selected.discordConfigured}
                />
              </div>
              <div className="panel-actions">
                <button className="button button-danger-quiet" type="button" onClick={removeProbe} disabled={deleting || saving}>
                  {deleting ? <Spinner /> : <Icon name="trash" />} {deleting ? 'Deleting…' : 'Delete listener'}
                </button>
                <button className="button button-primary" type="button" onClick={save} disabled={saving || !selected.name.trim()}>
                  {saving ? <Spinner /> : <Icon name="check" />} {saving ? 'Saving…' : 'Save policy'}
                </button>
              </div>
            </section>
            <section className="panel event-panel">
              <div className="section-title-row">
                <div><h2>Interactions</h2><p>Encrypted out-of-band requests received by this listener.</p></div>
                <div className="heading-actions">
                  <button className="button button-danger-quiet button-small" type="button" onClick={clearInteractions} disabled={clearing || interactions.length === 0}>
                    {clearing ? <Spinner /> : <Icon name="trash" size={15} />} {clearing ? 'Clearing…' : 'Clear'}
                  </button>
                  <button className="button button-secondary button-small" type="button" onClick={() => loadInteractions(selected.id)} disabled={interactionsLoading}>
                    {interactionsLoading ? <Spinner /> : <Icon name="refresh" size={15} />} Refresh
                  </button>
                </div>
              </div>
              {interactionsLoading ? (
                <div className="table-loading"><Spinner /><span>Loading encrypted interactions…</span></div>
              ) : interactions.length === 0 ? (
                <EmptyState
                  icon="activity"
                  title="Waiting for the first callback"
                  message="Place this listener's URL in an authorized test and interactions will appear here."
                />
              ) : (
                <div className="event-list" role="list">
                  {interactions.map((interaction) => (
                    <button className={'event-row ' + (!interaction.isRead ? 'event-unread' : '')} type="button" key={interaction.id} onClick={() => setSelectedInteraction(interaction)} role="listitem">
                      <span className="event-state">{!interaction.isRead && <i />}</span>
                      <span className="event-main">
                        <span className="event-title">{oobInteractionHeadline(interaction)}</span>
                        <span className="event-url">{stringValue(interaction.summary.query) ? '?' + stringValue(interaction.summary.query) : stringValue(interaction.summary.host, 'no host')}</span>
                      </span>
                      <span className="event-badges">
                        {stringValue(interaction.summary.matchedBy) && <span className="badge">{stringValue(interaction.summary.matchedBy)}</span>}
                        {numberValue(interaction.summary.bodyBytes || interaction.summary.body_bytes) > 0 && <span className="badge">body</span>}
                      </span>
                      <span className="event-meta">
                        <strong>{stringValue(interaction.summary.ip) || stringValue(interaction.summary.country) || '—'}</strong>
                        <span title={formatDate(interaction.receivedAt)}>{relativeTime(interaction.receivedAt)}</span>
                      </span>
                      <Icon name="chevron" size={17} />
                    </button>
                  ))}
                </div>
              )}
              {interactionCursor && (
                <div className="load-more">
                  <button className="button button-secondary" type="button" onClick={() => loadInteractions(selected.id, interactionCursor, true)} disabled={loadingMore}>
                    {loadingMore ? <Spinner /> : null}{loadingMore ? 'Loading…' : 'Load older interactions'}
                  </button>
                </div>
              )}
            </section>
          </div>
        </div>
      )}
      {createOpen && (
        <Modal title="Create OOB listener" onClose={() => !creating && setCreateOpen(false)}>
          <form className="modal-form" onSubmit={createProbe}>
            <label>
              <span>Listener name</span>
              <input
                autoFocus
                value={newProbeName}
                onChange={(event) => setNewProbeName(event.target.value)}
                maxLength={80}
                required
              />
            </label>
            <p>Each listener gets an independent, DNS- and path-safe token and its own callback URL.</p>
            <div className="panel-actions">
              <button className="button button-quiet" type="button" onClick={() => setCreateOpen(false)} disabled={creating}>Cancel</button>
              <button className="button button-primary" type="submit" disabled={creating || !newProbeName.trim()}>
                {creating ? <Spinner /> : <Icon name="globe" />} {creating ? 'Creating…' : 'Create listener'}
              </button>
            </div>
          </form>
        </Modal>
      )}
      {selectedInteraction && (
        <OobInteractionDrawer
          interaction={selectedInteraction}
          onClose={() => setSelectedInteraction(null)}
          onDeleted={removeInteraction}
          onRead={markInteractionRead}
        />
      )}
    </>
  );
}

const navigation: Array<{ id: View; label: string; icon: IconName; hint: string }> = [
  { id: 'events', label: 'Events', icon: 'events', hint: 'Capture inbox' },
  { id: 'collectors', label: 'Payloads', icon: 'code', hint: 'Collectors' },
  { id: 'oob', label: 'OOB', icon: 'globe', hint: 'Out-of-band server' },
  { id: 'security', label: 'Security', icon: 'security', hint: 'Access controls' },
  { id: 'audit', label: 'Audit', icon: 'audit', hint: 'Activity trail' },
];

function currentHash(): View {
  const value = window.location.hash.replace(/^#\/?/, '');
  return navigation.some((item) => item.id === value) ? value as View : 'events';
}

function Dashboard({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const [view, setView] = useState<View>(currentHash);
  const [menuOpen, setMenuOpen] = useState(false);
  const [stepUpBusy, setStepUpBusy] = useState(false);
  const [notices, setNotices] = useState<Notice[]>([]);
  const noticeCounter = useRef(0);

  useEffect(() => {
    stepUpStateHandler = setStepUpBusy;
    function hashChanged() {
      setView(currentHash());
      setMenuOpen(false);
    }
    window.addEventListener('hashchange', hashChanged);
    return () => {
      window.removeEventListener('hashchange', hashChanged);
      stepUpStateHandler = null;
    };
  }, []);

  function navigate(next: View) {
    window.location.hash = next;
    setView(next);
    setMenuOpen(false);
  }

  function notify(tone: Notice['tone'], message: string) {
    const id = ++noticeCounter.current;
    setNotices((current) => [...current, { id, tone, message }]);
    window.setTimeout(() => setNotices((current) => current.filter((notice) => notice.id !== id)), 4200);
  }

  async function logout() {
    try {
      await apiJson(AUTH + '/logout', { method: 'POST', body: {}, allowStepUp: false });
    } catch {
      // The local authenticated view must still close if the server already ended the session.
    }
    onLogout();
  }

  const active = navigation.find((item) => item.id === view) || navigation[0];
  return (
    <div className="app-shell">
      <aside className={'sidebar ' + (menuOpen ? 'sidebar-open' : '')}>
        <div className="sidebar-top">
          <Brand />
          <button className="icon-button mobile-close" type="button" onClick={() => setMenuOpen(false)} aria-label="Close navigation"><Icon name="close" /></button>
        </div>
        <div className="vault-chip">
          <span className="vault-avatar"><Icon name="shield" size={17} /></span>
          <span><strong>Private vault</strong><small><i /> Operational</small></span>
        </div>
        <nav aria-label="Primary">
          <p>Workspace</p>
          {navigation.map((item) => (
            <a
              href={'#' + item.id}
              className={view === item.id ? 'active' : ''}
              key={item.id}
              onClick={(event) => {
                event.preventDefault();
                navigate(item.id);
              }}
            >
              <Icon name={item.icon} />
              <span><strong>{item.label}</strong><small>{item.hint}</small></span>
            </a>
          ))}
        </nav>
        <div className="sidebar-security">
          <Icon name="lock" size={16} />
          <span><strong>Defense in depth</strong><small>App-encrypted R2 · CSRF locked</small></span>
        </div>
        <div className="sidebar-user">
          <span className="user-avatar">{(session.user.displayName || session.user.email).slice(0, 1).toUpperCase()}</span>
          <span><strong>{session.user.displayName}</strong><small>{session.user.email}</small></span>
          <button className="icon-button" type="button" onClick={logout} aria-label="Sign out" title="Sign out"><Icon name="logout" size={17} /></button>
        </div>
      </aside>
      {menuOpen && <button className="sidebar-scrim" type="button" onClick={() => setMenuOpen(false)} aria-label="Close navigation" />}
      <div className="workspace">
        <header className="topbar">
          <button className="icon-button menu-button" type="button" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Icon name="menu" /></button>
          <div><Icon name={active.icon} size={17} /><span>{active.label}</span></div>
          <div className="topbar-security"><span className="status-dot" /> Passkey session · expires {relativeTime(session.expiresAt)}</div>
        </header>
        <main className="page-content">
          {view === 'events' && <EventsPage notify={notify} />}
          {view === 'collectors' && <CollectorsPage notify={notify} />}
          {view === 'oob' && <OobPage notify={notify} />}
          {view === 'security' && <SecurityPage notify={notify} />}
          {view === 'audit' && <AuditPage />}
        </main>
      </div>
      {stepUpBusy && (
        <div className="step-up-toast" role="status">
          <span className="pulse-lock"><Icon name="key" size={17} /></span>
          <span><strong>Fresh approval required</strong><small>Touch your passkey to continue securely.</small></span>
          <Spinner />
        </div>
      )}
      <div className="toast-stack" aria-live="polite">
        {notices.map((notice) => (
          <div className={'toast toast-' + notice.tone} key={notice.id}>
            <Icon name={notice.tone === 'success' ? 'check' : notice.tone === 'danger' ? 'shield' : 'activity'} size={17} />
            <span>{notice.message}</span>
            <button className="icon-button" type="button" onClick={() => setNotices((items) => items.filter((item) => item.id !== notice.id))} aria-label="Dismiss">
              <Icon name="close" size={14} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function App() {
  const [phase, setPhase] = useState<'loading' | 'bootstrap' | 'login' | 'ready'>('loading');
  const [rpName, setRpName] = useState('BXSS Vault');
  const [session, setSession] = useState<Session | null>(null);
  const [oneTime, setOneTime] = useState<OneTimeData | null>(null);
  const [fatal, setFatal] = useState('');

  const lock = useCallback(() => {
    setCsrf('');
    window.location.replace('/');
  }, []);

  const acceptSession = useCallback((next: Session) => {
    setSession(next);
    setPhase('ready');
  }, []);

  useEffect(() => {
    authExpiredHandler = lock;
    return () => {
      authExpiredHandler = null;
    };
  }, [lock]);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const status = asMap(await apiJson(AUTH + '/status', { allowStepUp: false }));
        if (!alive) return;
        setRpName(stringValue(status.rp, 'BXSS Vault'));
        if (!booleanValue(status.initialized)) {
          setPhase('bootstrap');
          return;
        }
        try {
          const me = asMap(await apiJson(AUTH + '/me', { allowStepUp: false }));
          if (!alive) return;
          setCsrf(stringValue(me.csrfToken || me.csrf_token));
          acceptSession(normalizeSession(me));
        } catch (caught) {
          if (caught instanceof ApiError && caught.status === 401) {
            if (alive) setPhase('login');
          } else {
            throw caught;
          }
        }
      } catch (caught) {
        if (alive) {
          setFatal(friendlyError(caught));
          setPhase('login');
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, [acceptSession]);

  async function finishOneTime() {
    setOneTime(null);
    try {
      const me = asMap(await apiJson(AUTH + '/me', { allowStepUp: false }));
      setCsrf(stringValue(me.csrfToken || me.csrf_token, csrfToken));
      acceptSession(normalizeSession(me));
    } catch (caught) {
      setFatal(friendlyError(caught));
      setPhase('login');
    }
  }

  if (phase === 'loading') {
    return (
      <main className="boot-screen">
        <Brand />
        <div className="boot-orbit"><Icon name="shield" size={25} /></div>
        <p>Establishing a secure session…</p>
      </main>
    );
  }

  if (oneTime) return <OneTimeSecrets data={oneTime} onDone={finishOneTime} />;

  if (phase === 'bootstrap') {
    return <Bootstrap rpName={rpName} onComplete={(data, csrf) => {
      setCsrf(csrf);
      setOneTime(data);
    }} />;
  }

  if (phase === 'login' || !session) {
    return (
      <>
        {fatal && <div className="fatal-float"><ErrorBanner message={fatal} onDismiss={() => setFatal('')} /></div>}
        <Login rpName={rpName} onAuthenticated={acceptSession} />
      </>
    );
  }

  return <Dashboard session={session} onLogout={lock} />;
}

class AppErrorBoundary extends React.Component<{ children: React.ReactNode }, { error: string }> {
  state = { error: '' };

  static getDerivedStateFromError(error: unknown) {
    return { error: friendlyError(error) };
  }

  render() {
    if (this.state.error) {
      return (
        <main className="crash-screen">
          <Brand />
          <div className="crash-card">
            <Icon name="shield" size={28} />
            <h1>The dashboard stopped safely</h1>
            <p>{this.state.error}</p>
            <button className="button button-primary" type="button" onClick={() => window.location.reload()}>Reload vault</button>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Application root not found');
createRoot(rootElement).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>,
);
