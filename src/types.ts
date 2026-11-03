export interface Env {
  DB: D1Database;
  VAULT: R2Bucket;
  ASSETS: Fetcher;
  COLLECTOR_RATE_LIMITER: RateLimit;
  AUTH_RATE_LIMITER: RateLimit;
  AUTH_PEPPER: string;
  DATA_ENCRYPTION_KEY: string;
  BOOTSTRAP_TOKEN: string;
  DISCORD_WEBHOOK_URL?: string;
  RP_NAME?: string;
  RP_ID?: string;
  APP_ORIGIN?: string;
  COLLECTOR_ORIGIN?: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  SESSION_IDLE_SECONDS?: string;
  SESSION_ABSOLUTE_SECONDS?: string;
  MAX_CAPTURE_BYTES?: string;
  MAX_STORAGE_BYTES?: string;
  MAX_EVENTS_PER_DAY?: string;
  RETENTION_DAYS?: string;
  OOB_WILDCARD_HOST?: string;
}

export type Variables = {
  session: SessionContext;
  requestId: string;
};

export interface SessionContext {
  tokenHash: string;
  userId: string;
  email: string;
  displayName: string;
  role: 'owner' | 'analyst';
  csrfToken: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  stepUpUntil: number;
  sessionVersion: number;
}

export interface CollectorRecord {
  id: string;
  user_id: string;
  name: string;
  token_hash: string;
  token_ciphertext: string;
  token_iv: string;
  enabled: number;
  capture_cookies: number;
  capture_dom: number;
  capture_screenshot: number;
  capture_storage: number;
  discord_notifications: number;
  probe_checks: number;
  page_paths: string;
  chainload_url: string | null;
  created_at: number;
  updated_at: number;
}

export interface CapturedEvent {
  schemaVersion: 1;
  probeUid: string;
  injectionKey: string;
  url: string;
  origin: string;
  referrer: string;
  userAgent: string;
  title: string;
  browserTime: number;
  wasIframe: boolean;
  cookies: string;
  domHtml: string;
  domText: string;
  localStorage: Array<{ key: string; value: string }>;
  sessionStorage: Array<{ key: string; value: string }>;
  viewport: { width: number; height: number; devicePixelRatio: number };
  screenshotDiagnostics?: {
    requested: boolean;
    status: string;
    canvasWidth?: number;
    canvasHeight?: number;
    budgetBytes?: number;
    encodedBytes?: number;
  };
  secrets: Array<{ type: string; value: string }>;
  cors: string | false;
  gitExposed: string | false;
  pages: Array<{ path: string; url: string; status: number; body: string }>;
}

export interface OobProbeRecord {
  id: string;
  user_id: string;
  name: string;
  token_hash: string;
  token_ciphertext: string;
  token_iv: string;
  enabled: number;
  discord_notifications: number;
  created_at: number;
  updated_at: number;
}

export interface OobInteractionSummary {
  method: string;
  host: string;
  path: string;
  query: string;
  matchedBy: 'path' | 'host';
  ip: string;
  country: string;
  userAgent: string;
  headerCount: number;
  bodyBytes: number;
  bodyTruncated: boolean;
  receivedAt: number;
}

export interface EventSummary {
  sourceLabel: string;
  payloadParams: Array<{ name: string; value: string }>;
  url: string;
  origin: string;
  title: string;
  referrer: string;
  userAgent: string;
  wasIframe: boolean;
  browserTime: number;
  country: string;
  hasScreenshot: boolean;
  secretCount: number;
  storageItemCount: number;
  hasCorrelatedRequest: boolean;
}
