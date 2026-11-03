import html2canvas from 'html2canvas';

const MAX_RENDER_SCALE = 2;
const MAX_RENDER_WIDTH = 4_096;
const MAX_RENDER_HEIGHT = 16_384;
const MAX_RENDER_PIXELS = 10_000_000;
const MAX_SCREENSHOT_BYTES = 20_971_520;
const DEFAULT_CAPTURE_ENVELOPE_BYTES = 20_971_520;
const MIN_CAPTURE_ENVELOPE_BYTES = 65_536;
const MAX_CAPTURE_ENVELOPE_BYTES = 20_971_520;
const MAX_ENVELOPE_RESERVE_BYTES = 1_048_576;
const MULTIPART_HEADROOM_BYTES = 16_384;
const MIN_SCREENSHOT_BYTES = 1;
const JPEG_QUALITY_STEPS = [0.9, 0.82, 0.74] as const;
const LEGACY_MAX_WIDTH = 1_600;
const LEGACY_MAX_HEIGHT = 1_200;
const LEGACY_JPEG_QUALITY = 0.72;
// Kept well below our own per-strategy render timeouts (1.6-5s). The old
// 8000ms value could never actually fire first, so a page with a handful of
// slow/broken images just burned our entire external timeout instead of
// html2canvas giving up on them internally and finishing with placeholders.
const IMAGE_LOAD_TIMEOUT_MS = 2_500;
const FAST_FULL_RENDER_TIMEOUT_MS = 2_200;
const FAST_VIEWPORT_RENDER_TIMEOUT_MS = 1_600;
const FAST_MAX_CAPTURE_TIME_MS = 2_800;
const FAST_READINESS_BUDGET_MS = 650;
const RELIABLE_FULL_RENDER_TIMEOUT_MS = 5_000;
const RELIABLE_VIEWPORT_RENDER_TIMEOUT_MS = 2_800;
const RELIABLE_MAX_CAPTURE_TIME_MS = 8_000;
const RELIABLE_READINESS_BUDGET_MS = 1_400;
const TRANSPARENT_PIXEL =
  'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

export type RenderProfile = 'fast' | 'reliable';

function finitePositive(value: number, fallback: number): number {
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

/**
 * Keep full-page text sharp without allocating an unbounded browser canvas.
 * Large documents can fall below 1x only when that is necessary to stay
 * within the pixel and dimension limits.
 */
export function screenshotRenderScale(
  width: number,
  height: number,
  devicePixelRatio: number,
  maxPixels: number = MAX_RENDER_PIXELS,
): number {
  const safeWidth = finitePositive(width, 1);
  const safeHeight = finitePositive(height, 1);
  const density = Math.min(MAX_RENDER_SCALE, Math.max(1, finitePositive(devicePixelRatio, 1)));
  return Math.min(
    density,
    MAX_RENDER_WIDTH / safeWidth,
    MAX_RENDER_HEIGHT / safeHeight,
    Math.sqrt(maxPixels / (safeWidth * safeHeight)),
  );
}

export function screenshotDocumentSize(document: Document): { width: number; height: number } {
  const root = document.documentElement;
  const body = document.body;
  return {
    width: Math.max(
      1,
      root.clientWidth,
      root.scrollWidth,
      root.offsetWidth,
      body?.clientWidth ?? 0,
      body?.scrollWidth ?? 0,
      body?.offsetWidth ?? 0,
    ),
    height: Math.max(
      1,
      root.clientHeight,
      root.scrollHeight,
      root.offsetHeight,
      body?.clientHeight ?? 0,
      body?.scrollHeight ?? 0,
      body?.offsetHeight ?? 0,
    ),
  };
}

/** Leave enough room for the JSON field and multipart framing under the
 * default 20 MiB collector envelope, as well as the server's image-only cap. */
export function screenshotByteBudget(eventBytes: number, configuredEnvelopeBytes?: number): number {
  if (!Number.isFinite(eventBytes) || eventBytes < 0) return 0;
  const envelopeBytes = Number.isFinite(configuredEnvelopeBytes)
    && (configuredEnvelopeBytes as number) >= MIN_CAPTURE_ENVELOPE_BYTES
    && (configuredEnvelopeBytes as number) <= MAX_CAPTURE_ENVELOPE_BYTES
    ? Math.floor(configuredEnvelopeBytes as number)
    : DEFAULT_CAPTURE_ENVELOPE_BYTES;
  const reserveBytes = Math.min(MAX_ENVELOPE_RESERVE_BYTES, Math.floor(envelopeBytes * 0.05));
  const available = Math.floor(envelopeBytes - reserveBytes - eventBytes - MULTIPART_HEADROOM_BYTES);
  return available >= MIN_SCREENSHOT_BYTES ? Math.min(MAX_SCREENSHOT_BYTES, available) : 0;
}

const pause = (milliseconds: number): Promise<void> =>
  new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function waitForDomStability(maximumWait: number): Promise<void> {
  const minimumWait = Math.max(120, Math.floor(maximumWait * 0.3));
  const quietPeriod = Math.max(80, Math.floor(maximumWait * 0.2));

  return new Promise((resolve) => {
    const startedAt = Date.now();
    let lastMutationAt = startedAt;
    let settled = false;
    let quietTimer = 0;

    const finish = (): void => {
      if (settled) return;
      settled = true;
      observer.disconnect();
      window.clearTimeout(quietTimer);
      window.clearTimeout(maximumTimer);
      resolve();
    };

    const check = (): void => {
      const now = Date.now();
      const minimumRemaining = minimumWait - (now - startedAt);
      const quietRemaining = quietPeriod - (now - lastMutationAt);
      const remaining = Math.max(minimumRemaining, quietRemaining);
      if (remaining <= 0) {
        finish();
      } else {
        window.clearTimeout(quietTimer);
        quietTimer = window.setTimeout(check, remaining);
      }
    };

    const observer = new MutationObserver(() => {
      lastMutationAt = Date.now();
      check();
    });
    observer.observe(document.documentElement, {
      attributes: true,
      characterData: true,
      childList: true,
      subtree: true,
    });

    const maximumTimer = window.setTimeout(finish, maximumWait);
    check();
  });
}

async function waitForVisualReadiness(readinessBudgetMs: number, domStabilityMaxMs: number): Promise<void> {
  const readiness: Array<Promise<unknown>> = [];
  if (document.readyState !== 'complete') {
    readiness.push(new Promise<void>((resolve) => window.addEventListener('load', () => resolve(), { once: true })));
  }
  if (document.fonts?.ready) {
    readiness.push(document.fonts.ready);
    try {
      readiness.push(document.fonts.load('16px sans-serif'));
    } catch {
      // Ignore font load bootstrap failures.
    }
  }

  if (readiness.length > 0) {
    await Promise.race([Promise.allSettled(readiness), pause(readinessBudgetMs)]);
  }

  // Give freshly loaded fonts and responsive layout one paint to settle. The
  // timeout also covers throttled/background tabs where rAF may not run.
  await Promise.race([
    new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))),
    pause(40),
  ]);

  // DOMContentLoaded/window.load do not mean an SPA has finished replacing
  // its boot screen with asynchronously fetched content. Capture after the
  // document has stayed quiet briefly, with a hard cap for animated pages.
  await waitForDomStability(domStabilityMaxMs);
  await Promise.race([
    new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))),
    pause(40),
  ]);
}

export type RenderScreenshotResult = {
  canvas: HTMLCanvasElement | null;
  strategy: string | null;
};

type RenderStrategy = {
  id: string;
  target: () => HTMLElement | null;
  scale: number;
  viewportOnly?: boolean;
  foreignObjectRendering?: boolean;
  timeoutMs: number;
};

function isCrossOriginUrl(value: string): boolean {
  try {
    return new URL(value, window.location.href).origin !== window.location.origin;
  } catch {
    return true;
  }
}

function isValidCanvas(canvas: HTMLCanvasElement | null | undefined): canvas is HTMLCanvasElement {
  return Boolean(canvas && canvas.width > 0 && canvas.height > 0);
}

const BLANK_SAMPLE_GRID = 5;

/** The capture background is always painted white (see screenshotOptions).
 * If a grid of sample points across the canvas is entirely that background
 * color (or fully transparent), nothing actually drew - a resource CSP
 * silently blocked, a foreignObjectRendering no-op, a redacted/blank clone,
 * etc. Catching this here means we fall through to the next strategy while
 * there's still budget left, instead of returning a "successful" blank image. */
function looksLikeUsableCapture(canvas: HTMLCanvasElement): boolean {
  const context = canvas.getContext('2d');
  if (!context) return true; // Can't verify - don't block on it.
  try {
    for (let row = 1; row <= BLANK_SAMPLE_GRID; row += 1) {
      for (let col = 1; col <= BLANK_SAMPLE_GRID; col += 1) {
        const x = Math.min(canvas.width - 1, Math.floor((canvas.width * col) / (BLANK_SAMPLE_GRID + 1)));
        const y = Math.min(canvas.height - 1, Math.floor((canvas.height * row) / (BLANK_SAMPLE_GRID + 1)));
        const { data } = context.getImageData(x, y, 1, 1);
        const isWhiteBackground = data[0] === 255 && data[1] === 255 && data[2] === 255 && data[3] === 255;
        const isTransparent = data[3] === 0;
        if (!isWhiteBackground && !isTransparent) return true;
      }
    }
    return false;
  } catch {
    // getImageData throws for a tainted canvas (a cross-origin resource,
    // most often a CSS background-image, slipped through untainted). toBlob
    // would fail the same way later with no time left to recover, so treat
    // it as unusable now instead.
    return false;
  }
}

function ignoreUndrawableElements(element: Element): boolean {
  const tag = element.tagName;
  if (tag === 'IFRAME' || tag === 'FRAME' || tag === 'OBJECT' || tag === 'EMBED' || tag === 'VIDEO' || tag === 'AUDIO') {
    return true;
  }
  const htmlElement = element as HTMLElement;
  // Cheap, layout-free checks only (inline style / reflected attribute) -
  // deliberately not getComputedStyle, which would force a style recalc on
  // every node html2canvas visits and could offset the savings. Component
  // libraries (Radix, Headless UI, MUI, etc.) commonly leave large hidden
  // portal/dropdown/modal subtrees inline-toggled this way; skipping them
  // avoids walking content that will never be visible in the final image.
  if (htmlElement.hidden) return true;
  if (htmlElement.style && htmlElement.style.display === 'none') return true;
  return false;
}

function redactFormValues(clone: Document): void {
  clone.querySelectorAll('input, textarea, select').forEach((node) => {
    // html2canvas creates elements in a cloned document. Cross-realm
    // instanceof checks are unreliable, so discriminate by tag name.
    const tag = node.tagName.toLowerCase();
    if (tag === 'input') {
      const input = node as HTMLInputElement;
      input.value = input.type === 'password' ? '********' : '[redacted input]';
      input.setAttribute('value', input.value);
    } else if (tag === 'textarea') {
      const textarea = node as HTMLTextAreaElement;
      textarea.value = '[redacted input]';
      textarea.textContent = '[redacted input]';
    } else if (tag === 'select') {
      const select = node as unknown as HTMLSelectElement;
      for (const option of select.options) option.selected = false;
    }
  });
}

/** Cross-origin media is the most common source of intermittent html2canvas
 * failures because CORS availability differs by cache state, auth, and profile. */
function neutralizeCrossOriginMedia(clone: Document): void {
  clone.querySelectorAll('img').forEach((node) => {
    const image = node as HTMLImageElement;
    const src = image.currentSrc || image.getAttribute('src') || '';
    if (!src || src.startsWith('data:') || src.startsWith('blob:')) return;
    if (!isCrossOriginUrl(src)) {
      image.crossOrigin = 'anonymous';
      return;
    }
    image.removeAttribute('srcset');
    image.removeAttribute('sizes');
    image.src = TRANSPARENT_PIXEL;
  });

  clone.querySelectorAll('image, use').forEach((node) => {
    const href = node.getAttribute('href') || node.getAttribute('xlink:href') || '';
    if (href && isCrossOriginUrl(href)) {
      node.removeAttribute('href');
      node.removeAttribute('xlink:href');
    }
  });
}

const UNSUPPORTED_COLOR_ERROR_PATTERN = /oklch|oklab|lch\(|lab\(|color-mix|color\(|unsupported color/i;
const UNSUPPORTED_COLOR_VALUE_PATTERN = /oklch|oklab|lch\(|lab\(|color-mix|color\(/i;
const COLOR_PROPERTIES = [
  'color',
  'background-color',
  'border-top-color',
  'border-right-color',
  'border-bottom-color',
  'border-left-color',
  'outline-color',
  'text-decoration-color',
  'caret-color',
  'fill',
  'stroke',
] as const;

let colorProbeContext: CanvasRenderingContext2D | null | undefined;

/** Per the Canvas 2D spec, reading `fillStyle` back after assigning it always
 * yields a normalized rgb()/rgba() serialization, regardless of the input
 * color syntax (oklch, lab, color(), hwb, ...). That gives us a
 * browser-verified conversion to a format html2canvas's parser understands,
 * without having to reimplement CSS color parsing ourselves. */
function normalizedColor(value: string): string | null {
  if (colorProbeContext === undefined) {
    colorProbeContext = document.createElement('canvas').getContext('2d');
  }
  if (!colorProbeContext) return null;
  try {
    colorProbeContext.fillStyle = '#000000';
    colorProbeContext.fillStyle = value;
    return colorProbeContext.fillStyle;
  } catch {
    return null;
  }
}

/** Sidesteps a well-known html2canvas limitation: its color parser throws
 * outright on modern CSS color functions (oklch/oklab/lab/lch/color()/
 * color-mix), which are the default palette format for Tailwind CSS v4 and
 * several other current design systems. This is only invoked as a fallback
 * retry after that specific failure is observed (see attemptRender), so
 * pages that don't use these color functions never pay for it - walking
 * every element's computed style is not cheap. */
function sanitizeUnsupportedColors(clone: Document): void {
  const view = clone.defaultView;
  if (!view) return;
  clone.querySelectorAll<HTMLElement>('*').forEach((element) => {
    let computed: CSSStyleDeclaration;
    try {
      computed = view.getComputedStyle(element);
    } catch {
      return;
    }
    for (const prop of COLOR_PROPERTIES) {
      const raw = computed.getPropertyValue(prop);
      if (!raw || !UNSUPPORTED_COLOR_VALUE_PATTERN.test(raw)) continue;
      const normalized = normalizedColor(raw);
      if (normalized) element.style.setProperty(prop, normalized, 'important');
    }
  });
}

function prepareClonedDocument(sanitizeColors: boolean): (clone: Document) => void {
  return (clone: Document): void => {
    try {
      redactFormValues(clone);
    } catch {
      // Never let redaction break capture.
    }
    try {
      neutralizeCrossOriginMedia(clone);
    } catch {
      // Never let media sanitization break capture.
    }
    if (sanitizeColors) {
      try {
        sanitizeUnsupportedColors(clone);
      } catch {
        // Best-effort only; never let this block capture.
      }
    }
  };
}

function screenshotOptions(): Parameters<typeof html2canvas>[1] {
  return {
    // Deliberately mirror the small, direct html2canvas approach used by
    // lightweight blind-XSS screenshot collectors. The goal here is to let
    // html2canvas render the real document once instead of repeatedly cloning
    // and retrying a large page with many strategies.
    allowTaint: true,
    useCORS: true,
    width: 1024,
    height: 768,
    windowWidth: 1024,
    windowHeight: 768,
    scrollX: 0,
    scrollY: 0,
    backgroundColor: '#ffffff',
    logging: false,
    imageTimeout: IMAGE_LOAD_TIMEOUT_MS,
    onclone: (clone: Document): void => {
      try {
        redactFormValues(clone);
      } catch {
        // Redaction is best-effort and must never prevent the screenshot.
      }
    },
  };
}

/**
 * Capture exactly one fixed-size browser viewport.
 *
 * The old implementation tried several render strategies and used
 * Promise.race() as a timeout around html2canvas. That timeout could not
 * cancel html2canvas, so failed attempts continued rendering in the
 * background while the next attempt started. This implementation intentionally
 * performs one direct html2canvas render, matching the proven lightweight
 * pattern used by Xless-style collectors.
 */
export async function renderScreenshot(_profile: RenderProfile = 'fast'): Promise<RenderScreenshotResult> {
  try {
    const element = document.querySelector('html');
    if (!(element instanceof HTMLElement)) {
      return { canvas: null, strategy: null };
    }

    // Single lightweight capture pass, matching the simple html2canvas
    // approach used by the original implementation.
    const canvas = await html2canvas(element, {
      useCORS: true
 
    });

    if (!isValidCanvas(canvas)) {
      return { canvas: null, strategy: null };
    }

    return { canvas, strategy: 'html2canvas_simple' };
  } catch {
    return { canvas: null, strategy: null };
  }
}

function jpegBlob(canvas: HTMLCanvasElement, quality: number): Promise<Blob | null> {
  return new Promise((resolve) => {
    try {
      canvas.toBlob(resolve, 'image/jpeg', quality);
    } catch {
      resolve(null);
    }
  });
}

function downscaleCanvas(source: HTMLCanvasElement, factor: number): HTMLCanvasElement | null {
  const target = document.createElement('canvas');
  target.width = Math.max(1, Math.floor(source.width * factor));
  target.height = Math.max(1, Math.floor(source.height * factor));
  if (target.width === source.width && target.height === source.height) return null;

  const context = target.getContext('2d');
  if (!context) return null;
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = 'high';
  context.fillStyle = '#ffffff';
  context.fillRect(0, 0, target.width, target.height);
  context.drawImage(source, 0, 0, target.width, target.height);
  return target;
}

function fitCanvasWithin(source: HTMLCanvasElement, maxWidth: number, maxHeight: number): HTMLCanvasElement | null {
  const ratio = Math.min(1, maxWidth / source.width, maxHeight / source.height);
  if (ratio >= 1) return source;
  return downscaleCanvas(source, ratio);
}

/** Prefer a high-quality JPEG, then progressively trade quality and dimensions
 * only when needed so the blind callback is not rejected for being too large.
 * A legacy-sized fallback is tried before giving up, preserving the old
 * "save a screenshot if at all possible" behavior.
 *
 * JPEG size is monotonic in quality for fixed dimensions, so each pass
 * probes the cheapest (lowest-quality) encode first: if that alone already
 * exceeds the budget, the higher-quality steps are guaranteed to exceed it
 * too, and we skip straight to downscaling instead of burning two more
 * encode calls to confirm something we can already infer. A rough upfront
 * pre-shrink also avoids spending several full-resolution encode+downscale
 * passes on canvases that are dramatically larger than the byte budget could
 * ever allow (common for full-page captures against a small beacon budget). */
export async function encodeScreenshot(canvas: HTMLCanvasElement, maxBytes: number): Promise<Blob | null> {
  try {
    if (!Number.isFinite(maxBytes) || maxBytes < MIN_SCREENSHOT_BYTES) return null;

    let working = canvas;
    let triedLegacyFit = false;

    const roughBytesPerPixel = 0.4; // conservative JPEG estimate around quality ~0.74
    const rawPixels = working.width * working.height;
    if (rawPixels * roughBytesPerPixel > maxBytes * 4) {
      const preScale = Math.sqrt((maxBytes * 3) / (rawPixels * roughBytesPerPixel));
      const preShrunk = downscaleCanvas(working, Math.max(0.2, Math.min(0.9, preScale)));
      if (preShrunk) working = preShrunk;
    }

    const lowestQuality = JPEG_QUALITY_STEPS[JPEG_QUALITY_STEPS.length - 1];

    for (;;) {
      const probe = await jpegBlob(working, lowestQuality);
      if (!probe) return null;

      if (probe.size <= maxBytes) {
        let best = probe;
        for (let i = JPEG_QUALITY_STEPS.length - 2; i >= 0; i -= 1) {
          const encoded = await jpegBlob(working, JPEG_QUALITY_STEPS[i]);
          if (encoded && encoded.size <= maxBytes) {
            best = encoded;
          } else {
            break; // Higher qualities only get larger; no point probing further.
          }
        }
        return best;
      }

      if (!triedLegacyFit && (working.width > LEGACY_MAX_WIDTH || working.height > LEGACY_MAX_HEIGHT)) {
        const legacyCanvas = fitCanvasWithin(canvas, LEGACY_MAX_WIDTH, LEGACY_MAX_HEIGHT);
        const legacyEncoded = legacyCanvas ? await jpegBlob(legacyCanvas, LEGACY_JPEG_QUALITY) : null;
        if (legacyEncoded && legacyEncoded.size <= maxBytes) return legacyEncoded;
        if (legacyCanvas && legacyCanvas !== working) {
          working = legacyCanvas;
          triedLegacyFit = true;
          continue;
        }
        triedLegacyFit = true;
      }

      if (working.width <= 320 && working.height <= 320) return null;
      const estimatedFit = Math.sqrt(maxBytes / probe.size) * 0.94;
      const factor = Math.max(0.5, Math.min(0.85, estimatedFit));
      const smaller = downscaleCanvas(working, factor);
      if (!smaller) return null;
      working = smaller;
    }
  } catch {
    // Screenshot failure must never prevent the rest of the blind callback.
    return null;
  }
}