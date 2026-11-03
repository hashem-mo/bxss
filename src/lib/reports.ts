import { randomToken } from './encoding';
import type { CapturedEvent, EventSummary } from '../types';

export const REPORT_TOKEN_BYTES = 16;
export const REPORT_TOKEN_LENGTH = 22;
export const MAX_REPORT_EVENTS = 8;
export const MAX_ACTIVE_REPORTS = 20;
export const DEFAULT_REPORT_EXPIRY_DAYS = 7;
export const MAX_REPORT_EXPIRY_DAYS = 30;
export const MAX_REPORT_PAYLOAD_BYTES = 8_388_608;
const reportTokenPattern = /^[A-Za-z0-9_-]{22}$/;

export interface SharedReportEvent {
  id: string;
  collectorName: string;
  receivedAt: number;
  summary: EventSummary;
  detail: CapturedEvent;
  correlatedRequest: unknown;
  screenshot: { mime: string } | null;
}

export interface SharedReportPayload {
  schemaVersion: 1;
  id: string;
  title: string;
  generatedAt: number;
  expiresAt: number;
  events: SharedReportEvent[];
}

export function isReportToken(value: string): boolean {
  return reportTokenPattern.test(value);
}

export function createReportToken(): string {
  return randomToken(REPORT_TOKEN_BYTES);
}

export function detectImageType(bytes: Uint8Array): { mime: string; extension: string } | null {
  if (
    bytes.length >= 8
    && bytes[0] === 0x89
    && bytes[1] === 0x50
    && bytes[2] === 0x4e
    && bytes[3] === 0x47
    && bytes[4] === 0x0d
    && bytes[5] === 0x0a
    && bytes[6] === 0x1a
    && bytes[7] === 0x0a
  ) {
    return { mime: 'image/png', extension: 'png' };
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return { mime: 'image/jpeg', extension: 'jpg' };
  }
  return null;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatUtc(seconds: number): string {
  const millis = seconds > 10_000_000_000 ? seconds : seconds * 1000;
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) return 'Unknown time';
  return `${new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(date)} UTC`;
}

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

function sourceLabel(event: SharedReportEvent): string {
  const candidates = [event.summary.sourceLabel];
  for (const value of candidates) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function eventHeadline(event: SharedReportEvent): string {
  const title = event.detail.title || event.summary.title;
  const url = event.detail.url || event.summary.url;
  const origin = event.detail.origin || event.summary.origin;
  return title || url || origin || 'Untitled capture';
}

function eventBlocks(event: SharedReportEvent): Array<{ title: string; value: unknown }> {
  const placement = sourceLabel(event);
  return [
    {
      title: 'Location and browser',
      value: {
        placement: placement || undefined,
        url: event.detail.url || event.summary.url,
        origin: event.detail.origin || event.summary.origin,
        title: event.detail.title || event.summary.title,
        referrer: event.detail.referrer || event.summary.referrer,
        userAgent: event.detail.userAgent || event.summary.userAgent,
        browserTime: event.detail.browserTime,
        wasIframe: event.detail.wasIframe,
        viewport: event.detail.viewport,
        country: event.summary.country || undefined,
      },
    },
    { title: 'Payload parameters', value: event.summary.payloadParams },
    { title: 'Cookies', value: event.detail.cookies },
    { title: 'Detected secrets', value: event.detail.secrets },
    { title: 'DOM text', value: event.detail.domText },
    { title: 'DOM snapshot (inert text)', value: event.detail.domHtml },
    { title: 'Local storage', value: event.detail.localStorage },
    { title: 'Session storage', value: event.detail.sessionStorage },
    { title: 'Page checks', value: event.detail.pages },
    { title: 'Probe checks', value: { cors: event.detail.cors, gitExposed: event.detail.gitExposed } },
    { title: 'Correlated injection request', value: event.correlatedRequest },
  ].filter((block) => {
    if (!hasContent(block.value)) return false;
    if (typeof block.value !== 'object' || block.value === null) return true;
    return Object.values(block.value as object).some(hasContent);
  });
}

const REPORT_CSS = `
:root {
  color-scheme: dark;
  --bg: #080b10;
  --surface: #10161f;
  --raised: #141c27;
  --border: #243044;
  --text: #edf3f8;
  --muted: #8b98a8;
  --cyan: #40e2c1;
  --danger: #ff8b98;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  min-height: 100%;
  background: radial-gradient(circle at 80% -10%, rgba(64,226,193,.07), transparent 36%), var(--bg);
  color: var(--text);
  font: 15px/1.5 Inter, ui-sans-serif, system-ui, sans-serif;
}
body { padding: 28px 18px 64px; }
main { width: min(920px, 100%); margin: 0 auto; }
.masthead {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
  margin-bottom: 22px;
  padding-bottom: 18px;
  border-bottom: 1px solid var(--border);
}
.brand { color: var(--cyan); font-size: 11px; font-weight: 760; letter-spacing: .16em; text-transform: uppercase; }
h1 { margin: 8px 0 6px; font-size: clamp(26px, 4vw, 36px); letter-spacing: -.04em; font-weight: 620; }
.meta, .kicker { color: var(--muted); font-size: 13px; }
.stats { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
.stat {
  min-width: 92px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--surface);
  text-align: right;
}
.stat strong { display: block; font-size: 18px; }
.stat span { color: var(--muted); font-size: 11px; }
.notice {
  display: flex;
  gap: 10px;
  margin: 0 0 22px;
  padding: 12px 14px;
  border: 1px solid rgba(64,226,193,.16);
  border-radius: 12px;
  color: #9bb8b6;
  background: rgba(64,226,193,.05);
  font-size: 13px;
}
article {
  margin-bottom: 16px;
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: 16px;
  background: linear-gradient(160deg, rgba(18,24,34,.96), rgba(12,16,24,.98));
}
.capture-head { margin-bottom: 16px; }
.capture-head h2 { margin: 0 0 6px; font-size: 20px; letter-spacing: -.02em; overflow-wrap: anywhere; }
.capture-head p { margin: 0; color: var(--muted); font-size: 12px; }
.placement {
  display: inline-block;
  margin-top: 10px;
  padding: 3px 9px;
  border: 1px solid rgba(64,226,193,.2);
  border-radius: 99px;
  color: #9fd0c7;
  font-size: 11px;
}
.shot {
  margin: 0 0 16px;
  overflow: hidden;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: #070b10;
}
.shot img { display: block; width: 100%; height: auto; }
section { margin-top: 14px; }
section h3 {
  margin: 0 0 8px;
  color: #c5d0db;
  font-size: 12px;
  letter-spacing: .04em;
  text-transform: uppercase;
}
pre {
  margin: 0;
  padding: 12px;
  overflow: auto;
  border: 1px solid #1e2734;
  border-radius: 10px;
  background: #0b1118;
  color: #d5dee7;
  font: 12px/1.45 "Cascadia Code", ui-monospace, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.page-foot {
  margin-top: 28px;
  color: var(--muted);
  font-size: 12px;
}
@media print {
  :root { color-scheme: light; }
  html, body { background: #fff; color: #111; }
  .notice, article, .stat, .shot, pre { border-color: #ccc; background: #fff; color: #111; }
}
`.trim();

export function renderReportHtml(payload: SharedReportPayload, token: string): string {
  const screenshotCount = payload.events.filter((event) => event.screenshot).length;
  const uniqueOrigins = new Set(
    payload.events.map((event) => event.detail.origin || event.summary.origin).filter(Boolean),
  );
  const articles = payload.events.map((event, index) => {
    const headline = escapeHtml(eventHeadline(event));
    const placement = sourceLabel(event);
    const shot = event.screenshot
      ? `<div class="shot"><img src="/r/${encodeURIComponent(token)}/s/${encodeURIComponent(event.id)}" alt="Capture screenshot ${index + 1}"></div>`
      : '';
    const blocks = eventBlocks(event)
      .map((block) => `<section><h3>${escapeHtml(block.title)}</h3><pre>${escapeHtml(pretty(block.value))}</pre></section>`)
      .join('');
    return `<article>
      <div class="capture-head">
        <h2>${headline}</h2>
        <p>${escapeHtml(event.collectorName)} · ${escapeHtml(formatUtc(event.receivedAt))}</p>
        ${placement ? `<span class="placement">${escapeHtml(placement)}</span>` : ''}
      </div>
      ${shot}
      ${blocks}
    </article>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>${escapeHtml(payload.title)} · BXSS Vault report</title>
  <style>${REPORT_CSS}</style>
</head>
<body>
  <main>
    <header class="masthead">
      <div>
        <div class="brand">BXSS Vault</div>
        <h1>${escapeHtml(payload.title)}</h1>
        <p class="meta">Generated ${escapeHtml(formatUtc(payload.generatedAt))} · Expires ${escapeHtml(formatUtc(payload.expiresAt))}</p>
      </div>
      <div class="stats">
        <div class="stat"><strong>${payload.events.length}</strong><span>captures</span></div>
        <div class="stat"><strong>${screenshotCount}</strong><span>screenshots</span></div>
        <div class="stat"><strong>${uniqueOrigins.size}</strong><span>origins</span></div>
      </div>
    </header>
    <p class="notice">Captured values are rendered as inert text. Links, scripts, and markup from the target are never executed. Treat this URL as a credential.</p>
    ${articles}
    <p class="page-foot">Read-only snapshot. This page does not require vault login. The link stops working when it expires or is revoked.</p>
  </main>
</body>
</html>`;
}

export function emptyReportHtml(message: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Report unavailable</title>
  <style>${REPORT_CSS}</style>
</head>
<body>
  <main>
    <div class="brand">BXSS Vault</div>
    <h1>Report unavailable</h1>
    <p class="meta">${escapeHtml(message)}</p>
  </main>
</body>
</html>`;
}
