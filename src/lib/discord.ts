import type { Env } from '../types';

const DISCORD_TIMEOUT_MS = 5_000;
const webhookPathPattern = /^\/api(?:\/v\d+)?\/webhooks\/[0-9]{10,30}\/[A-Za-z0-9._-]{40,200}$/;

export interface DiscordCaptureNotice {
  eventId: string;
  collectorName: string;
  receivedAt: number;
}

export interface DiscordOobNotice {
  interactionId: string;
  probeName: string;
  method: string;
  receivedAt: number;
}

export function validDiscordWebhookUrl(value: string | undefined): string | null {
  if (!value || value.length > 512) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:'
      || url.hostname !== 'discord.com'
      || url.port
      || url.username
      || url.password
      || url.search
      || url.hash
      || !webhookPathPattern.test(url.pathname)
    ) return null;
    return url.toString();
  } catch {
    return null;
  }
}

export function discordWebhookConfigured(env: Env): boolean {
  return Boolean(validDiscordWebhookUrl(env.DISCORD_WEBHOOK_URL));
}

function plainDiscordText(value: string, max: number): string {
  return Array.from(value)
    .slice(0, max)
    .join('')
    .normalize('NFKC')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();
}

export function discordCaptureBody(notice: DiscordCaptureNotice): Record<string, unknown> {
  const collectorName = plainDiscordText(notice.collectorName, 80) || 'Collector';
  const timestamp = new Date(notice.receivedAt * 1_000).toISOString();
  return {
    username: 'BXSS Vault',
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: 'New blind XSS capture',
        color: 0x2dd4bf,
        fields: [
          { name: 'Collector', value: collectorName, inline: true },
          { name: 'Event ID', value: notice.eventId, inline: true },
          { name: 'Received', value: timestamp, inline: false },
        ],
        footer: { text: 'Metadata only. Open BXSS Vault to view protected details.' },
        timestamp,
      },
    ],
  };
}

export function discordOobBody(notice: DiscordOobNotice): Record<string, unknown> {
  const probeName = plainDiscordText(notice.probeName, 80) || 'Listener';
  const method = plainDiscordText(notice.method, 16) || 'REQUEST';
  const timestamp = new Date(notice.receivedAt * 1_000).toISOString();
  return {
    username: 'BXSS Vault',
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: 'New out-of-band interaction',
        color: 0x818cf8,
        fields: [
          { name: 'Listener', value: probeName, inline: true },
          { name: 'Method', value: method, inline: true },
          { name: 'Interaction ID', value: notice.interactionId, inline: false },
          { name: 'Received', value: timestamp, inline: false },
        ],
        footer: { text: 'Metadata only. Open BXSS Vault to view the captured request.' },
        timestamp,
      },
    ],
  };
}

async function postDiscordWebhook(webhookUrl: string, body: Record<string, unknown>): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DISCORD_TIMEOUT_MS);
  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (response.body) await response.body.cancel();
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function sendDiscordCaptureNotification(
  env: Env,
  notice: DiscordCaptureNotice,
): Promise<boolean> {
  const webhookUrl = validDiscordWebhookUrl(env.DISCORD_WEBHOOK_URL);
  if (!webhookUrl) return false;
  return postDiscordWebhook(webhookUrl, discordCaptureBody(notice));
}

export async function sendDiscordOobNotification(env: Env, notice: DiscordOobNotice): Promise<boolean> {
  const webhookUrl = validDiscordWebhookUrl(env.DISCORD_WEBHOOK_URL);
  if (!webhookUrl) return false;
  return postDiscordWebhook(webhookUrl, discordOobBody(notice));
}

export async function sendDiscordTestNotification(env: Env, collectorName: string): Promise<boolean> {
  const webhookUrl = validDiscordWebhookUrl(env.DISCORD_WEBHOOK_URL);
  if (!webhookUrl) return false;
  return postDiscordWebhook(webhookUrl, {
    username: 'BXSS Vault',
    allowed_mentions: { parse: [] },
    embeds: [
      {
        title: 'Discord notifications connected',
        color: 0x2dd4bf,
        description: `Metadata-only notifications are ready for ${plainDiscordText(collectorName, 80) || 'this collector'}.`,
        footer: { text: 'No capture data was included in this test.' },
        timestamp: new Date().toISOString(),
      },
    ],
  });
}
