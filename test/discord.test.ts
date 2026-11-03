import { describe, expect, it } from 'vitest';
import { discordCaptureBody, validDiscordWebhookUrl } from '../src/lib/discord';

const webhookToken = 'A'.repeat(68);

describe('Discord notification security', () => {
  it('accepts only canonical HTTPS Discord webhook endpoints', () => {
    const valid = `https://discord.com/api/webhooks/123456789012345678/${webhookToken}`;
    expect(validDiscordWebhookUrl(valid)).toBe(valid);
    expect(validDiscordWebhookUrl(valid + '?wait=true')).toBeNull();
    expect(validDiscordWebhookUrl(valid.replace('discord.com', 'discord.example'))).toBeNull();
    expect(validDiscordWebhookUrl(valid.replace('https:', 'http:'))).toBeNull();
    expect(validDiscordWebhookUrl(`https://discord.com.evil.invalid/api/webhooks/123/${webhookToken}`)).toBeNull();
  });

  it('builds a metadata-only payload with mentions disabled', () => {
    const body = discordCaptureBody({
      eventId: '7e66a7fb-a507-4280-a513-096fe79da79e',
      collectorName: '@everyone\u202E Primary collector',
      receivedAt: 1_700_000_000,
    });
    const serialized = JSON.stringify(body);
    expect(body.allowed_mentions).toEqual({ parse: [] });
    expect(serialized).toContain('7e66a7fb-a507-4280-a513-096fe79da79e');
    expect(serialized).toContain('Primary collector');
    expect(serialized).not.toContain('\u202E');
    for (const forbidden of ['cookies', 'localStorage', 'sessionStorage', 'domHtml', 'screenshot', 'referrer']) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});
