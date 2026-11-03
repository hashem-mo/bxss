import { describe, expect, it } from 'vitest';
import {
  COLLECTOR_ALIAS_BYTES,
  COLLECTOR_ALIAS_LENGTH,
  PAYLOAD_PARAM_MAX_COUNT,
  SOURCE_LABEL_MAX_BYTES,
  canonicalPayloadParams,
  createCollectorAlias,
  encodePayloadParams,
  encodeSourceLabel,
  isCollectorAlias,
  normalizeSourceLabel,
  payloadParamsFromLoaderUrl,
  sourceLabelFromLoaderUrl,
} from '../src/lib/collector-identifiers';
import { base64UrlToBytes } from '../src/lib/encoding';

describe('collector aliases', () => {
  it('generates canonical 128-bit base64url aliases', () => {
    const aliases = new Set(Array.from({ length: 128 }, createCollectorAlias));
    expect(aliases.size).toBe(128);
    for (const alias of aliases) {
      expect(alias).toHaveLength(COLLECTOR_ALIAS_LENGTH);
      expect(isCollectorAlias(alias)).toBe(true);
      expect(base64UrlToBytes(alias)).toHaveLength(COLLECTOR_ALIAS_BYTES);
    }
  });

  it('rejects non-canonical or incorrectly sized aliases', () => {
    expect(isCollectorAlias('A'.repeat(COLLECTOR_ALIAS_LENGTH - 1))).toBe(false);
    expect(isCollectorAlias(`${'A'.repeat(COLLECTOR_ALIAS_LENGTH - 1)}=`)).toBe(false);
    expect(isCollectorAlias(`/${'A'.repeat(COLLECTOR_ALIAS_LENGTH - 1)}`)).toBe(false);
  });
});

describe('source label normalization', () => {
  it('normalizes compatibility characters, controls, bidi formatting, and whitespace', () => {
    expect(normalizeSourceLabel('  Ｅxample\u0000\t\u202E   placement\u00a0 ')).toBe('Example placement');
  });

  it('caps UTF-8 without splitting an astral code point', () => {
    const normalized = normalizeSourceLabel('😀'.repeat(100));
    expect(new TextEncoder().encode(normalized).byteLength).toBe(SOURCE_LABEL_MAX_BYTES);
    expect(Array.from(normalized)).toHaveLength(SOURCE_LABEL_MAX_BYTES / 4);
    expect(normalized).not.toMatch(/[\ud800-\udfff]$/u);
  });

  it('is idempotent and keeps the value as plain text rather than parsing it as a URL', () => {
    const label = '</script> "not a url" / footer';
    expect(normalizeSourceLabel(normalizeSourceLabel(label))).toBe(label);
    expect(encodeSourceLabel(label)).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('accepts exactly one url parameter and drops ambiguous duplicates', () => {
    expect(sourceLabelFromLoaderUrl(new URL('https://collector.invalid/p/x.js?url=example.com'))).toBe(
      'example.com',
    );
    expect(sourceLabelFromLoaderUrl(new URL('https://collector.invalid/p/x.js?url=one&url=two'))).toBe('');
  });
});

describe('payload query parameters', () => {
  it('preserves order, duplicates, and bare flags as inert metadata', () => {
    const params = payloadParamsFromLoaderUrl(
      new URL('https://collector.invalid/a/alias.js?url=checkout%20form&aa&tag=one&tag=two'),
    );
    expect(params).toEqual([
      { name: 'url', value: 'checkout form' },
      { name: 'aa', value: '' },
      { name: 'tag', value: 'one' },
      { name: 'tag', value: 'two' },
    ]);
    expect(canonicalPayloadParams(params)).toEqual(params);
    expect(encodePayloadParams(params ?? [])).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('rejects the entire metadata set rather than silently truncating limits', () => {
    const tooMany = new URL('https://collector.invalid/p/token.js');
    for (let index = 0; index <= PAYLOAD_PARAM_MAX_COUNT; index += 1) {
      tooMany.searchParams.append(`p${index}`, 'x');
    }
    expect(payloadParamsFromLoaderUrl(tooMany)).toBeNull();

    const tooLarge = new URL('https://collector.invalid/p/token.js');
    tooLarge.searchParams.set('value', 'x'.repeat(2_000));
    expect(payloadParamsFromLoaderUrl(tooLarge)).toBeNull();
  });

  it('rejects non-canonical signed metadata shapes', () => {
    expect(canonicalPayloadParams([{ name: ' flag ', value: '' }])).toBeNull();
    expect(canonicalPayloadParams([{ name: 'ok', value: '', extra: true }])).toBeNull();
    expect(canonicalPayloadParams({ name: 'ok', value: '' })).toBeNull();
  });
});
