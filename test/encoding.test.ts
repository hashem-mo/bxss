import { describe, expect, it } from 'vitest';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  constantTimeEqual,
  randomToken,
  truncateUtf8,
  utf8,
} from '../src/lib/encoding';

describe('encoding primitives', () => {
  it('round-trips arbitrary bytes through base64url', () => {
    const original = Uint8Array.from([0, 1, 2, 127, 128, 254, 255]);
    expect(Array.from(base64UrlToBytes(bytesToBase64Url(original)))).toEqual(Array.from(original));
  });

  it('generates 256-bit URL-safe tokens', () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(base64UrlToBytes(token)).toHaveLength(32);
  });

  it('compares equal and unequal strings without prefix shortcuts', () => {
    expect(constantTimeEqual('same-value', 'same-value')).toBe(true);
    expect(constantTimeEqual('same-value', 'same-valuE')).toBe(false);
    expect(constantTimeEqual('short', 'shorter')).toBe(false);
  });

  it('truncates on UTF-8 byte boundaries', () => {
    const truncated = truncateUtf8('alpha-🔐-omega', 10);
    expect(utf8(truncated).byteLength).toBeLessThanOrEqual(10);
    expect(truncated).not.toContain('�');
  });
});
