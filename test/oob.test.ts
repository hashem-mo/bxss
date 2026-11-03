import { describe, expect, it } from 'vitest';
import {
  MAX_OOB_BODY_BYTES,
  OOB_HEADER_VALUE_MAX_BYTES,
  OOB_TOKEN_LENGTH,
  base32LowerEncode,
  boundOobHeaders,
  boundOobText,
  createOobToken,
  encodeOobBody,
  isOobToken,
  normalizeOobWildcardHost,
  oobHostLoader,
  oobPathLoader,
  oobTokenFromHost,
  oobTokenFromPath,
} from '../src/lib/oob';

describe('OOB tokens', () => {
  it('generates DNS- and path-safe 128-bit base32 tokens', () => {
    const tokens = new Set(Array.from({ length: 256 }, createOobToken));
    expect(tokens.size).toBe(256);
    for (const token of tokens) {
      expect(token).toHaveLength(OOB_TOKEN_LENGTH);
      expect(isOobToken(token)).toBe(true);
      // A valid DNS label: lowercase, <= 63 chars, and usable verbatim in a path.
      expect(token).toMatch(/^[a-z2-7]{26}$/);
      expect(encodeURIComponent(token)).toBe(token);
    }
  });

  it('encodes base32 without padding and matches a known vector', () => {
    // RFC 4648 test vector "foobar" -> MZXW6YTBOI (lowercased here).
    expect(base32LowerEncode(new TextEncoder().encode('foobar'))).toBe('mzxw6ytboi');
    expect(base32LowerEncode(new Uint8Array(0))).toBe('');
  });

  it('rejects uppercase, padded, or wrong-length tokens', () => {
    expect(isOobToken('A'.repeat(OOB_TOKEN_LENGTH))).toBe(false);
    expect(isOobToken('a'.repeat(OOB_TOKEN_LENGTH - 1))).toBe(false);
    expect(isOobToken(`${'a'.repeat(OOB_TOKEN_LENGTH - 1)}=`)).toBe(false);
    expect(isOobToken('a'.repeat(OOB_TOKEN_LENGTH) + '1')).toBe(false); // '1' is not a base32 char
  });
});

describe('OOB token resolution', () => {
  const token = createOobToken();

  it('extracts the token from a /o/<token> path and ignores the capture sub-path', () => {
    expect(oobTokenFromPath(`/o/${token}`)).toBe(token);
    expect(oobTokenFromPath(`/o/${token}/anything/here?x=1`.split('?')[0])).toBe(token);
    expect(oobTokenFromPath(`/o/${token}/a/b/c`)).toBe(token);
  });

  it('rejects non-OOB and malformed paths', () => {
    expect(oobTokenFromPath('/o/')).toBeNull();
    expect(oobTokenFromPath('/o/not-a-valid-token')).toBeNull();
    expect(oobTokenFromPath(`/p/${token}`)).toBeNull();
    expect(oobTokenFromPath('/')).toBeNull();
  });

  it('normalizes an operator-supplied wildcard capture host', () => {
    expect(normalizeOobWildcardHost('https://OOB.Example.com/')).toBe('oob.example.com');
    expect(normalizeOobWildcardHost('oob.example.com.')).toBe('oob.example.com');
    expect(normalizeOobWildcardHost('localhost')).toBe(''); // must contain a dot
    expect(normalizeOobWildcardHost(undefined)).toBe('');
    expect(normalizeOobWildcardHost('bad_host!.com')).toBe('');
  });

  it('extracts the token only from the immediate leftmost label of the wildcard host', () => {
    const host = 'oob.example.com';
    expect(oobTokenFromHost(`${token}.oob.example.com`, host)).toBe(token);
    expect(oobTokenFromHost(`${token.toUpperCase()}.OOB.EXAMPLE.COM`, host)).toBe(token);
    expect(oobTokenFromHost(`extra.${token}.oob.example.com`, host)).toBeNull();
    expect(oobTokenFromHost(`${token}.other.example.com`, host)).toBeNull();
    expect(oobTokenFromHost('oob.example.com', host)).toBeNull();
    expect(oobTokenFromHost(`${token}.oob.example.com`, '')).toBeNull();
  });

  it('builds loader URLs', () => {
    expect(oobPathLoader('https://collector.example.com/', token)).toBe(`https://collector.example.com/o/${token}`);
    expect(oobHostLoader('oob.example.com', token)).toBe(`${token}.oob.example.com`);
    expect(oobHostLoader('', token)).toBe('');
  });
});

describe('OOB request bounding', () => {
  it('collapses control characters and caps header values by UTF-8 length', () => {
    expect(boundOobText('a\u0000b\u0007c', 64)).toBe('a b c');
    const long = 'x'.repeat(OOB_HEADER_VALUE_MAX_BYTES + 100);
    expect(new TextEncoder().encode(boundOobText(long, OOB_HEADER_VALUE_MAX_BYTES)).byteLength)
      .toBe(OOB_HEADER_VALUE_MAX_BYTES);
  });

  it('preserves order and reports the true header count while bounding stored entries', () => {
    const headers = new Headers();
    headers.append('X-One', 'first');
    headers.append('X-Two', 'second');
    const { headers: bounded, count } = boundOobHeaders(headers);
    expect(count).toBe(2);
    expect(bounded.map((header) => header.name)).toContain('x-one');
  });

  it('keeps UTF-8 bodies as text and non-UTF-8 bodies as base64url', () => {
    const text = encodeOobBody(new TextEncoder().encode('{"ok":true}'));
    expect(text).toMatchObject({ body: '{"ok":true}', encoding: 'utf-8', truncated: false });

    const binary = encodeOobBody(new Uint8Array([0xff, 0xfe, 0x00, 0x80]));
    expect(binary.encoding).toBe('base64url');
    expect(binary.body).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('truncates oversized bodies but records the true byte length', () => {
    const oversized = new Uint8Array(MAX_OOB_BODY_BYTES + 512).fill(0x61);
    const encoded = encodeOobBody(oversized);
    expect(encoded.truncated).toBe(true);
    expect(encoded.byteLength).toBe(MAX_OOB_BODY_BYTES + 512);
    expect(new TextEncoder().encode(encoded.body).byteLength).toBe(MAX_OOB_BODY_BYTES);
  });
});
