import { describe, expect, it } from 'vitest';
import type { Env } from '../src/types';
import { keyedHash, openBytes, openJson, packSealed, sealBytes, sealJson, unpackSealed } from '../src/lib/crypto';
import { base64UrlToBytes, bytesToBase64Url, randomToken, utf8 } from '../src/lib/encoding';

function environment(): Env {
  return {
    AUTH_PEPPER: randomToken(),
    DATA_ENCRYPTION_KEY: randomToken(),
  } as Env;
}

describe('vault cryptography', () => {
  it('round-trips JSON with context-bound AES-256-GCM', async () => {
    const env = environment();
    const sealed = await sealJson(env, 'event:test:summary', { cookie: 'critical=value', count: 7 });
    expect(sealed.iv).toMatch(/^[A-Za-z0-9_-]{16}$/);
    await expect(openJson(env, 'event:test:summary', sealed)).resolves.toEqual({
      cookie: 'critical=value',
      count: 7,
    });
  });

  it('rejects context substitution and ciphertext tampering', async () => {
    const env = environment();
    const sealed = await sealJson(env, 'event:a:detail', { secret: true });
    await expect(openJson(env, 'event:b:detail', sealed)).rejects.toThrow();
    const tamperedBytes = base64UrlToBytes(sealed.ciphertext);
    tamperedBytes[Math.floor(tamperedBytes.length / 2)] ^= 1;
    const tampered = { ...sealed, ciphertext: bytesToBase64Url(tamperedBytes) };
    await expect(openJson(env, 'event:a:detail', tampered)).rejects.toThrow();
  });

  it('packs encrypted R2 objects without losing authentication data', async () => {
    const env = environment();
    const original = utf8('synthetic screenshot bytes');
    const packed = packSealed(await sealBytes(env, 'event:one:screenshot', original));
    await expect(openBytes(env, 'event:one:screenshot', unpackSealed(packed))).resolves.toEqual(original);
  });

  it('uses keyed, namespace-separated indexes', async () => {
    const env = environment();
    const first = await keyedHash(env, 'session', 'token');
    expect(await keyedHash(env, 'session', 'token')).toBe(first);
    expect(await keyedHash(env, 'collector-token', 'token')).not.toBe(first);
  });
});
