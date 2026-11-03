import type { Env } from '../types';
import { base64UrlToBytes, bytesToBase64Url, fromUtf8, randomBytes, utf8, type Bytes } from './encoding';

const aesKeyCache = new Map<string, Promise<CryptoKey>>();
const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

function validatedKey(secret: string, label: string): Bytes {
  const bytes = base64UrlToBytes(secret);
  if (bytes.byteLength !== 32) throw new Error(`${label} must decode to exactly 32 bytes`);
  return bytes;
}

function getAesKey(secret: string): Promise<CryptoKey> {
  let key = aesKeyCache.get(secret);
  if (!key) {
    key = crypto.subtle.importKey('raw', validatedKey(secret, 'DATA_ENCRYPTION_KEY'), 'AES-GCM', false, [
      'encrypt',
      'decrypt',
    ]);
    aesKeyCache.set(secret, key);
  }
  return key;
}

function getHmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeyCache.get(secret);
  if (!key) {
    key = crypto.subtle.importKey(
      'raw',
      validatedKey(secret, 'AUTH_PEPPER'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    hmacKeyCache.set(secret, key);
  }
  return key;
}

export async function keyedHash(env: Env, namespace: string, value: string): Promise<string> {
  const key = await getHmacKey(env.AUTH_PEPPER);
  const digest = await crypto.subtle.sign('HMAC', key, utf8(`${namespace}\0${value}`));
  return bytesToBase64Url(digest);
}

export async function sha256(value: string | Uint8Array<ArrayBufferLike>): Promise<string> {
  const source = typeof value === 'string' ? utf8(value) : (new Uint8Array(value) as Bytes);
  const digest = await crypto.subtle.digest('SHA-256', source);
  return bytesToBase64Url(digest);
}

export interface SealedValue {
  ciphertext: string;
  iv: string;
}

export async function sealBytes(env: Env, context: string, plaintext: Uint8Array<ArrayBufferLike>): Promise<SealedValue> {
  const key = await getAesKey(env.DATA_ENCRYPTION_KEY);
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(`bxss-vault:v1:${context}`), tagLength: 128 },
    key,
    new Uint8Array(plaintext) as Bytes,
  );
  return { ciphertext: bytesToBase64Url(encrypted), iv: bytesToBase64Url(iv) };
}

export async function openBytes(env: Env, context: string, sealed: SealedValue): Promise<Bytes> {
  const key = await getAesKey(env.DATA_ENCRYPTION_KEY);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64UrlToBytes(sealed.iv),
      additionalData: utf8(`bxss-vault:v1:${context}`),
      tagLength: 128,
    },
    key,
    base64UrlToBytes(sealed.ciphertext),
  );
  return new Uint8Array(decrypted) as Bytes;
}

export async function sealJson(env: Env, context: string, value: unknown): Promise<SealedValue> {
  return sealBytes(env, context, utf8(JSON.stringify(value)));
}

export async function openJson<T>(env: Env, context: string, sealed: SealedValue): Promise<T> {
  return JSON.parse(fromUtf8(await openBytes(env, context, sealed))) as T;
}

export function packSealed(sealed: SealedValue): Bytes {
  const iv = base64UrlToBytes(sealed.iv);
  const ciphertext = base64UrlToBytes(sealed.ciphertext);
  const packed = new Uint8Array(1 + iv.byteLength + ciphertext.byteLength);
  packed[0] = iv.byteLength;
  packed.set(iv, 1);
  packed.set(ciphertext, 1 + iv.byteLength);
  return packed as Bytes;
}

export function unpackSealed(packed: ArrayBuffer | Uint8Array<ArrayBufferLike>): SealedValue {
  const bytes = packed instanceof Uint8Array ? packed : new Uint8Array(packed);
  const ivLength = bytes[0] ?? 0;
  if (ivLength !== 12 || bytes.byteLength <= 1 + ivLength + 16) throw new Error('Invalid encrypted object');
  return {
    iv: bytesToBase64Url(bytes.subarray(1, 1 + ivLength)),
    ciphertext: bytesToBase64Url(bytes.subarray(1 + ivLength)),
  };
}
