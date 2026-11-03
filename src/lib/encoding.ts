const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type Bytes = Uint8Array<ArrayBuffer>;

export const utf8 = (value: string): Bytes => encoder.encode(value) as Bytes;
export const fromUtf8 = (value: ArrayBuffer | Uint8Array<ArrayBufferLike>): string => decoder.decode(value);

export function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array<ArrayBufferLike>): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let offset = 0; offset < view.length; offset += 0x8000) {
    binary += String.fromCharCode(...view.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value: string): Bytes {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes as Bytes;
}

export const randomBytes = (length = 32): Bytes => crypto.getRandomValues(new Uint8Array(length)) as Bytes;
export const randomToken = (length = 32): string => bytesToBase64Url(randomBytes(length));
export const randomId = (): string => crypto.randomUUID();

export function constantTimeEqual(left: string, right: string): boolean {
  const a = utf8(left);
  const b = utf8(right);
  const length = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

export function safeJsonParse<T>(value: string, fallback: T): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

export function truncateUtf8(value: string, maxBytes: number): string {
  if (utf8(value).byteLength <= maxBytes) return value;
  let low = 0;
  let high = value.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (utf8(value.slice(0, mid)).byteLength <= maxBytes) low = mid;
    else high = mid - 1;
  }
  return value.slice(0, low);
}
