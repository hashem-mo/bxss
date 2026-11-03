import { bytesToBase64Url, utf8 } from './encoding';

// Cloudflare Workers currently accepts request URLs up to 16 KiB. Keep one
// KiB in reserve for platform/proxy normalization and validate the complete
// URL rather than only the config query value.
export const MAX_SIGNED_RUNTIME_URL_BYTES = 15 * 1_024;
export const MAX_SIGNED_CONFIG_CHARS = 14 * 1_024;

const base64UrlPattern = /^[A-Za-z0-9_-]+$/;

function validEncodedConfig(value: string): boolean {
  return value.length >= 40
    && value.length <= MAX_SIGNED_CONFIG_CHARS
    && base64UrlPattern.test(value);
}

function validSignature(value: string): boolean {
  return value.length === 43 && base64UrlPattern.test(value);
}

function urlFitsRuntimeBudget(url: URL): boolean {
  return utf8(url.toString()).byteLength <= MAX_SIGNED_RUNTIME_URL_BYTES;
}

export function encodeProbeConfig(value: unknown): string | null {
  const encoded = bytesToBase64Url(utf8(JSON.stringify(value)));
  return validEncodedConfig(encoded) ? encoded : null;
}

export function createSignedRuntimeUrl(
  origin: string,
  runtimePath: string,
  encodedConfig: string,
  signature: string,
  cacheKey = '',
): URL | null {
  if (!validEncodedConfig(encodedConfig) || !validSignature(signature)) return null;
  try {
    const runtime = new URL(runtimePath, `${origin}/`);
    runtime.searchParams.set('config', encodedConfig);
    runtime.searchParams.set('sig', signature);
    if (cacheKey && /^[A-Za-z0-9_-]{1,32}$/.test(cacheKey)) {
      runtime.searchParams.set('v', cacheKey);
      if (!urlFitsRuntimeBudget(runtime)) runtime.searchParams.delete('v');
    }
    return urlFitsRuntimeBudget(runtime) ? runtime : null;
  } catch {
    return null;
  }
}

export function signedRuntimeParams(url: URL): { encodedConfig: string; signature: string } | null {
  if (!urlFitsRuntimeBudget(url)) return null;
  const encodedConfigs = url.searchParams.getAll('config');
  const signatures = url.searchParams.getAll('sig');
  if (encodedConfigs.length !== 1 || signatures.length !== 1) return null;
  const encodedConfig = encodedConfigs[0];
  const signature = signatures[0];
  return validEncodedConfig(encodedConfig) && validSignature(signature)
    ? { encodedConfig, signature }
    : null;
}
