import { describe, expect, it } from 'vitest';
import {
  MAX_SIGNED_CONFIG_CHARS,
  MAX_SIGNED_RUNTIME_URL_BYTES,
  createSignedRuntimeUrl,
  encodeProbeConfig,
  signedRuntimeParams,
} from '../src/lib/probe-runtime-config';

describe('signed probe runtime URLs', () => {
  it('fits the largest valid Unicode collector settings beneath the Worker URL budget', () => {
    const astral = String.fromCodePoint(0x1f600);
    const origin = `https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(51)}`;
    const callback = new URL(`/c/${'t'.repeat(80)}`, origin);
    callback.searchParams.set('source_label', 'A'.repeat(342));
    callback.searchParams.set('source_label_sig', 's'.repeat(43));
    callback.searchParams.set('payload_params', 'P'.repeat(1_366));
    callback.searchParams.set('payload_params_sig', 's'.repeat(43));

    const chainloadPrefix = 'https://chain.invalid/';
    const chainloadUrl = chainloadPrefix
      + astral.repeat(Math.floor((2_048 - chainloadPrefix.length) / astral.length));
    const pagePath = `/${astral.repeat(127)}`;
    const encodedConfig = encodeProbeConfig({
      callback: callback.toString(),
      injectionKey: 'i'.repeat(256),
      captureCookies: true,
      captureDom: true,
      captureScreenshot: true,
      captureStorage: true,
      probeChecks: true,
      pagePaths: [pagePath, pagePath, pagePath],
      chainloadUrl,
    });

    expect(encodedConfig).not.toBeNull();
    expect(encodedConfig?.length).toBeGreaterThan(8_192);
    const runtime = createSignedRuntimeUrl(
      origin,
      `/probe-runtime/${'t'.repeat(80)}.js`,
      encodedConfig ?? '',
      's'.repeat(43),
    );
    expect(runtime).not.toBeNull();
    expect(new TextEncoder().encode(runtime?.toString()).byteLength).toBeLessThanOrEqual(
      MAX_SIGNED_RUNTIME_URL_BYTES,
    );
    expect(signedRuntimeParams(runtime as URL)).toEqual({
      encodedConfig,
      signature: 's'.repeat(43),
    });
  });

  it('rejects oversized configs, oversized complete URLs, and ambiguous query values', () => {
    const origin = 'https://collector.invalid';
    const signature = 's'.repeat(43);
    expect(createSignedRuntimeUrl(origin, '/probe-runtime/a.js', 'A'.repeat(MAX_SIGNED_CONFIG_CHARS + 1), signature))
      .toBeNull();

    const config = 'A'.repeat(40);
    expect(createSignedRuntimeUrl(origin, `/${'x'.repeat(MAX_SIGNED_RUNTIME_URL_BYTES)}`, config, signature)).toBeNull();

    const duplicate = new URL('/probe-runtime/a.js', origin);
    duplicate.searchParams.append('config', config);
    duplicate.searchParams.append('config', config);
    duplicate.searchParams.set('sig', signature);
    expect(signedRuntimeParams(duplicate)).toBeNull();
  });

  it('allows a runtime cache-buster without changing signed config validation', () => {
    const runtime = createSignedRuntimeUrl(
      'https://collector.invalid',
      '/probe-runtime/a.js',
      'A'.repeat(40),
      's'.repeat(43),
      'fresh_123',
    );

    expect(runtime?.searchParams.get('v')).toBe('fresh_123');
    expect(signedRuntimeParams(runtime as URL)).toEqual({
      encodedConfig: 'A'.repeat(40),
      signature: 's'.repeat(43),
    });
  });
});
