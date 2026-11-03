import { bytesToBase64Url, randomToken, utf8 } from './encoding';

export const COLLECTOR_ALIAS_BYTES = 16;
export const COLLECTOR_ALIAS_LENGTH = 22;
export const SOURCE_LABEL_MAX_BYTES = 256;
export const PAYLOAD_PARAM_MAX_COUNT = 16;
export const PAYLOAD_PARAM_NAME_MAX_BYTES = 96;
export const PAYLOAD_PARAM_VALUE_MAX_BYTES = 384;
export const PAYLOAD_PARAMS_MAX_BYTES = 1_024;
const SOURCE_LABEL_RAW_CODE_POINTS = 1_024;

const collectorAliasPattern = /^[A-Za-z0-9_-]{22}$/;

export interface PayloadParam {
  name: string;
  value: string;
}

export function isCollectorAlias(value: string): boolean {
  return collectorAliasPattern.test(value);
}

export function createCollectorAlias(): string {
  return randomToken(COLLECTOR_ALIAS_BYTES);
}

/**
 * Canonicalizes an operator-supplied placement label as inert display text.
 * It deliberately does not parse, resolve, or otherwise trust the value as a URL.
 */
export function normalizeSourceLabel(value: string | null | undefined): string {
  if (!value) return '';
  const raw = Array.from(value).slice(0, SOURCE_LABEL_RAW_CODE_POINTS).join('');
  const normalized = raw
    .normalize('NFKC')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
    .replace(/\s+/gu, ' ')
    .trim();

  let result = '';
  let length = 0;
  for (const codePoint of normalized) {
    const encodedLength = utf8(codePoint).byteLength;
    if (length + encodedLength > SOURCE_LABEL_MAX_BYTES) break;
    result += codePoint;
    length += encodedLength;
  }
  return result;
}

export function sourceLabelFromLoaderUrl(url: URL): string {
  const values = url.searchParams.getAll('url');
  return values.length === 1 ? normalizeSourceLabel(values[0]) : '';
}

export function encodeSourceLabel(label: string): string {
  return bytesToBase64Url(utf8(label));
}

function normalizeParamPart(value: string, maxBytes: number, trim: boolean): { value: string; truncated: boolean } {
  const normalized = Array.from(value).slice(0, maxBytes * 4 + 1).join('')
    .normalize('NFKC')
    .replace(/[\p{Cc}\p{Cf}]/gu, ' ');
  const candidate = trim ? normalized.trim() : normalized;
  let output = '';
  let length = 0;
  let truncated = false;
  for (const codePoint of candidate) {
    const encodedLength = utf8(codePoint).byteLength;
    if (length + encodedLength > maxBytes) {
      truncated = true;
      break;
    }
    output += codePoint;
    length += encodedLength;
  }
  if (Array.from(value).length > maxBytes * 4) truncated = true;
  return { value: output, truncated };
}

/**
 * Captures loader query parameters as bounded, inert metadata. An ordered array
 * deliberately preserves duplicate keys and flag parameters such as `&aa`.
 */
export function payloadParamsFromLoaderUrl(url: URL): PayloadParam[] | null {
  const params: PayloadParam[] = [];
  for (const [rawName, rawValue] of url.searchParams) {
    if (params.length >= PAYLOAD_PARAM_MAX_COUNT) return null;
    const normalizedName = normalizeParamPart(rawName, PAYLOAD_PARAM_NAME_MAX_BYTES, true);
    const normalizedValue = normalizeParamPart(rawValue, PAYLOAD_PARAM_VALUE_MAX_BYTES, false);
    if (normalizedName.truncated || normalizedValue.truncated) return null;
    const name = normalizedName.value;
    if (!name) return null;
    const value = normalizedValue.value;
    const candidate = [...params, { name, value }];
    if (utf8(JSON.stringify(candidate)).byteLength > PAYLOAD_PARAMS_MAX_BYTES) return null;
    params.push({ name, value });
  }
  return params;
}

export function canonicalPayloadParams(value: unknown): PayloadParam[] | null {
  if (!Array.isArray(value) || value.length > PAYLOAD_PARAM_MAX_COUNT) return null;
  const params: PayloadParam[] = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
    const record = item as Record<string, unknown>;
    if (Object.keys(record).length !== 2 || typeof record.name !== 'string' || typeof record.value !== 'string') {
      return null;
    }
    const name = normalizeParamPart(record.name, PAYLOAD_PARAM_NAME_MAX_BYTES, true);
    const paramValue = normalizeParamPart(record.value, PAYLOAD_PARAM_VALUE_MAX_BYTES, false);
    if (
      name.truncated
      || paramValue.truncated
      || !name.value
      || name.value !== record.name
      || paramValue.value !== record.value
    ) return null;
    params.push({ name: name.value, value: paramValue.value });
  }
  if (utf8(JSON.stringify(params)).byteLength > PAYLOAD_PARAMS_MAX_BYTES) return null;
  return params;
}

export function encodePayloadParams(params: PayloadParam[]): string {
  return bytesToBase64Url(utf8(JSON.stringify(params)));
}
