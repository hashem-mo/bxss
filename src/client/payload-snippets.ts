import {
  PAYLOAD_PARAM_MAX_COUNT,
  PAYLOAD_PARAM_NAME_MAX_BYTES,
  PAYLOAD_PARAM_VALUE_MAX_BYTES,
  PAYLOAD_PARAMS_MAX_BYTES,
  type PayloadParam,
} from '../lib/collector-identifiers';

export interface PayloadQueryResult {
  normalizedQuery: string;
  params: PayloadParam[];
  error: string;
}

export interface PayloadSnippets extends PayloadQueryResult {
  loaderUrl: string;
  scriptTag: string;
  compactScriptTag: string;
  attributeBreakout: string;
  imageErrorHandler: string;
  javascriptLoader: string;
}

const encoder = new TextEncoder();

function utf8Length(value: string): number {
  return encoder.encode(value).byteLength;
}

function normalizePart(value: string, trim: boolean): string {
  const normalized = value.normalize('NFKC').replace(/[\p{Cc}\p{Cf}]/gu, ' ');
  return trim ? normalized.trim() : normalized;
}

function decodeQueryPart(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return null;
  }
}

// encodeURIComponent deliberately leaves a few punctuation characters alone.
// Encoding them too keeps generated snippets safe when pasted into either kind
// of quoted HTML attribute without changing what URLSearchParams decodes.
function encodeQueryPart(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => (
    '%' + character.charCodeAt(0).toString(16).toUpperCase()
  ));
}

/**
 * Canonicalizes dashboard query input without dropping meaningful segments.
 * The returned validation errors match the collector's all-or-nothing limits.
 */
export function normalizePayloadQuery(value: string): PayloadQueryResult {
  const rawQuery = value.trim().replace(/^[?&]+/, '');
  if (!rawQuery) return { normalizedQuery: '', params: [], error: '' };

  const segments = rawQuery.split('&').filter((segment) => segment.length > 0);
  if (segments.length > PAYLOAD_PARAM_MAX_COUNT) {
    return { normalizedQuery: '', params: [], error: `Use no more than ${PAYLOAD_PARAM_MAX_COUNT} query parameters.` };
  }

  const params: PayloadParam[] = [];
  const encodedSegments: string[] = [];
  for (const segment of segments) {
    const separator = segment.indexOf('=');
    const rawName = separator < 0 ? segment : segment.slice(0, separator);
    const rawValue = separator < 0 ? '' : segment.slice(separator + 1);
    const decodedName = decodeQueryPart(rawName);
    const decodedValue = decodeQueryPart(rawValue);
    if (decodedName === null || decodedValue === null) {
      return {
        normalizedQuery: '',
        params: [],
        error: 'Use valid UTF-8 percent encoding in query parameters.',
      };
    }

    const name = normalizePart(decodedName, true);
    const paramValue = normalizePart(decodedValue, false);
    if (!name) {
      return { normalizedQuery: '', params: [], error: 'Query parameter names cannot be empty.' };
    }
    if (utf8Length(name) > PAYLOAD_PARAM_NAME_MAX_BYTES) {
      return {
        normalizedQuery: '',
        params: [],
        error: `Parameter names must be ${PAYLOAD_PARAM_NAME_MAX_BYTES} UTF-8 bytes or less.`,
      };
    }
    if (utf8Length(paramValue) > PAYLOAD_PARAM_VALUE_MAX_BYTES) {
      return {
        normalizedQuery: '',
        params: [],
        error: `Parameter values must be ${PAYLOAD_PARAM_VALUE_MAX_BYTES} UTF-8 bytes or less.`,
      };
    }

    const candidate = [...params, { name, value: paramValue }];
    if (utf8Length(JSON.stringify(candidate)) > PAYLOAD_PARAMS_MAX_BYTES) {
      return {
        normalizedQuery: '',
        params: [],
        error: 'The parameter metadata must be 1 KB or less.',
      };
    }

    params.push({ name, value: paramValue });
    encodedSegments.push(
      encodeQueryPart(name) + (separator < 0 ? '' : '=' + encodeQueryPart(paramValue)),
    );
  }

  return { normalizedQuery: encodedSegments.join('&'), params, error: '' };
}

export function escapeHtmlAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function javascriptString(value: string): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function appendQuery(baseUrl: string, query: string): string {
  if (!query) return baseUrl;
  const fragmentAt = baseUrl.indexOf('#');
  const beforeFragment = fragmentAt < 0 ? baseUrl : baseUrl.slice(0, fragmentAt);
  const fragment = fragmentAt < 0 ? '' : baseUrl.slice(fragmentAt);
  const separator = beforeFragment.endsWith('?') || beforeFragment.endsWith('&')
    ? ''
    : beforeFragment.includes('?') ? '&' : '?';
  return beforeFragment + separator + query + fragment;
}

export function createPayloadSnippets(baseUrl: string, rawQuery: string): PayloadSnippets {
  const query = normalizePayloadQuery(rawQuery);
  const empty = {
    ...query,
    loaderUrl: '',
    scriptTag: '',
    compactScriptTag: '',
    attributeBreakout: '',
    imageErrorHandler: '',
    javascriptLoader: '',
  };
  if (query.error || !baseUrl) return empty;

  const loaderUrl = appendQuery(baseUrl, query.normalizedQuery);
  const escapedUrl = escapeHtmlAttribute(loaderUrl);
  const javascriptLoader = 'var s=document.createElement(\'script\');s.src='
    + javascriptString(loaderUrl)
    + ';document.head.appendChild(s)';

  return {
    ...query,
    loaderUrl,
    scriptTag: '<script src="' + escapedUrl + '" async><' + '/script>',
    compactScriptTag: '<script src="' + escapedUrl + '"><' + '/script>',
    attributeBreakout: '\"><script src="' + escapedUrl + '"><' + '/script>',
    imageErrorHandler: '\"><img src=x onerror="' + escapeHtmlAttribute(javascriptLoader) + '">',
    javascriptLoader,
  };
}
