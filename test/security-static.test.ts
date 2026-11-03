import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

describe('static security invariants', () => {
  it('does not use React HTML escape hatches for captured content', async () => {
    const client = await readFile(new URL('../src/client/main.tsx', import.meta.url), 'utf8');
    expect(client).not.toContain('dangerouslySetInnerHTML');
    expect(client).not.toMatch(/\.innerHTML\s*=/);
    expect(client).not.toContain('<iframe');
  });

  it('keeps private storage behind a Worker binding', async () => {
    const config = await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
    expect(config).toContain('"binding": "VAULT"');
    expect(config).not.toContain('r2.dev');
    expect(config).not.toContain('public_bucket');
    // Custom execution limits are a Standard Usage Model feature. The Free
    // plan supplies its own fixed CPU/subrequest limits and rejects this field.
    expect(config).not.toMatch(/"limits"\s*:/);
  });

  it('declares every root-of-trust secret', async () => {
    const config = await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
    expect(config).toContain('AUTH_PEPPER');
    expect(config).toContain('DATA_ENCRYPTION_KEY');
    expect(config).toContain('BOOTSTRAP_TOKEN');
  });

  it('requires a signed collector-bound second-stage probe runtime', async () => {
    const collector = await readFile(new URL('../src/routes/collector.ts', import.meta.url), 'utf8');
    expect(collector).toContain("app.get('/probe-runtime/:tokenFile'");
    expect(collector).toContain('probe-config:${credentialHash}');
    expect(collector).toContain('constantTimeEqual(signature, expectedSignature)');
  });

  it('stores compact aliases as revocable hashed and encrypted capabilities', async () => {
    const migration = await readFile(new URL('../migrations/0003_collector_aliases.sql', import.meta.url), 'utf8');
    const collector = await readFile(new URL('../src/routes/collector.ts', import.meta.url), 'utf8');
    const worker = await readFile(new URL('../src/worker.ts', import.meta.url), 'utf8');
    expect(migration).toContain('alias_hash TEXT NOT NULL UNIQUE');
    expect(migration).toContain('alias_ciphertext TEXT');
    expect(migration).toContain('WHERE revoked_at IS NULL');
    expect(collector).toContain("keyedHash(c.env, 'collector-alias', alias)");
    expect(collector).toContain("app.get('/a/*'");
    expect(collector).toContain("app.get('/probe-runtime/a/:aliasFile'");
    expect(worker).toContain("'/a/'");
  });

  it('derives inert source labels from a signed callback query, not capture JSON', async () => {
    const collector = await readFile(new URL('../src/routes/collector.ts', import.meta.url), 'utf8');
    expect(collector).toMatch(/callback\.searchParams\.set\('source_label',\s*encodedSourceLabel\)/);
    expect(collector).toContain('source-label:${credentialHash}');
    expect(collector).toContain('constantTimeEqual(signature, expected)');
    expect(collector).toContain('verifiedSourceLabel(c, authorization.hash)');
    expect(collector).not.toMatch(/event\.sourceLabel\s*=/);
  });

  it('signs bounded loader query metadata before accepting it in a callback', async () => {
    const collector = await readFile(new URL('../src/routes/collector.ts', import.meta.url), 'utf8');
    expect(collector).toContain('payloadParamsFromLoaderUrl(loaderUrl)');
    expect(collector).toMatch(/callback\.searchParams\.set\('payload_params',\s*encodedPayloadParams\)/);
    expect(collector).toContain('payload-params:${credentialHash}');
    expect(collector).toContain('verifiedPayloadParams(c, authorization.hash)');
    expect(collector).not.toMatch(/event\.payloadParams\s*=/);
  });

  it('keeps Discord delivery metadata-only and off the callback critical path', async () => {
    const collector = await readFile(new URL('../src/routes/collector.ts', import.meta.url), 'utf8');
    const discord = await readFile(new URL('../src/lib/discord.ts', import.meta.url), 'utf8');
    expect(collector).toContain('c.executionCtx.waitUntil(');
    expect(collector).toContain('sendDiscordCaptureNotification');
    expect(discord).toContain('allowed_mentions: { parse: [] }');
    expect(discord).not.toMatch(/notice\.(cookies|domHtml|localStorage|sessionStorage|url|referrer)/);
  });

  it('exposes the out-of-band capture endpoint as a public, token-gated path', async () => {
    const worker = await readFile(new URL('../src/worker.ts', import.meta.url), 'utf8');
    const oob = await readFile(new URL('../src/routes/oob.ts', import.meta.url), 'utf8');
    expect(worker).toContain("'/o/'");
    expect(worker).toContain('oobTokenFromHost');
    expect(oob).toContain("app.all('/o/:token'");
    expect(oob).toContain("keyedHash(env, 'oob-token', token)");
    // Enabled listeners only, enforced again at insert time.
    expect(oob).toContain('AND enabled = 1');
    expect(oob).toContain('EXISTS (');
  });

  it('never reflects request input into the out-of-band response', async () => {
    const oob = await readFile(new URL('../src/routes/oob.ts', import.meta.url), 'utf8');
    const lib = await readFile(new URL('../src/lib/oob.ts', import.meta.url), 'utf8');
    // The only Response in the capture path is built from the resolved spec
    // (operator-configured policy or the inert default) — never from the request.
    expect(oob).toContain('new Response(spec.body, { status: spec.status, headers })');
    expect(oob).not.toMatch(/new Response\((?!spec\.body)/);
    // A listener with no custom response still serves an empty body.
    expect(lib).toContain("return { status: fallbackStatus, headers: [...merged.values()], body: '' };");
  });

  it('keeps the listener token out of the non-step-up interaction summary', async () => {
    const oob = await readFile(new URL('../src/routes/oob.ts', import.meta.url), 'utf8');
    const admin = await readFile(new URL('../src/routes/admin.ts', import.meta.url), 'utf8');
    // The summary (served by the non-step-up list) uses token-redacted fields.
    expect(oob).toContain('redactToken(url.pathname, token)');
    expect(oob).toContain('redactToken(url.host, token)');
    expect(oob).toContain('host: summaryHost');
    expect(oob).toContain('path: summaryPath');
    // The full request line stays in the detail, which is step-up gated.
    expect(admin).toMatch(/app\.get\('\/oob\/interactions\/:id'[\s\S]{0,120}requireStepUp\(c\)/);
  });

  it('validates operator-controlled OOB response headers against injection', async () => {
    const oob = await readFile(new URL('../src/lib/oob.ts', import.meta.url), 'utf8');
    const admin = await readFile(new URL('../src/routes/admin.ts', import.meta.url), 'utf8');
    // Field-name token + field-value restricted to visible ASCII/space/tab (no CR/LF).
    expect(oob).toContain("const headerValuePattern = /^[\\t\\x20-\\x7e]*$/");
    // Framing headers can never be set by an operator.
    expect(oob).toContain("'content-length'");
    expect(oob).toContain("'transfer-encoding'");
    // The admin API routes the operator policy through the validator and rejects bad input.
    expect(admin).toContain('canonicalOobResponse(body.data.response)');
    expect(admin).toContain("'invalid_response'");
  });

  it('encrypts and hashes out-of-band listener tokens like collector tokens', async () => {
    const migration = await readFile(new URL('../migrations/0006_oob_interactions.sql', import.meta.url), 'utf8');
    expect(migration).toContain('token_hash TEXT NOT NULL UNIQUE');
    expect(migration).toContain('token_ciphertext TEXT NOT NULL');
    expect(migration).toContain('CREATE TABLE oob_interactions');
    expect(migration).toContain('detail_key TEXT NOT NULL');
  });

  it('keeps out-of-band Discord delivery metadata-only and off the capture critical path', async () => {
    const oob = await readFile(new URL('../src/routes/oob.ts', import.meta.url), 'utf8');
    const discord = await readFile(new URL('../src/lib/discord.ts', import.meta.url), 'utf8');
    expect(oob).toContain('ctx.waitUntil(');
    expect(oob).toContain('sendDiscordOobNotification');
    // The out-of-band notice carries no captured request content.
    expect(discord).not.toMatch(/notice\.(path|host|body|query|headers|ip|country|userAgent)/);
  });
});
