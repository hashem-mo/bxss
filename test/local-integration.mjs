import { readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const secretsUrl = new URL('./.integration-secrets.json', import.meta.url);
const secrets = JSON.parse(await readFile(secretsUrl, 'utf8'));
const origin = process.env.BXSS_TEST_ORIGIN || 'http://127.0.0.1:8787';
const authHeaders = {
  Cookie: `__Host-bxss_session=${secrets.sessionToken}`,
  'User-Agent': secrets.userAgent,
};
const mutationHeaders = {
  ...authHeaders,
  Origin: origin,
  'Sec-Fetch-Site': 'same-origin',
  'Content-Type': 'application/json',
  'X-BXSS-CSRF': secrets.csrf,
};

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

try {
  const noLength = await fetch(`${origin}/c/${secrets.collectorToken}`, {
    method: 'POST',
    headers: { 'Content-Type': 'multipart/form-data; boundary=empty' },
  });
  // Node supplies Content-Length: 0 for this request; both absent and empty
  // bodies must fail before multipart parsing.
  assert(noLength.status === 413, `empty callback returned ${noLength.status}`);

  const createdCollectorResponse = await fetch(`${origin}/api/collectors`, {
    method: 'POST',
    headers: mutationHeaders,
    body: JSON.stringify({ name: 'Additional integration payload' }),
  });
  assert(createdCollectorResponse.status === 201, `collector creation returned ${createdCollectorResponse.status}`);
  const createdCollector = (await createdCollectorResponse.json()).collector;
  assert(createdCollector?.name === 'Additional integration payload', 'new collector name did not round-trip');
  assert(
    /^https?:\/\/[^/]+\/p\/[A-Za-z0-9_-]{40,80}\.js$/.test(createdCollector?.loaderUrl || ''),
    'new collector loader URL is invalid',
  );

  const aliasRotation = await fetch(`${origin}/api/collectors/${secrets.collectorId}/alias/rotate`, {
    method: 'POST',
    headers: mutationHeaders,
    body: '{}',
  });
  assert(aliasRotation.status === 200, `alias rotation returned ${aliasRotation.status}`);
  const aliasBody = await aliasRotation.json();
  assert(/^[A-Za-z0-9_-]{22}$/.test(aliasBody.alias), 'compact alias is not canonical 128-bit base64url');
  assert(aliasBody.aliasLoaderUrl === `${origin}/a/${aliasBody.alias}.js`, 'compact alias URL is wrong');

  const sourceInput = '  Ｅxample\u202E   placement  ';
  const expectedSourceLabel = 'Example placement';
  const compactLoaderUrl = new URL(aliasBody.aliasLoaderUrl);
  compactLoaderUrl.searchParams.set('url', sourceInput);
  compactLoaderUrl.search += '&aa&tag=one&tag=two';
  const compactLoader = await fetch(compactLoaderUrl);
  assert(compactLoader.status === 200, `compact loader returned ${compactLoader.status}`);
  assert((compactLoader.headers.get('cache-control') || '').includes('no-store'), 'compact loader is cacheable');
  const compactSource = await compactLoader.text();
  assert(!compactSource.includes(sourceInput), 'source label was interpolated into executable JavaScript');
  const compactRuntimePath = JSON.parse(/s\.src=("[^"]+")/.exec(compactSource)?.[1] || 'null');
  assert(typeof compactRuntimePath === 'string', 'compact loader is missing its runtime URL');
  const compactRuntimeUrl = new URL(compactRuntimePath);
  const compactConfig = JSON.parse(Buffer.from(compactRuntimeUrl.searchParams.get('config'), 'base64url').toString('utf8'));
  assert(new URL(compactConfig.callback).pathname === `/c/a/${aliasBody.alias}`, 'compact callback path is wrong');
  assert(compactConfig.captureStorage === true, 'browser storage capture was not enabled in probe config');
  assert(new URL(compactConfig.callback).searchParams.has('source_label_sig'), 'source label is not signed');
  assert(new URL(compactConfig.callback).searchParams.has('payload_params_sig'), 'payload parameters are not signed');
  const compactRuntime = await fetch(compactRuntimeUrl);
  assert(compactRuntime.status === 200, `compact signed runtime returned ${compactRuntime.status}`);

  const injectionKey = 'integration-key';
  const injectionRequest = 'POST /authorized HTTP/1.1\nX-Synthetic: true';
  const injected = await fetch(`${origin}/ingest/injections`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${secrets.injectionToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ collectorId: secrets.collectorId, injectionKey, request: injectionRequest }),
  });
  assert(injected.status === 202, `injection correlation returned ${injected.status}`);

  const event = {
    schemaVersion: 1,
    probeUid: 'integration-probe',
    sourceLabel: 'forged-body-label',
    injectionKey,
    url: 'https://authorized.example.invalid/account?test=1',
    origin: 'https://authorized.example.invalid',
    referrer: 'https://authorized.example.invalid/start',
    userAgent: 'Synthetic Browser',
    title: '<script>must remain inert</script>',
    browserTime: Date.now(),
    wasIframe: false,
    cookies: 'critical_cookie=encrypted-only',
    domHtml: '<main><img src=x onerror=alert(1)>encrypted DOM</main>',
    domText: 'encrypted DOM',
    localStorage: [{ key: 'local-key', value: 'encrypted-local-value' }],
    sessionStorage: [{ key: 'session-key', value: 'encrypted-session-value' }],
    viewport: { width: 1280, height: 720, devicePixelRatio: 1 },
    secrets: [{ type: 'synthetic', value: 'integration-secret' }],
    cors: false,
    gitExposed: false,
    pages: [],
  };
  const sendCapture = async (probeUid, callback = `${origin}/c/${secrets.collectorToken}`) => {
    const form = new FormData();
    form.set('event', JSON.stringify({ ...event, probeUid }));
    form.set('screenshot', new File([new Uint8Array([0xff, 0xd8, 0xff, 0xd9])], 'capture.jpg', { type: 'image/jpeg' }));
    return fetch(callback, { method: 'POST', body: form });
  };
  const accepted = await sendCapture(event.probeUid, compactConfig.callback);
  assert(accepted.status === 204, `valid callback returned ${accepted.status}`);

  const loader = await fetch(`${origin}/p/${secrets.collectorToken}.js`);
  assert(loader.status === 200, `loader returned ${loader.status}`);
  assert((loader.headers.get('content-type') || '').startsWith('application/javascript'), 'loader MIME is wrong');
  const loaderSource = await loader.text();
  const runtimePath = JSON.parse(/s\.src=("[^"]+")/.exec(loaderSource)?.[1] || 'null');
  assert(typeof runtimePath === 'string' && runtimePath.includes('/probe-runtime/'), 'loader is missing its signed runtime URL');
  const runtime = await fetch(runtimePath);
  assert(runtime.status === 200, `probe runtime returned ${runtime.status}`);
  assert((runtime.headers.get('content-type') || '').includes('javascript'), 'probe runtime MIME is wrong');
  assert((await runtime.text()).length > 10_000, 'probe runtime bundle is unexpectedly empty');
  const tamperedRuntime = new URL(runtimePath);
  tamperedRuntime.searchParams.set('config', tamperedRuntime.searchParams.get('config').slice(0, -1) + 'A');
  assert((await fetch(tamperedRuntime)).status === 404, 'tampered probe configuration was accepted');
  const genericRuntime = await fetch(`${origin}/probe-runtime.js`);
  assert(genericRuntime.status !== 200, 'unsigned generic probe runtime is publicly reachable');

  const listed = await fetch(`${origin}/api/events`, { headers: authHeaders });
  assert(listed.status === 200, `event list returned ${listed.status}`);
  const listBody = await listed.json();
  assert(listBody.events?.length === 1, 'event was not indexed exactly once');
  const eventId = listBody.events[0].id;
  assert(listBody.events[0].summary.title === event.title, 'encrypted summary did not round-trip');
  assert(
    listBody.events[0].summary.sourceLabel === expectedSourceLabel,
    'normalized source label did not round-trip in the encrypted summary',
  );
  const expectedPayloadParams = [
    { name: 'url', value: sourceInput.normalize('NFKC').replace(/[\p{Cc}\p{Cf}]/gu, ' ') },
    { name: 'aa', value: '' },
    { name: 'tag', value: 'one' },
    { name: 'tag', value: 'two' },
  ];
  assert(
    JSON.stringify(listBody.events[0].summary.payloadParams) === JSON.stringify(expectedPayloadParams),
    'signed payload parameters did not round-trip in the encrypted summary',
  );

  const viewed = await fetch(`${origin}/api/events/${eventId}`, { headers: authHeaders });
  assert(viewed.status === 200, `event detail returned ${viewed.status}`);
  const viewedBody = (await viewed.json()).event;
  const detail = viewedBody.detail;
  assert(detail.cookies === event.cookies, 'encrypted cookie detail did not round-trip');
  assert(detail.domHtml === event.domHtml, 'encrypted DOM detail did not round-trip');
  assert(JSON.stringify(detail.localStorage) === JSON.stringify(event.localStorage), 'localStorage did not round-trip');
  assert(JSON.stringify(detail.sessionStorage) === JSON.stringify(event.sessionStorage), 'sessionStorage did not round-trip');
  assert(detail.sourceLabel === expectedSourceLabel, 'server source label did not override the capture body');
  assert(
    JSON.stringify(detail.payloadParams) === JSON.stringify(expectedPayloadParams),
    'signed payload parameters did not round-trip in encrypted detail',
  );
  assert(viewedBody.correlatedRequest?.request === injectionRequest, 'correlated injection request did not round-trip');

  const screenshot = await fetch(`${origin}/api/events/${eventId}/screenshot`, { headers: authHeaders });
  assert(screenshot.status === 200, `screenshot returned ${screenshot.status}`);
  assert(screenshot.headers.get('content-type') === 'image/jpeg', 'screenshot MIME was not revalidated');
  const screenshotBytes = new Uint8Array(await screenshot.arrayBuffer());
  assert(screenshotBytes[0] === 0xff && screenshotBytes[1] === 0xd8, 'screenshot decrypt failed');

  const aliasRevocation = await fetch(`${origin}/api/collectors/${secrets.collectorId}/alias/revoke`, {
    method: 'POST',
    headers: mutationHeaders,
    body: '{}',
  });
  const revokedBody = await aliasRevocation.json();
  assert(aliasRevocation.status === 200 && revokedBody.revoked === true, 'active alias was not revoked');
  assert((await fetch(compactLoaderUrl)).status === 404, 'revoked compact loader still resolves');
  assert((await fetch(compactRuntimeUrl)).status === 404, 'revoked compact runtime still resolves');
  assert((await sendCapture('revoked-alias', compactConfig.callback)).status === 204, 'revoked alias response leaked state');
  const afterRevokedCallback = await (await fetch(`${origin}/api/events`, { headers: authHeaders })).json();
  assert(afterRevokedCallback.events?.length === 1, 'revoked alias committed a telemetry event');

  const secondRotation = await fetch(`${origin}/api/collectors/${secrets.collectorId}/alias/rotate`, {
    method: 'POST',
    headers: mutationHeaders,
    body: '{}',
  });
  const secondAlias = await secondRotation.json();
  assert(secondRotation.status === 200 && secondAlias.alias !== aliasBody.alias, 'alias did not rotate');
  const collectorsResponse = await fetch(`${origin}/api/collectors`, { headers: authHeaders });
  const collectorsBody = await collectorsResponse.json();
  const integrationCollector = collectorsBody.collectors?.find((collector) => collector.id === secrets.collectorId);
  assert(collectorsResponse.status === 200, `collector list returned ${collectorsResponse.status}`);
  assert(integrationCollector?.alias === secondAlias.alias, 'active alias is missing from admin API');
  assert(
    integrationCollector?.aliasLoaderUrl === secondAlias.aliasLoaderUrl,
    'active compact URL is missing from admin API',
  );

  const crossOrigin = await fetch(`${origin}/api/events/${eventId}/read`, {
    method: 'POST',
    headers: { ...mutationHeaders, Origin: 'https://attacker.invalid' },
    body: JSON.stringify({ read: true }),
  });
  assert(crossOrigin.status === 403, `cross-origin mutation returned ${crossOrigin.status}`);

  const marked = await fetch(`${origin}/api/events/${eventId}/read`, {
    method: 'POST',
    headers: mutationHeaders,
    body: JSON.stringify({ read: true }),
  });
  assert(marked.status === 200, `same-origin read mutation returned ${marked.status}`);

  const exported = await fetch(`${origin}/api/export/events`, { headers: authHeaders });
  assert(exported.status === 200, `plaintext export returned ${exported.status}`);
  const exportBody = await exported.json();
  assert(exportBody.manifest?.format === 'bxss-vault-plaintext-v1', 'export manifest is missing');
  assert(
    exportBody.manifest?.collectors?.some((collector) => collector.id === secrets.collectorId && collector.token === secrets.collectorToken),
    'collector migration token did not export',
  );
  assert(exportBody.events?.[0]?.detail?.cookies === event.cookies, 'event plaintext did not export');
  assert(exportBody.events?.[0]?.correlatedRequest?.request === injectionRequest, 'correlated request did not export');
  assert(exportBody.events?.[0]?.screenshot?.mime === 'image/jpeg', 'image did not export');
  const exportedImage = Buffer.from(exportBody.events[0].screenshot.data, 'base64url');
  assert(exportedImage[0] === 0xff && exportedImage[1] === 0xd8, 'exported image bytes are invalid');
  const injectionExport = await fetch(`${origin}/api/export/injections`, { headers: authHeaders });
  assert(injectionExport.status === 200, `injection export returned ${injectionExport.status}`);
  const injectionBody = await injectionExport.json();
  assert(injectionBody.requests?.[0]?.data?.request === injectionRequest, 'unmatched/matched injection export is incomplete');

  // --- Out-of-band interaction server --------------------------------------
  const createdProbe = await fetch(`${origin}/api/oob`, {
    method: 'POST',
    headers: mutationHeaders,
    body: JSON.stringify({ name: 'Integration OOB listener' }),
  });
  assert(createdProbe.status === 201, `oob listener creation returned ${createdProbe.status}`);
  const probe = (await createdProbe.json()).probe;
  assert(/^[a-z2-7]{26}$/.test(probe.token), 'oob token is not a canonical base32 token');
  assert(probe.pathLoaderUrl === `${origin}/o/${probe.token}`, 'oob path loader URL is wrong');

  const oobCallback = await fetch(`${origin}/o/${probe.token}/blind-rce?x=1`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Synthetic-Oob': 'yes' },
    body: JSON.stringify({ probe: 'oob' }),
  });
  assert(oobCallback.status === 200, `oob callback returned ${oobCallback.status}`);
  assert((await oobCallback.text()) === '', 'oob endpoint reflected a response body');
  assert(oobCallback.headers.get('access-control-allow-origin') === '*', 'oob endpoint is missing permissive CORS');

  // Unknown but well-formed tokens get the same uniform response: no enumeration signal.
  const unknownOob = await fetch(`${origin}/o/aaaaaaaaaaaaaaaaaaaaaaaaaa`);
  assert(unknownOob.status === 200, `unknown oob token returned ${unknownOob.status}`);

  const oobList = await (await fetch(`${origin}/api/oob/interactions?probeId=${probe.id}`, { headers: authHeaders })).json();
  assert(oobList.interactions?.length === 1, 'oob interaction was not indexed exactly once');
  const oobInteractionId = oobList.interactions[0].id;
  const oobSummary = oobList.interactions[0].summary;
  assert(oobSummary.method === 'POST', 'oob summary method did not round-trip');
  assert(oobSummary.matchedBy === 'path', 'oob summary match source did not round-trip');
  assert(oobSummary.query === 'x=1', 'oob summary query did not round-trip');
  // The non-step-up summary must not disclose the listener token, but must keep
  // the capture sub-path for triage.
  assert(!oobSummary.path.includes(probe.token), 'listener token leaked into the non-step-up summary');
  assert(oobSummary.path.includes('/blind-rce'), 'oob summary path lost its capture sub-path');

  const viewedOob = await (await fetch(`${origin}/api/oob/interactions/${oobInteractionId}`, { headers: authHeaders })).json();
  const oobDetail = viewedOob.interaction.detail;
  assert(oobDetail.path === `/o/${probe.token}/blind-rce`, 'step-up detail should retain the full request path');
  assert(oobDetail.body === JSON.stringify({ probe: 'oob' }), 'encrypted oob body did not round-trip');
  assert(
    Array.isArray(oobDetail.headers) && oobDetail.headers.some((header) => header.name === 'x-synthetic-oob' && header.value === 'yes'),
    'encrypted oob header did not round-trip',
  );

  const oobExport = await (await fetch(`${origin}/api/export/oob`, { headers: authHeaders })).json();
  assert(oobExport.interactions?.[0]?.detail?.body === JSON.stringify({ probe: 'oob' }), 'oob interaction did not export');

  // Custom response control: the operator decides status, headers, and body.
  const configured = await fetch(`${origin}/api/oob/${probe.id}`, {
    method: 'PATCH',
    headers: mutationHeaders,
    body: JSON.stringify({
      response: {
        status: 418,
        body: '<x>dtd</x>',
        headers: [
          { name: 'Content-Type', value: 'application/xml' },
          { name: 'X-OOB', value: 'served' },
        ],
      },
    }),
  });
  assert(configured.status === 200, `oob response config returned ${configured.status}`);
  assert((await configured.json()).probe?.response?.status === 418, 'oob response config did not round-trip');

  const served = await fetch(`${origin}/o/${probe.token}/with-response`);
  assert(served.status === 418, `configured oob response status was ${served.status}`);
  assert(served.headers.get('content-type') === 'application/xml', 'configured content-type was not served');
  assert(served.headers.get('x-oob') === 'served', 'configured custom header was not served');
  assert(served.headers.get('access-control-allow-origin') === '*', 'default CORS header was dropped');
  assert((await served.text()) === '<x>dtd</x>', 'configured response body was not served');

  // Framing / injection headers must be rejected by the admin API.
  const forbidden = await fetch(`${origin}/api/oob/${probe.id}`, {
    method: 'PATCH',
    headers: mutationHeaders,
    body: JSON.stringify({ response: { status: 200, headers: [{ name: 'Content-Length', value: '9' }] } }),
  });
  assert(forbidden.status === 422, `forbidden response header should be rejected, got ${forbidden.status}`);

  // A 3xx + Location redirect (SSRF chaining) is served as configured.
  const redirectConfig = await fetch(`${origin}/api/oob/${probe.id}`, {
    method: 'PATCH',
    headers: mutationHeaders,
    body: JSON.stringify({ response: { status: 302, headers: [{ name: 'Location', value: 'https://authorized.internal/' }] } }),
  });
  assert(redirectConfig.status === 200, `redirect config returned ${redirectConfig.status}`);
  const redirected = await fetch(`${origin}/o/${probe.token}`, { redirect: 'manual' });
  assert(redirected.status === 302, `redirect status was ${redirected.status}`);
  assert(redirected.headers.get('location') === 'https://authorized.internal/', 'redirect Location was not served');

  // Clearing reverts to the inert empty 200 default.
  const cleared = await fetch(`${origin}/api/oob/${probe.id}`, {
    method: 'PATCH',
    headers: mutationHeaders,
    body: JSON.stringify({ response: null }),
  });
  assert(cleared.status === 200 && (await cleared.json()).probe?.response === null, 'custom response was not cleared');
  const defaulted = await fetch(`${origin}/o/${probe.token}`);
  assert(defaulted.status === 200 && (await defaulted.text()) === '', 'listener did not revert to the empty 200 default');

  // Reset the interaction log (the response probes above were captured too).
  for (let guard = 0; guard < 20; guard += 1) {
    const payload = await (await fetch(`${origin}/api/oob/interactions`, {
      method: 'DELETE',
      headers: mutationHeaders,
      body: JSON.stringify({ all: true, probeId: probe.id, confirmation: 'DELETE OOB INTERACTIONS' }),
    })).json();
    if (!payload.remaining) break;
  }
  const afterClear = await (await fetch(`${origin}/api/oob/interactions?probeId=${probe.id}`, { headers: authHeaders })).json();
  assert((afterClear.interactions?.length ?? 0) === 0, 'per-probe interaction clear did not empty the log');

  // Disabled listeners stop capturing while still returning a response.
  const paused = await fetch(`${origin}/api/oob/${probe.id}`, {
    method: 'PATCH',
    headers: mutationHeaders,
    body: JSON.stringify({ enabled: false }),
  });
  assert(paused.status === 200, `oob listener pause returned ${paused.status}`);
  assert((await fetch(`${origin}/o/${probe.token}`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'x' })).status === 200, 'paused oob listener leaked state');
  const afterPaused = await (await fetch(`${origin}/api/oob/interactions?probeId=${probe.id}`, { headers: authHeaders })).json();
  assert((afterPaused.interactions?.length ?? 0) === 0, 'paused oob listener committed an interaction');

  // Deleting the listener removes the listener row.
  let deletedProbe = false;
  for (let attempt = 0; attempt < 10 && !deletedProbe; attempt += 1) {
    const payload = await (await fetch(`${origin}/api/oob/${probe.id}`, { method: 'DELETE', headers: mutationHeaders, body: '{}' })).json();
    deletedProbe = payload.deleted === true;
  }
  assert(deletedProbe, 'oob listener was not deleted after draining interactions');
  assert(
    (await fetch(`${origin}/api/oob/interactions/${oobInteractionId}`, { headers: authHeaders })).status === 404,
    'oob interaction survived listener deletion',
  );

  if (process.env.BXSS_TEST_RETENTION === '1') {
    const wrangler = fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js', import.meta.url));
    const aged = spawnSync(
      process.execPath,
      [wrangler, 'd1', 'execute', 'DB', '--local', '--command', `UPDATE events SET received_at = 0 WHERE id = '${eventId}'`],
      { cwd: new URL('..', import.meta.url), encoding: 'utf8', windowsHide: true },
    );
    assert(aged.status === 0, `could not age event for retention test: ${aged.stderr || aged.stdout}`);
    const scheduledUrl = new URL('/__scheduled', origin);
    scheduledUrl.searchParams.set('cron', '*/5 * * * *');
    const scheduled = await fetch(scheduledUrl);
    assert(scheduled.status === 200, `scheduled retention returned ${scheduled.status}`);
  } else {
    const deleted = await fetch(`${origin}/api/events/${eventId}`, {
      method: 'DELETE',
      headers: mutationHeaders,
      body: '{}',
    });
    assert(deleted.status === 200, `event delete returned ${deleted.status}`);

    assert((await sendCapture('integration-bulk')).status === 204, 'bulk-delete fixture was not accepted');
    const bulkList = await (await fetch(`${origin}/api/events`, { headers: authHeaders })).json();
    const bulkId = bulkList.events?.[0]?.id;
    const bulkDeleted = await fetch(`${origin}/api/events`, {
      method: 'DELETE',
      headers: mutationHeaders,
      body: JSON.stringify({ ids: [bulkId] }),
    });
    assert(bulkDeleted.status === 200, `bulk delete returned ${bulkDeleted.status}`);
    assert((await bulkDeleted.json()).deletedIds?.includes(bulkId), 'bulk delete did not report the deleted event');

    assert((await sendCapture('integration-delete-all')).status === 204, 'delete-all fixture was not accepted');
    const deleteAll = await fetch(`${origin}/api/events`, {
      method: 'DELETE',
      headers: mutationHeaders,
      body: JSON.stringify({ all: true, confirmation: 'DELETE ALL CAPTURES' }),
    });
    assert(deleteAll.status === 200, `delete all returned ${deleteAll.status}`);
    assert((await deleteAll.json()).remaining === false, 'delete all did not finish');
  }

  const afterDelete = await fetch(`${origin}/api/events/${eventId}`, { headers: authHeaders });
  assert(afterDelete.status === 404, `deleted event returned ${afterDelete.status}`);
  const stats = await fetch(`${origin}/api/stats`, { headers: authHeaders });
  const statsBody = await stats.json();
  assert(stats.status === 200 && statsBody.stats.eventCount === 0, 'event counter did not return to zero');
  assert(statsBody.stats.storageBytes === 0, 'storage counter did not return to zero');

  const unauthenticated = await fetch(`${origin}/api/events`);
  assert(unauthenticated.status === 401, `unauthenticated API returned ${unauthenticated.status}`);
  console.log(
    process.env.BXSS_TEST_RETENTION === '1'
      ? 'Local encrypted ingest/view/scheduled-retention integration passed.'
      : 'Local encrypted ingest/export/view/screenshot/single/bulk/delete-all integration passed.',
  );
} finally {
  await rm(secretsUrl, { force: true });
}
