# Security policy

BXSS Vault is a hostile-content vault. Treat every captured URL, cookie, DOM,
request, image, string, and out-of-band HTTP interaction as attacker-controlled,
even when a capture came from an authorized target.

## Deployment invariants

- Keep the R2 bucket private. Do not enable `r2.dev`, a public bucket domain,
  bucket CORS, or S3 credentials.
- Keep `AUTH_PEPPER` and `DATA_ENCRYPTION_KEY` only in Cloudflare Worker
  secrets and an offline recovery store. Never commit them.
- Set `APP_ORIGIN` and `RP_ID` explicitly before using a custom production
  hostname. Changing the RP ID makes existing passkeys unusable.
- Put the console hostname behind a deny-by-default Cloudflare Access policy
  and configure `CF_ACCESS_TEAM_DOMAIN` plus `CF_ACCESS_AUD` for in-Worker JWT
  validation.
- Allow only exact administrator identities in Access. Require a WebAuthn
  hardware key and enroll at least two keys per administrator.
- Never place captured data in email, chat, analytics, Worker logs, or issue
  trackers. Optional Discord notices are restricted to collector/listener name,
  a random event or interaction ID, the HTTP method for out-of-band interactions,
  and receipt time; they never contain captured content.
- If you enable the out-of-band wildcard host (`OOB_WILDCARD_HOST`), keep it off
  the console hostname and never place it behind Cloudflare Access. It is a
  public, token-gated capture surface.
- A per-listener custom OOB response is served on the collector origin. It is
  operator-authored, validated (field-name token, ASCII values, no CR/LF, no
  framing headers) and token-gated, but it does let that origin return
  operator-chosen status, headers (including `Location`/`Set-Cookie`) and body —
  so treat it as content you are publishing there, and only configure authorized
  content. The default empty `200` response remains in force until you opt in.
- Keep `DISCORD_WEBHOOK_URL` only as a Cloudflare Worker secret. Treat it as a
  credential because anyone holding it can post into the configured channel.
- Keep the console free of third-party scripts, fonts, tag managers, and
  analytics.
- Take encrypted offline backups and test restoration. Cloudflare Free has no
  mission-critical availability SLA.
- Confirm the scheduled retention trigger is present after deployment and
  test it with synthetic data before relying on automatic deletion.

## Authentication model

There are no passwords and no public signup. The first owner is created only
with the high-entropy `BOOTSTRAP_TOKEN`. Authentication uses discoverable
passkeys with user verification required. Sessions are opaque, server-side,
bound to the browser user agent, idle-expiring, absolute-expiring, revocable,
and protected by `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` cookies.

Sensitive reads and mutations require a new passkey assertion within five
minutes. Recovery codes are high-entropy, single-use, and can only register a
new passkey; they do not directly reveal data. Successful recovery revokes all
existing sessions.

## Stored-data model

Sensitive summaries, event bodies (including bounded local/session storage),
screenshots, collector tokens, correlated requests, out-of-band listener tokens,
and out-of-band interactions (method, host, path, query, bounded request headers
and body, and source metadata) are encrypted with AES-256-GCM before D1/R2
storage. Each object uses a fresh 96-bit nonce and context-specific authenticated
data. R2 object names contain only random IDs. Screenshots are validated by magic
bytes before storage and after decryption. Out-of-band listener tokens, like
collector tokens, are stored only as a keyed hash plus an encrypted copy for
one-time display.

This application-level encryption protects database and bucket exports. It
does not protect against an attacker who controls both the deployed Worker and
its secrets. For that threat model, split collector/admin/storage into separate
Workers and use a client-held or external-KMS decryption key.

The one-command deployment deliberately uses a single Worker for operational
simplicity. That is a documented isolation tradeoff, not equivalent to an
independently audited secrets vault or a supported mission-critical service.

## Plaintext exports

Migration exports deliberately remove application-level encryption. Generate
them only on a trusted administrator device, write them directly to encrypted
storage, verify completeness before migration, and securely dispose of working
copies. The manifest contains live collector and out-of-band listener tokens;
rotate those tokens after the destination is operational. Never upload an export
to chat, email, a public issue, or an unencrypted consumer cloud drive.

## Reporting a vulnerability

Do not include real captures, credentials, cookies, or target details in a
report. Provide a minimal synthetic reproduction and the affected commit.
