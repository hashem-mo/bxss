-- Out-of-band (OOB) HTTP interaction capture.
--
-- An OOB listener owns a DNS- and path-safe base32 token. Any request that a
-- target server makes to the token (as a /o/<token> path, or as the leftmost
-- label of an optional wildcard capture host) is recorded as an interaction.
-- This proves blind, out-of-band vulnerabilities such as SSRF, blind command
-- injection, XXE, and template/JNDI callbacks without executing anything.
--
-- Interactions share the same application-level AES-256-GCM encryption, the
-- R2 storage byte budget tracked in app_state, and the retention sweep as blind
-- XSS captures. The token is only ever stored as a keyed hash plus an encrypted
-- copy for one-time display, exactly like a collector token.

CREATE TABLE oob_probes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_ciphertext TEXT NOT NULL,
  token_iv TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  discord_notifications INTEGER NOT NULL DEFAULT 0 CHECK (discord_notifications IN (0, 1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX oob_probes_user_id ON oob_probes(user_id);

CREATE TABLE oob_interactions (
  id TEXT PRIMARY KEY,
  probe_id TEXT NOT NULL REFERENCES oob_probes(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL,
  summary_ciphertext TEXT NOT NULL,
  summary_iv TEXT NOT NULL,
  detail_key TEXT NOT NULL,
  detail_bytes INTEGER NOT NULL DEFAULT 0,
  is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
  created_day TEXT NOT NULL
);

CREATE INDEX oob_interactions_probe_time ON oob_interactions(probe_id, received_at DESC, id DESC);
CREATE INDEX oob_interactions_day ON oob_interactions(created_day);
CREATE INDEX oob_interactions_retention ON oob_interactions(received_at ASC, id ASC);
