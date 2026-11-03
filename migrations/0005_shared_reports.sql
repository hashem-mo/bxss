CREATE TABLE shared_reports (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 80),
  token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 43),
  token_ciphertext TEXT NOT NULL,
  token_iv TEXT NOT NULL,
  payload_key TEXT NOT NULL,
  payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
  event_count INTEGER NOT NULL CHECK (event_count >= 1 AND event_count <= 8),
  screenshot_count INTEGER NOT NULL CHECK (screenshot_count >= 0 AND screenshot_count <= event_count),
  object_keys_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_viewed_at INTEGER,
  CHECK (expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (
    (revoked_at IS NULL AND token_ciphertext <> '' AND token_iv <> '')
    OR
    (revoked_at IS NOT NULL AND token_ciphertext = '' AND token_iv = '')
  )
);

CREATE INDEX shared_reports_user
ON shared_reports(user_id, created_at DESC, id DESC);

CREATE INDEX shared_reports_lookup
ON shared_reports(token_hash);

CREATE INDEX shared_reports_retention
ON shared_reports(expires_at ASC, id ASC);
