PRAGMA foreign_keys = ON;

CREATE TABLE app_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  storage_bytes INTEGER NOT NULL DEFAULT 0 CHECK (storage_bytes >= 0),
  event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT INTO app_state (id, created_at, updated_at)
VALUES (1, unixepoch(), unixepoch());

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  display_name TEXT NOT NULL,
  webauthn_user_id TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'analyst')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  session_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX users_single_owner
ON users(role) WHERE role = 'owner';

CREATE TABLE passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE INDEX passkeys_user_id ON passkeys(user_id);

CREATE TABLE auth_challenges (
  flow_hash TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('bootstrap', 'login', 'add_passkey', 'step_up', 'recovery')),
  challenge TEXT NOT NULL,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  context_json TEXT NOT NULL DEFAULT '{}',
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX auth_challenges_expiry ON auth_challenges(expires_at);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  user_agent_hash TEXT NOT NULL,
  session_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  step_up_until INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE recovery_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);

CREATE INDEX recovery_codes_user_id ON recovery_codes(user_id);

CREATE TABLE collectors (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_ciphertext TEXT NOT NULL,
  token_iv TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  capture_cookies INTEGER NOT NULL DEFAULT 1 CHECK (capture_cookies IN (0, 1)),
  capture_dom INTEGER NOT NULL DEFAULT 1 CHECK (capture_dom IN (0, 1)),
  capture_screenshot INTEGER NOT NULL DEFAULT 0 CHECK (capture_screenshot IN (0, 1)),
  probe_checks INTEGER NOT NULL DEFAULT 0 CHECK (probe_checks IN (0, 1)),
  page_paths TEXT NOT NULL DEFAULT '[]',
  chainload_url TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX collectors_user_id ON collectors(user_id);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  collector_id TEXT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL,
  summary_ciphertext TEXT NOT NULL,
  summary_iv TEXT NOT NULL,
  detail_key TEXT NOT NULL,
  detail_bytes INTEGER NOT NULL DEFAULT 0,
  screenshot_key TEXT,
  screenshot_bytes INTEGER NOT NULL DEFAULT 0,
  screenshot_mime TEXT,
  probe_uid_hash TEXT,
  injection_key_hash TEXT,
  is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
  created_day TEXT NOT NULL
);

CREATE INDEX events_collector_time ON events(collector_id, received_at DESC, id DESC);
CREATE INDEX events_day ON events(created_day);
CREATE INDEX events_probe_uid ON events(collector_id, probe_uid_hash);

CREATE TABLE injection_requests (
  id TEXT PRIMARY KEY,
  collector_id TEXT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
  injection_key_hash TEXT NOT NULL,
  request_ciphertext TEXT NOT NULL,
  request_iv TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (collector_id, injection_key_hash)
);

CREATE INDEX injection_requests_lookup
ON injection_requests(collector_id, injection_key_hash);

CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL CHECK (scope = 'injection:write'),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX api_tokens_user_id ON api_tokens(user_id);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  result TEXT NOT NULL CHECK (result IN ('success', 'denied', 'error')),
  request_id TEXT,
  ip_hash TEXT,
  user_agent_hash TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE INDEX audit_log_time ON audit_log(created_at DESC);
CREATE INDEX audit_log_user ON audit_log(user_id, created_at DESC);
