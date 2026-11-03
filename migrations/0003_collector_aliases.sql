CREATE TABLE collector_aliases (
  id TEXT PRIMARY KEY,
  collector_id TEXT NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
  alias_hash TEXT NOT NULL UNIQUE CHECK (length(alias_hash) = 43),
  alias_ciphertext TEXT,
  alias_iv TEXT,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (
    (revoked_at IS NULL AND alias_ciphertext IS NOT NULL AND alias_iv IS NOT NULL)
    OR
    (revoked_at IS NOT NULL AND alias_ciphertext IS NULL AND alias_iv IS NULL)
  )
);

CREATE UNIQUE INDEX collector_aliases_one_active
ON collector_aliases(collector_id) WHERE revoked_at IS NULL;

CREATE INDEX collector_aliases_history
ON collector_aliases(collector_id, created_at DESC);
