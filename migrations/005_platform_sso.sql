-- Opaque application grants derive from one expiring human login token.
-- Deleting that parent token revokes every application grant from the session.
CREATE TABLE IF NOT EXISTS sso_grants(
  token_hash TEXT PRIMARY KEY,
  parent_hash TEXT NOT NULL REFERENCES api_tokens(token_hash) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sso_grants_parent ON sso_grants(parent_hash,client_id);
CREATE INDEX IF NOT EXISTS idx_sso_grants_expiry ON sso_grants(expires_at);
