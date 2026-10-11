-- Google identities are keyed by Google's immutable subject, never by email.
CREATE TABLE IF NOT EXISTS user_identities(
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_sub TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(provider, provider_sub)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);
