-- MeshBridge schema v2: email-based accounts + email verification codes.
-- Idempotent: ALTER statements are retried by db.RunMigrations which skips
-- "duplicate column" errors; indexes use IF NOT EXISTS.

ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL AND email != '';

CREATE TABLE IF NOT EXISTS email_verification_codes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,      -- sha256(code || ":" || serverSecret)
  purpose TEXT NOT NULL,        -- setup|register|reset
  attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evcode_email ON email_verification_codes(email, purpose, created_at);

INSERT OR IGNORE INTO settings(key, value) VALUES
  ('allow_registration', '1'),
  ('setup_completed', '0'),
  ('mail_code_cooldown_seconds', '60'),
  ('mail_code_expire_minutes', '15'),
  ('mail_code_minute_limit', '5'),
  ('mail_code_daily_limit', '100');
