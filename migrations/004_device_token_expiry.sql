-- Device tokens must age out: before this column they were valid forever and
-- revocation was the only lever (and had no endpoint). New tokens are minted
-- with a 90-day expiry; existing rows keep 0 (= no expiry) — revoke and
-- re-enroll them, or let the next rotation handle them.
ALTER TABLE device_tokens ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;
