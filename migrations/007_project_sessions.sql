-- MeshBridge project sessions that were derived from a platform sign-in carry
-- the (hashed) grant they were issued from. Deleting that grant -- platform
-- sign-out, the expiry sweep, a password reset that drops the parent token --
-- deletes the project session with it, so revocation is immediate and costs
-- nothing on the request path. Local password/Google sessions leave it NULL.
ALTER TABLE api_tokens ADD COLUMN grant_hash TEXT REFERENCES sso_grants(token_hash) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_api_tokens_grant ON api_tokens(grant_hash) WHERE grant_hash IS NOT NULL;
