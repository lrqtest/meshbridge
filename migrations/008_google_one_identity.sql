-- A user holds at most one Google identity. The application checks this inside
-- its linking transaction; this index is the final arbiter between concurrent
-- first sign-ins, and stops a reassigned mailbox from attaching a second
-- Google subject to an account that is already linked.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_identities_one_per_provider ON user_identities(user_id, provider);
