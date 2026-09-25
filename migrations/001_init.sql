-- MeshBridge schema v1 (SQLite, WAL). Keep migrations idempotent-ish.
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user', -- admin|user
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_memberships(
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL, -- owner|admin|member|viewer
  PRIMARY KEY(project_id, user_id)
);

CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(id),
  headscale_node_id TEXT,
  tailscale_ip TEXT,
  tags TEXT NOT NULL DEFAULT '[]',
  project_ids TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_enrollment_tokens(
  token_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agents(
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  agent_version TEXT NOT NULL DEFAULT '',
  tailscale_version TEXT NOT NULL DEFAULT '',
  last_seen INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 0,
  info_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS agent_sessions(
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_tokens(
  token_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_used INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_device_tokens_device ON device_tokens(device_id);

CREATE TABLE IF NOT EXISTS relay_nodes(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  region TEXT NOT NULL, -- jp|hk|sg|usw|...
  tags TEXT NOT NULL DEFAULT '[]',
  udp_port INTEGER NOT NULL DEFAULT 40000,
  monthly_quota_bytes INTEGER NOT NULL DEFAULT 1099511627776,
  bytes_in_month INTEGER NOT NULL DEFAULT 0,
  bytes_out_month INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0,
  healthy INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS transfer_jobs(
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  src_device_id TEXT NOT NULL,
  dst_device_id TEXT NOT NULL,
  src_path TEXT NOT NULL,
  dst_path TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'QUEUED', -- QUEUED|PROBING|WAITING_FOR_ROUTE|TRANSFERRING|PAUSED|VERIFYING|COMPLETED|FAILED|CANCELLED
  route_type TEXT NOT NULL DEFAULT '',
  relay_id TEXT NOT NULL DEFAULT '',
  bytes_total INTEGER NOT NULL DEFAULT 0,
  bytes_done INTEGER NOT NULL DEFAULT 0,
  retry_count INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  started_at INTEGER NOT NULL DEFAULT 0,
  completed_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS transfer_files(
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES transfer_jobs(id) ON DELETE CASCADE,
  rel_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  chunk_size INTEGER NOT NULL,
  chunk_count INTEGER NOT NULL,
  final_blake3 TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS transfer_chunks(
  job_id TEXT NOT NULL,
  file_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  blake3 TEXT NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(job_id, file_id, idx)
);

CREATE TABLE IF NOT EXISTS path_observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src_device_id TEXT NOT NULL,
  dst_device_id TEXT NOT NULL,
  class TEXT NOT NULL,
  rtt_ms REAL NOT NULL DEFAULT 0,
  loss REAL NOT NULL DEFAULT 0,
  relay_name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_path_obs_pair_time ON path_observations(src_device_id, dst_device_id, created_at);

CREATE TABLE IF NOT EXISTS storage_profiles(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  endpoint TEXT NOT NULL,
  region TEXT NOT NULL,
  bucket TEXT NOT NULL,
  access_key TEXT NOT NULL,
  secret_enc TEXT NOT NULL, -- encrypted with master key
  path_prefix TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS api_tokens(
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  device_id TEXT NOT NULL DEFAULT '',
  job_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);

CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
