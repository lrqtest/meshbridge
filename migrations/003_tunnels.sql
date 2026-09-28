-- MeshBridge schema v3: public web tunnels.
-- Exposes an intranet HTTP service to the internet through an agent-initiated
-- outbound reverse tunnel; visitors are gated by a per-tunnel access key.

CREATE TABLE IF NOT EXISTS tunnels(
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT '',
  slug TEXT NOT NULL UNIQUE,            -- 32 hex chars; capability URL component
  target_scheme TEXT NOT NULL DEFAULT 'http',  -- http|https (agent-side TLS to target)
  target_host TEXT NOT NULL DEFAULT '127.0.0.1',
  target_port INTEGER NOT NULL,
  key_required INTEGER NOT NULL DEFAULT 1,
  access_key_hash TEXT NOT NULL DEFAULT '',    -- sha256 hex; raw key shown once at create/rotate
  status TEXT NOT NULL DEFAULT 'active',       -- active|disabled|quota_exceeded
  strip_prefix INTEGER NOT NULL DEFAULT 1,     -- path mode: serve app at /t/<slug>/ root
  sandbox INTEGER NOT NULL DEFAULT 1,          -- path mode: CSP sandbox (opaque origin isolation)
  monthly_quota_bytes INTEGER NOT NULL DEFAULT 5368709120,   -- 5 GiB
  max_request_bytes INTEGER NOT NULL DEFAULT 104857600,      -- 100 MiB request body cap
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);

CREATE TABLE IF NOT EXISTS tunnel_usage(
  tunnel_id TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
  month TEXT NOT NULL,                  -- 'YYYY-MM' UTC
  bytes_in INTEGER NOT NULL DEFAULT 0,  -- visitor request bodies
  bytes_out INTEGER NOT NULL DEFAULT 0, -- proxied response bodies (incl. hijacked)
  warned INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(tunnel_id, month)
);

INSERT OR IGNORE INTO settings(key, value) VALUES
  ('tunnels_enabled', '1'),
  ('tunnels_global_monthly_bytes', '21474836480');  -- 20 GiB across all tunnels
