// Package config loads and validates MeshBridge server configuration.
package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Env               string // production/staging/dev
	ListenAddr        string // e.g. 127.0.0.1:8081 (never public by default)
	DataDir           string // /var/lib/meshbridge
	PolicyPath        string // /etc/headscale/policy.hujson
	PolicySnapshotDir string
	HeadscaleURL      string // http://127.0.0.1:8080
	HeadscaleAPIKey   string // from server.env, never logged
	MasterKeyPath     string // /etc/meshbridge/master.key
	DerpLimitBytes    int64  // default 100MiB
	DefaultChunkBytes int64  // default 64MiB
	ProbeIntervalSec  int
	ControlWarnBytes  []int64
}

func Default() Config {
	return Config{
		Env:               "production",
		ListenAddr:        "127.0.0.1:8081",
		DataDir:           "/var/lib/meshbridge",
		PolicyPath:        "/etc/headscale/policy.hujson",
		PolicySnapshotDir: "/var/lib/meshbridge/policy-snapshots",
		HeadscaleURL:      "http://127.0.0.1:8080",
		MasterKeyPath:     "/etc/meshbridge/master.key",
		DerpLimitBytes:    100 << 20,
		DefaultChunkBytes: 64 << 20,
		ProbeIntervalSec:  15,
		ControlWarnBytes:  []int64{30 << 30, 40 << 30, 45 << 30},
	}
}

func FromEnv() Config {
	c := Default()
	if v := os.Getenv("MESH_ENV"); v != "" {
		c.Env = v
	}
	if v := os.Getenv("MESH_LISTEN"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("MESH_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("MESH_HEADSCALE_URL"); v != "" {
		c.HeadscaleURL = v
	}
	c.HeadscaleAPIKey = os.Getenv("MESH_HEADSCALE_API_KEY")
	if v := os.Getenv("MESH_DERP_LIMIT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.DerpLimitBytes = n
		}
	}
	return c
}

// Validate enforces CONTROL != DATA invariants.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen addr empty")
	}
	// Refuse to bind transfer/API to 0.0.0.0 in production unless explicitly overridden.
	if c.Env == "production" && (c.ListenAddr == "0.0.0.0:8081" || c.ListenAddr == ":8081") {
		return fmt.Errorf("refusing to listen on all interfaces in production (CONTROL != DATA); bind 127.0.0.1 behind Caddy")
	}
	if c.DerpLimitBytes <= 0 || c.DerpLimitBytes > 1<<30 {
		return fmt.Errorf("derp limit out of range")
	}
	if c.DefaultChunkBytes < 8<<20 || c.DefaultChunkBytes > 256<<20 {
		return fmt.Errorf("chunk size must be 8MiB..256MiB")
	}
	if c.HeadscaleURL == "" {
		return fmt.Errorf("headscale url empty")
	}
	return nil
}
