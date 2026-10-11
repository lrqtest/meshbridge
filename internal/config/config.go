// Package config loads and validates MeshBridge server configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mineai/kit/httpx"
	"github.com/mineai/kit/sso"
)

type Config struct {
	// BaseURL is the MineAI platform origin. It is also the SSO issuer when
	// platform sign-in is enabled, so it must not move to a project origin.
	BaseURL string
	// ProjectURL is the separately addressed MeshBridge project origin. Empty
	// means a single-surface (standalone) installation. ProjectSSO makes the
	// project a client of the platform sign-in served by the same process.
	ProjectURL        string
	ProjectSSO        bool
	GoogleClientID    string
	SSOEnabled        bool
	SSOIssuer         string
	SSOClients        map[string]string
	SSODev            bool
	ssoConfigError    error
	Env               string // production/staging/dev
	ListenAddr        string // e.g. 127.0.0.1:8081 (never public by default)
	GatewayListenAddr string // 127.0.0.1:8082 (tunnel visitor gateway, loopback)
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
	TunnelBaseDomain  string // enables t-<slug>.<domain> mode (default: host of MESH_BASE_URL)
}

func Default() Config {
	return Config{
		ProjectSSO:        true,
		Env:               "production",
		ListenAddr:        "127.0.0.1:8081",
		GatewayListenAddr: "127.0.0.1:8082",
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
	c.BaseURL = os.Getenv("MESH_BASE_URL")
	c.ProjectURL = strings.TrimSpace(os.Getenv("MESH_PROJECT_URL"))
	c.GoogleClientID = strings.TrimSpace(os.Getenv("MESH_GOOGLE_CLIENT_ID"))
	c.SSOIssuer = os.Getenv("MESH_SSO_ISSUER")
	for name, dest := range map[string]*bool{"MESH_SSO_ENABLED": &c.SSOEnabled, "MESH_SSO_DEV": &c.SSODev, "MESH_PROJECT_SSO": &c.ProjectSSO} {
		if raw := os.Getenv(name); raw != "" {
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				c.ssoConfigError = fmt.Errorf("%s must be an explicit boolean", name)
			} else {
				*dest = parsed
			}
		}
	}
	if c.SSOEnabled {
		if err := json.Unmarshal([]byte(os.Getenv("MESH_SSO_CLIENTS")), &c.SSOClients); err != nil {
			c.ssoConfigError = fmt.Errorf("MESH_SSO_CLIENTS must be a JSON client-to-callback object")
		}
	}
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
	if v := os.Getenv("MESH_MASTER_KEY_PATH"); v != "" {
		c.MasterKeyPath = v
	}
	if v := os.Getenv("MESH_GATEWAY_LISTEN"); v != "" {
		c.GatewayListenAddr = v
	}
	if v := os.Getenv("MESH_TUNNEL_BASE_DOMAIN"); v != "" {
		c.TunnelBaseDomain = v
	}
	if v := os.Getenv("MESH_DERP_LIMIT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			c.DerpLimitBytes = n
		}
	}
	return c
}

// ProjectSSOClientID is the platform SSO client id of the MeshBridge project.
const ProjectSSOClientID = "meshbridge"

// ProjectSSOEnabled reports whether the MeshBridge project signs in through
// the platform: SSO is on, a project origin exists and it was not opted out.
func (c Config) ProjectSSOEnabled() bool {
	return c.SSOEnabled && c.ProjectSSO && c.ProjectURL != ""
}

// ProjectCallback is the exact callback URI registered for the project client.
func (c Config) ProjectCallback() string { return c.ProjectURL + "/sso/callback" }

// Validate enforces CONTROL != DATA invariants.
func (c Config) Validate() error {
	if c.ssoConfigError != nil {
		return c.ssoConfigError
	}
	if c.ProjectURL != "" {
		dev := c.Env == "dev"
		if err := sso.ValidateOrigin(c.ProjectURL, dev); err != nil {
			return fmt.Errorf("MESH_PROJECT_URL: %w", err)
		}
		if err := sso.ValidateOrigin(c.BaseURL, dev); err != nil {
			return fmt.Errorf("MESH_PROJECT_URL needs MESH_BASE_URL as the platform origin: %w", err)
		}
		if HostKey(c.BaseURL) == HostKey(c.ProjectURL) {
			return fmt.Errorf("MESH_PROJECT_URL must be a different origin than MESH_BASE_URL")
		}
		if c.ProjectSSOEnabled() {
			if err := sso.ValidateCallback(c.ProjectCallback(), c.SSODev); err != nil {
				return fmt.Errorf("project SSO callback: %w", err)
			}
		}
	}
	if c.SSOEnabled {
		if c.SSODev && c.Env != "dev" {
			return fmt.Errorf("SSO development exceptions require MESH_ENV=dev")
		}
		if err := sso.ValidateOrigin(c.SSOIssuer, c.SSODev); err != nil {
			return fmt.Errorf("SSO issuer: %w", err)
		}
		if c.BaseURL != c.SSOIssuer {
			return fmt.Errorf("MESH_SSO_ISSUER must equal MESH_BASE_URL")
		}
		apps := []string{"folio", "codebench", "echo", "inkwell", "parley", "hearthvale"}
		if len(c.SSOClients) != len(apps) {
			return fmt.Errorf("SSO requires callbacks for exactly six account applications")
		}
		seen := map[string]bool{}
		for _, id := range apps {
			callback := c.SSOClients[id]
			if err := sso.ValidateCallback(callback, c.SSODev); err != nil {
				return fmt.Errorf("SSO %s callback: %w", id, err)
			}
			if !strings.HasSuffix(callback, "/sso/callback") || sso.ValidateOrigin(strings.TrimSuffix(callback, "/sso/callback"), c.SSODev) != nil || seen[callback] {
				return fmt.Errorf("SSO callbacks must be distinct application /sso/callback URIs")
			}
			seen[callback] = true
		}
	}
	if c.ListenAddr == "" {
		return fmt.Errorf("listen addr empty")
	}
	if err := validateListener(c.ListenAddr, c.Env == "production"); err != nil {
		return fmt.Errorf("API listen: %w", err)
	}
	if c.GatewayListenAddr != "" {
		if err := validateListener(c.GatewayListenAddr, c.Env == "production"); err != nil {
			return fmt.Errorf("gateway listen: %w", err)
		}
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

func validateListener(addr string, production bool) error {
	if err := httpx.ValidateListen(addr, production); err != nil {
		return err
	}
	// Shared validation also serves ephemeral test listeners. Mesh deploys
	// fixed API/gateway ports, so its configuration continues to reject zero.
	_, port, _ := net.SplitHostPort(addr)
	n, _ := strconv.ParseUint(port, 10, 16)
	if n == 0 {
		return fmt.Errorf("port must be 1..65535")
	}
	return nil
}

// HostKey normalizes an origin or a Host header to "host[:port]" for
// comparison: lower case, no trailing dot, default ports removed.
func HostKey(value string) string {
	host := strings.TrimSpace(value)
	scheme := ""
	if i := strings.Index(host, "://"); i >= 0 {
		scheme, host = strings.ToLower(host[:i]), host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		name, port = strings.Trim(host, "[]"), ""
	}
	name = strings.TrimSuffix(name, ".")
	if port == "80" && scheme != "https" || port == "443" && scheme != "http" {
		port = ""
	}
	if strings.Contains(name, ":") {
		name = "[" + name + "]"
	}
	if port != "" {
		return name + ":" + port
	}
	return name
}
