package config

import (
	"encoding/json"
	"testing"
)

func testProjectConfig() Config {
	c := testSSOConfig()
	c.SSOIssuer, c.BaseURL = "https://platform.example", "https://platform.example"
	c.ProjectURL = "https://mesh.platform.example"
	return c
}

func TestProjectOriginIsOptionalAndSeparate(t *testing.T) {
	d := Default()
	if d.ProjectURL != "" || !d.ProjectSSO || d.ProjectSSOEnabled() {
		t.Fatalf("single-surface default must stay inert: %+v", d)
	}
	c := testProjectConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.ProjectSSOEnabled() || c.ProjectCallback() != "https://mesh.platform.example/sso/callback" {
		t.Fatalf("project SSO wiring: %v %q", c.ProjectSSOEnabled(), c.ProjectCallback())
	}
	c.ProjectSSO = false
	if c.ProjectSSOEnabled() || c.Validate() != nil {
		t.Fatal("explicit project SSO opt-out must validate and disable the client")
	}
}

func TestProjectOriginRejectsAmbiguousOrUnsafeValues(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"trailing slash":   func(c *Config) { c.ProjectURL += "/" },
		"path":             func(c *Config) { c.ProjectURL += "/console" },
		"plain http":       func(c *Config) { c.ProjectURL = "http://mesh.platform.example" },
		"credentials":      func(c *Config) { c.ProjectURL = "https://user:pw@mesh.platform.example" },
		"query":            func(c *Config) { c.ProjectURL += "?x=1" },
		"same origin":      func(c *Config) { c.ProjectURL = c.BaseURL },
		"same host, case":  func(c *Config) { c.ProjectURL = "https://PLATFORM.example" },
		"default port":     func(c *Config) { c.ProjectURL = "https://platform.example:443" },
		"missing platform": func(c *Config) { c.BaseURL, c.SSOEnabled = "", false },
		"junk":             func(c *Config) { c.ProjectURL = "mesh.platform.example" },
	} {
		c := testProjectConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted %q (base %q)", name, c.ProjectURL, c.BaseURL)
		}
	}
	// Development may use two loopback names as two distinct origins.
	c := testProjectConfig()
	c.Env, c.SSODev = "dev", true
	c.SSOIssuer, c.BaseURL, c.ProjectURL = "http://localhost:28081", "http://localhost:28081", "http://127.0.0.1:28081"
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback development origins rejected: %v", err)
	}
	c.Env = "production"
	if err := c.Validate(); err == nil {
		t.Fatal("loopback HTTP origins accepted outside development")
	}
}

func TestProjectEnvironment(t *testing.T) {
	c := testProjectConfig()
	encoded, _ := json.Marshal(c.SSOClients)
	t.Setenv("MESH_BASE_URL", c.BaseURL)
	t.Setenv("MESH_SSO_ISSUER", c.SSOIssuer)
	t.Setenv("MESH_SSO_CLIENTS", string(encoded))
	t.Setenv("MESH_SSO_ENABLED", "true")
	t.Setenv("MESH_PROJECT_URL", " "+c.ProjectURL+" ")
	got := FromEnv()
	if got.ProjectURL != c.ProjectURL || !got.ProjectSSOEnabled() || got.Validate() != nil {
		t.Fatalf("env wiring: %+v %v", got, got.Validate())
	}
	t.Setenv("MESH_PROJECT_SSO", "false")
	if got = FromEnv(); got.ProjectSSOEnabled() || got.Validate() != nil {
		t.Fatal("MESH_PROJECT_SSO=false must keep the surface split but drop the client")
	}
	t.Setenv("MESH_PROJECT_SSO", "maybe")
	if FromEnv().Validate() == nil {
		t.Fatal("ambiguous boolean accepted")
	}
}

func TestHostKeyNormalizesOriginsAndHostHeaders(t *testing.T) {
	for in, want := range map[string]string{
		"https://MineAI.top":                  "mineai.top",
		"https://mineai.top/":                 "mineai.top",
		"https://mineai.top:443":              "mineai.top",
		"mineai.top:443":                      "mineai.top",
		"mineai.top.":                         "mineai.top",
		"http://localhost:28081":              "localhost:28081",
		"LOCALHOST:28081":                     "localhost:28081",
		"127.0.0.1:28081":                     "127.0.0.1:28081",
		"http://example.test:80":              "example.test",
		"[::1]:8081":                          "[::1]:8081",
		"https://meshbridge.mineai.top/#/app": "meshbridge.mineai.top",
		"":                                    "",
	} {
		if got := HostKey(in); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", in, got, want)
		}
	}
	if HostKey("https://mineai.top") == HostKey("https://meshbridge.mineai.top") {
		t.Fatal("platform and project hosts must differ")
	}
}
