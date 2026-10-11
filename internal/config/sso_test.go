package config

import (
	"encoding/json"
	"testing"
)

func testSSOConfig() Config {
	c := Default()
	c.SSOEnabled = true
	c.SSOIssuer = "https://mesh.example"
	c.BaseURL = c.SSOIssuer
	c.SSOClients = map[string]string{}
	for _, app := range []string{"folio", "codebench", "echo", "inkwell", "parley", "hearthvale"} {
		c.SSOClients[app] = "https://" + app + ".example/sso/callback"
	}
	return c
}

func TestSSOConfigurationDefaultsAndSixExactCallbacks(t *testing.T) {
	if Default().SSOEnabled {
		t.Fatal("SSO enabled by default")
	}
	c := testSSOConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.SSOIssuer = "http://mesh.example"; c.BaseURL = c.SSOIssuer },
		func(c *Config) { c.BaseURL = "https://wrong.example" }, func(c *Config) { delete(c.SSOClients, "echo") },
		func(c *Config) { c.SSOClients["toolshed"] = "https://toolshed.example/sso/callback" },
		func(c *Config) { c.SSOClients["echo"] = "https://echo.example/foo/sso/callback" },
		func(c *Config) { c.SSOClients["echo"] = "https://echo.example/sso/callback?debug=1" },
		func(c *Config) { c.SSOClients["echo"] = c.SSOClients["folio"] }, func(c *Config) { c.SSODev = true },
	} {
		c = testSSOConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatal("invalid SSO configuration accepted", c.SSOIssuer, c.BaseURL, c.SSOClients)
		}
	}
	c = testSSOConfig()
	c.Env = "dev"
	c.SSODev = true
	c.SSOIssuer = "http://localhost:9000"
	c.BaseURL = c.SSOIssuer
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.SSOIssuer = "http://public.example"
	c.BaseURL = c.SSOIssuer
	if err := c.Validate(); err == nil {
		t.Fatal("public HTTP dev exception")
	}
}

func TestSSOEnvironmentExplicitOptIn(t *testing.T) {
	c := testSSOConfig()
	encoded, _ := json.Marshal(c.SSOClients)
	t.Setenv("MESH_BASE_URL", c.BaseURL)
	t.Setenv("MESH_SSO_ISSUER", c.SSOIssuer)
	t.Setenv("MESH_SSO_CLIENTS", string(encoded))
	t.Setenv("MESH_SSO_DEV", "false")
	t.Setenv("MESH_SSO_ENABLED", "false")
	if c := FromEnv(); c.SSOEnabled || c.Validate() != nil {
		t.Fatal("disabled configuration failed")
	}
	t.Setenv("MESH_SSO_ENABLED", "true")
	if c := FromEnv(); !c.SSOEnabled || c.Validate() != nil {
		t.Fatal("SSO optin failed", c.Validate())
	}
	t.Setenv("MESH_SSO_ENABLED", "yes")
	if c := FromEnv(); c.Validate() == nil {
		t.Fatal("ambiguous optin accepted")
	}
	t.Setenv("MESH_SSO_ENABLED", "true")
	t.Setenv("MESH_SSO_CLIENTS", "{}")
	if c := FromEnv(); c.Validate() == nil {
		t.Fatal("empty callback allowlist accepted")
	}
}
