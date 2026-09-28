// fix_test.go — regressions for the 2026-09-26 security-review findings:
// same-origin isolation (CSP sandbox), slow-upload header timeout, gate page
// self-containment, and tunnel-global settings.
package tunnel_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/tunnel"
)

// slowBody drips bytes at a fixed interval, simulating a visitor on a slow
// uplink: the request write must block for the full drip duration without
// any header deadline firing mid-upload (the original 60s-upload 502).
type slowBody struct {
	total, sent int
	chunk       int
	interval    time.Duration
}

func (b *slowBody) Read(p []byte) (int, error) {
	if b.sent >= b.total {
		return 0, io.EOF
	}
	time.Sleep(b.interval)
	n := b.chunk
	if n > len(p) {
		n = len(p)
	}
	if b.sent+n > b.total {
		n = b.total - b.sent
	}
	for i := 0; i < n; i++ {
		p[i] = 0x61
	}
	b.sent += n
	return n, nil
}

// TestSlowUploadNetworkPace: visitor drip-feeds the body slower than the
// configured header cap — must still succeed (deadline never armed while
// writing).
func TestSlowUploadNetworkPace(t *testing.T) {
	s := newStack(t, func(c *tunnel.GatewayConfig) {
		c.HeaderTimeout = 400 * time.Millisecond
	})
	tu, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "target_port": s.appPort, "key_required": false,
	}, adminToken)
	s.reconcile(t, tu["id"].(string))
	slug := tu["slug"].(string)

	// 10 chunks × 80ms = 800ms > 400ms cap; under the old code the
	// pre-armed deadline fired mid-write → 502.
	body := &slowBody{total: 10 * 1024, chunk: 1024, interval: 80 * time.Millisecond}
	pr, err := http.Post(s.gwSrv.URL+"/t/"+slug+"/echo", "application/octet-stream", body)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Body.Close()
	b, _ := io.ReadAll(pr.Body)
	if pr.StatusCode != 200 || !strings.Contains(string(b), `"body":10240`) {
		t.Fatalf("slow-network upload = %d %.120s, want 200 with full body", pr.StatusCode, b)
	}
}

// TestSlowUpstreamConsumption: the visitor is fast but the upstream reads
// the body slowly — slower than a "responsiveness" timeout would allow.
// With the default (generous, absolute) cap this must succeed; it is the
// shape of the reported 65-second-upload 502.
func TestSlowUpstreamConsumption(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sip", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 8*1024)
		got := 0
		for got < 64*1024 {
			n, err := r.Body.Read(buf)
			got += n
			if err != nil {
				break
			}
			if got >= 64*1024 {
				time.Sleep(800 * time.Millisecond) // app is "slow" while the body sits in the tunnel
				_, _ = io.Copy(io.Discard, r.Body)
				break
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	app := httptest.NewServer(mux)
	defer app.Close()
	u, _ := url.Parse(app.URL)
	port, _ := strconv.Atoi(u.Port())

	s := newStack(t) // default generous cap
	tu, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "target_port": port, "key_required": false,
	}, adminToken)
	s.reconcile(t, tu["id"].(string))

	pr, err := http.Post(s.gwSrv.URL+"/t/"+tu["slug"].(string)+"/sip",
		"application/octet-stream", bytes.NewReader(bytes.Repeat([]byte{0x61}, 128*1024)))
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Body.Close()
	b, _ := io.ReadAll(pr.Body)
	if pr.StatusCode != 200 {
		t.Fatalf("slow-consumer upload = %d %.120s, want 200", pr.StatusCode, b)
	}
}

// TestPathModeSandboxIsolation pins the same-origin fix: path mode (which
// shares the browser origin with the console) must serve responses with a
// sandbox CSP; subdomain mode (own origin) and sandbox=false must not.
func TestPathModeSandboxIsolation(t *testing.T) {
	s := newStack(t)
	t1, _ := s.createTunnel(t, map[string]any{"device_id": "dev1", "target_port": s.appPort, "key_required": false}, adminToken)
	t2, _ := s.createTunnel(t, map[string]any{"device_id": "dev1", "target_port": s.appPort, "key_required": false, "sandbox": false}, adminToken)
	s.reconcile(t, t1["id"].(string), t2["id"].(string))
	slug1 := t1["slug"].(string)
	slug2 := t2["slug"].(string)

	// Path mode + sandbox default ON → header present.
	resp, _ := s.get(t, "/t/"+slug1+"/echo", "", "")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Fatalf("path mode CSP = %q, want sandbox directive (console token is same-origin readable otherwise)", csp)
	}
	// Sandbox OFF → header absent (owner explicitly trusted the content).
	resp, _ = s.get(t, "/t/"+slug2+"/echo", "", "")
	if csp := resp.Header.Get("Content-Security-Policy"); strings.Contains(csp, "sandbox") {
		t.Fatalf("sandbox=false tunnel still sandboxed: %q", csp)
	}
	// Subdomain mode (own origin) → no sandbox needed.
	subHost := tunnel.PublicHost(tunnel.SubdomainLabel(slug1), baseDomain)
	resp, _ = s.get(t, "/echo", subHost, "")
	if csp := resp.Header.Get("Content-Security-Policy"); strings.Contains(csp, "sandbox") {
		t.Fatalf("subdomain mode must not sandbox: %q", csp)
	}
	// Toggling sandbox via PATCH takes effect (proxy bundle rebuilt).
	if resp, _ := apiPatch(t, s, "/api/v1/tunnels/"+t2["id"].(string), map[string]any{"sandbox": true}); resp.StatusCode != 200 {
		t.Fatalf("patch sandbox = %d", resp.StatusCode)
	}
	resp, _ = s.get(t, "/t/"+slug2+"/echo", "", "")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Fatalf("sandbox PATCH did not apply: %q", csp)
	}
}

// TestGatePageSelfContained pins the gate-CSS fix: the page must render
// behind any reverse-proxy split, i.e. inline nonce styling with no
// dependency on paths the proxy might route elsewhere.
func TestGatePageSelfContained(t *testing.T) {
	s := newStack(t)
	tu, _ := s.createTunnel(t, map[string]any{"device_id": "dev1", "target_port": s.appPort}, adminToken)
	s.reconcile(t, tu["id"].(string))
	resp, body := s.get(t, "/t/"+tu["slug"].(string)+"/echo", "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "mb_tunnel_key") {
		t.Fatalf("gate page missing: %d", resp.StatusCode)
	}
	if strings.Contains(body, "href=") {
		t.Fatalf("gate page still references an external asset: %.200s", body)
	}
	if !strings.Contains(body, `<style nonce=`) {
		t.Fatal("gate page must inline its style with a nonce")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "'nonce-") {
		t.Fatalf("gate CSP must whitelist the style nonce: %q", csp)
	}
}

// TestTunnelSettingsRoundTrip covers the admin-only global settings API.
func TestTunnelSettingsRoundTrip(t *testing.T) {
	s := newStack(t)
	// Non-admin is rejected.
	req, _ := http.NewRequest("GET", s.api.URL+"/api/v1/tunnels/settings", nil)
	req.Header.Set("Authorization", "Bearer stranger-token")
	if resp, err := s.visitor.Do(req); err != nil || resp.StatusCode != 403 {
		t.Fatalf("stranger GET settings = %v %d, want 403", err, statusOf(resp))
	}
	// Admin reads defaults.
	req, _ = http.NewRequest("GET", s.api.URL+"/api/v1/tunnels/settings", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Enabled           bool  `json:"enabled"`
		GlobalMonthlyByte int64 `json:"global_monthly_bytes"`
		RatePerMin        int   `json:"rate_per_min"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	resp.Body.Close()
	if !cfg.Enabled || cfg.GlobalMonthlyByte <= 0 || cfg.RatePerMin <= 0 {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	// Admin updates; bad values rejected; values persist.
	put := func(body string, token string) *http.Response {
		req, _ := http.NewRequest("PUT", s.api.URL+"/api/v1/tunnels/settings", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.visitor.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	if resp := put(`{"rate_per_min":1}`, adminToken); resp.StatusCode != 400 {
		t.Fatalf("rate=1 accepted: %d", resp.StatusCode)
	}
	if resp := put(`{"enabled":false,"rate_per_min":600}`, adminToken); resp.StatusCode != 200 {
		t.Fatalf("valid put = %d", resp.StatusCode)
	}
	var enabled string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key='tunnels_enabled'`).Scan(&enabled)
	if enabled != "0" {
		t.Fatalf("enabled setting = %q, want 0", enabled)
	}
	var rate string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key='tunnels_rate_per_min'`).Scan(&rate)
	if rate != "600" {
		t.Fatalf("rate setting = %q, want 600", rate)
	}
}
