// tunnel_test.go — end-to-end: in-memory DB → api server (WS endpoint) →
// gateway visitor listener → real agent Client → local upstream app.
package tunnel_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/api"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/db"
	"github.com/meshbridge/meshbridge/internal/tunnel"
)

const (
	adminToken  = "test-admin-token"
	deviceToken = "test-device-token"
	baseDomain  = "t.example.test"
)

type stack struct {
	db      *sql.DB
	api     *httptest.Server
	gw      *tunnel.Gateway
	gwSrv   *httptest.Server
	app     *httptest.Server
	appHost string
	appPort int
	client  *tunnel.Client
	visitor *http.Client
	t       *testing.T
}

func newStack(t *testing.T, cfgMods ...func(*tunnel.GatewayConfig)) *stack {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.sqlite"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.RunMigrations(d, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatal(err)
	}
	// users: admin u1, stranger u3; device dev1 owned by u1.
	mustExec(t, d, `INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u1','admin','x','admin',1)`)
	mustExec(t, d, `INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u3','mallory','x','user',1)`)
	mustExec(t, d, `INSERT INTO api_tokens(token_hash,user_id,name,created_at) VALUES(?, 'u1','t',1)`, auth.HashToken(adminToken))
	mustExec(t, d, `INSERT INTO api_tokens(token_hash,user_id,name,created_at) VALUES(?, 'u3','t',1)`, auth.HashToken("stranger-token"))
	mustExec(t, d, `INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES('dev1','box-a','u1',1)`)
	mustExec(t, d, `INSERT INTO device_tokens(token_hash,device_id,created_at) VALUES(?, 'dev1',1)`, auth.HashToken(deviceToken))

	// local "intranet web app"
	mux := http.NewServeMux()
	// catch-all echoes the path it was called with (proves prefix handling)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.RequestURI()})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, io.LimitReader(r.Body, 64<<20))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path": r.URL.RequestURI(), "host": r.Host,
			"xff": r.Header.Get("X-Forwarded-For"), "method": r.Method, "body": n,
		})
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login?next=1")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{0x61}, 1<<20))
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("app: not hijackable")
			return
		}
		conn, rw, _ := hj.Hijack()
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: rawtest\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		buf := make([]byte, 4)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				_, _ = rw.Write(buf[:n]) // echo server
				rw.Flush()
			}
			if err != nil {
				return
			}
		}
	})
	app := httptest.NewServer(mux)
	t.Cleanup(app.Close)
	appURL, _ := url.Parse(app.URL)
	port := 0
	fmt.Sscanf(appURL.Port(), "%d", &port)

	// control plane + gateway
	srv := api.New(d)
	gwCfg := tunnel.GatewayConfig{
		DB: d, Secret: []byte("unit-test-gate-secret-32-bytes-ok!"), BaseDomain: baseDomain,
	}
	for _, mod := range cfgMods {
		mod(&gwCfg)
	}
	gw := tunnel.NewGateway(gwCfg)
	srv.Gateway = gw
	apiSrv := httptest.NewServer(srv.Mux)
	t.Cleanup(apiSrv.Close)
	gwSrv := httptest.NewServer(gw.Handler())
	t.Cleanup(gwSrv.Close)

	jar, _ := cookiejar.New(nil)
	cl, err := tunnel.NewClient(apiSrv.URL, deviceToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	return &stack{db: d, api: apiSrv, gw: gw, gwSrv: gwSrv, app: app,
		appHost: appURL.Hostname(), appPort: port, client: cl,
		visitor: &http.Client{Jar: jar, Timeout: 20 * time.Second}, t: t}
}

func mustExec(t *testing.T, d *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := d.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// createTunnel goes through the real API. Returns tunnel view + access key.
func (s *stack) createTunnel(t *testing.T, body map[string]any, token string) (map[string]any, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", s.api.URL+"/api/v1/tunnels", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create tunnel: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Tunnel    map[string]any `json:"tunnel"`
		AccessKey string         `json:"access_key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Tunnel, out.AccessKey
}

// reconcile asks the heartbeat endpoint for the device's tunnels and applies
// them to the agent, then waits until every wanted tunnel is online.
func (s *stack) reconcile(t *testing.T, wantOnline ...string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"device_id": "dev1"})
	req, _ := http.NewRequest("POST", s.api.URL+"/api/v1/agents/heartbeat", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var hb struct {
		Tunnels []tunnel.AgentConfig `json:"tunnels"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&hb)
	s.client.Reconcile(context.Background(), hb.Tunnels)
	deadline := time.Now().Add(8 * time.Second)
	for _, id := range wantOnline {
		for time.Now().Before(deadline) {
			if s.gw.Online(id) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !s.gw.Online(id) {
			t.Fatalf("tunnel %s never came online", id)
		}
	}
}

func (s *stack) get(t *testing.T, path, host, bearer string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", s.gwSrv.URL+path, nil)
	if host != "" {
		req.Host = host
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func TestTunnelE2E(t *testing.T) {
	s := newStack(t)

	t1, key1 := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "name": "gated app", "target_port": s.appPort,
	}, adminToken)
	t2, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "name": "open app", "target_port": s.appPort, "key_required": false,
	}, adminToken)
	t3, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "name": "full path", "target_port": s.appPort, "key_required": false, "strip_prefix": false,
	}, adminToken)
	slug1 := t1["slug"].(string)
	slug2 := t2["slug"].(string)
	slug3 := t3["slug"].(string)

	s.reconcile(t, t1["id"].(string), t2["id"].(string), t3["id"].(string))

	// ---- path mode: unknown slug → 404 ----
	if resp, _ := s.get(t, "/t/"+strings.Repeat("f", 32)+"/echo", "", ""); resp.StatusCode != 404 {
		t.Fatalf("unknown slug = %d, want 404", resp.StatusCode)
	}

	// ---- prefix canonicalization (client must NOT follow this one) ----
	{
		noRedirect := *s.visitor
		noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
		req, _ := http.NewRequest("GET", s.gwSrv.URL+"/t/"+slug1, nil)
		if resp, err := noRedirect.Do(req); err != nil || resp.StatusCode != 308 {
			t.Fatalf("bare prefix = %v %d, want 308", err, statusOf(resp))
		}
	}

	// ---- gate: unauthenticated visitor sees the key page ----
	resp, body := s.get(t, "/t/"+slug1+"/echo?x=1", "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "mb_tunnel_key") {
		t.Fatalf("gate page missing: %d %.200s", resp.StatusCode, body)
	}

	// ---- gate: wrong key → 401 with page ----
	form := url.Values{"mb_tunnel_key": {"wrong-key"}}
	req, _ := http.NewRequest("POST", s.gwSrv.URL+"/t/"+slug1+"/echo?x=1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := io.ReadAll(pr.Body)
	pr.Body.Close()
	_ = pb
	if pr.StatusCode != 401 {
		t.Fatalf("wrong key = %d, want 401", pr.StatusCode)
	}

	// ---- gate: correct key → 303 + cookie, then proxied ----
	form.Set("mb_tunnel_key", key1)
	req, _ = http.NewRequest("POST", s.gwSrv.URL+"/t/"+slug1+"/echo?x=1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr, err = s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, pr.Body)
	pr.Body.Close()
	if pr.StatusCode != 200 { // followed the 303 with the cookie
		t.Fatalf("key submit = %d, want 200 (followed redirect)", pr.StatusCode)
	}
	resp, body = s.get(t, "/t/"+slug1+"/echo?x=1", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("cookie'd GET = %d", resp.StatusCode)
	}
	var echo struct {
		Path, Host, XFF, Method string
	}
	_ = json.Unmarshal([]byte(body), &echo)
	if echo.Path != "/echo?x=1" {
		t.Fatalf("app saw path %q, want /echo?x=1 (prefix stripped)", echo.Path)
	}
	if echo.XFF != "127.0.0.1" {
		t.Fatalf("app saw XFF %q, want visitor IP", echo.XFF)
	}
	if echo.Host != fmt.Sprintf("127.0.0.1:%d", s.appPort) {
		t.Fatalf("app saw Host %q", echo.Host)
	}

	// ---- Bearer key (no cookie: a cookieless client) ----
	bare := &http.Client{Timeout: 10 * time.Second}
	req2, _ := http.NewRequest("GET", s.gwSrv.URL+"/t/"+slug1+"/echo", nil)
	req2.Header.Set("Authorization", "Bearer totally-wrong")
	if resp, err := bare.Do(req2); err != nil || resp.StatusCode != 401 {
		t.Fatalf("bad bearer = %v %d, want 401", err, statusOf(resp))
	}
	req3, _ := http.NewRequest("GET", s.gwSrv.URL+"/t/"+slug1+"/echo", nil)
	req3.Header.Set("Authorization", "Bearer "+key1)
	resp4, err := bare.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	body4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	if resp4.StatusCode != 200 || !strings.Contains(string(body4), `"path":"/echo"`) {
		t.Fatalf("bearer = %d %.200s", resp4.StatusCode, body4)
	}

	// ---- key-less tunnel proxies directly ----
	resp, body = s.get(t, "/t/"+slug2+"/echo", "", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"path":"/echo"`) {
		t.Fatalf("keyless = %d %.200s", resp.StatusCode, body)
	}

	// ---- redirect Location gets the tunnel prefix (no follow) ----
	{
		noFollow := *s.visitor
		noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
		req, _ := http.NewRequest("GET", s.gwSrv.URL+"/t/"+slug2+"/redir", nil)
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "/t/"+slug2+"/login?next=1" {
			t.Fatalf("Location = %q, want tunnel-prefixed", loc)
		}
	}

	// ---- subdomain mode: no prefix, correct host routing ----
	subHost := tunnel.PublicHost(tunnel.SubdomainLabel(slug2), baseDomain)
	resp, body = s.get(t, "/echo", subHost, "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"path":"/echo"`) {
		t.Fatalf("subdomain = %d %.200s", resp.StatusCode, body)
	}

	// ---- subdomain gate is bound to the slug ----
	subHost1 := tunnel.PublicHost(tunnel.SubdomainLabel(slug1), baseDomain)
	resp, body = s.get(t, "/echo", subHost1, "")
	if resp.StatusCode != 200 || !strings.Contains(body, "mb_tunnel_key") {
		t.Fatalf("subdomain gate missing: %d %.200s", resp.StatusCode, body)
	}
	resp, _ = s.get(t, "/echo", subHost1, key1)
	if resp.StatusCode != 200 {
		t.Fatalf("subdomain bearer = %d, want 200", resp.StatusCode)
	}

	// ---- no-strip tunnel sees the full public path ----
	resp, body = s.get(t, "/t/"+slug3+"/echo", "", "")
	if !strings.Contains(body, `"/t/`+slug3+`/echo"`) {
		t.Fatalf("no-strip app saw %q", body)
	}

	// ---- upload: request body reaches the app and is accounted ----
	up := bytes.Repeat([]byte{0x62}, 1<<20)
	req, _ = http.NewRequest("POST", s.gwSrv.URL+"/t/"+slug2+"/echo", bytes.NewReader(up))
	uresp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	ub, _ := io.ReadAll(uresp.Body)
	uresp.Body.Close()
	if !strings.Contains(string(ub), `"body":1048576`) {
		t.Fatalf("upload echo: %.200s", ub)
	}

	// ---- usage accounting wrote rows (upload body in, small responses out) ----
	var inB, outB int64
	_ = s.db.QueryRow(`SELECT bytes_in,bytes_out FROM tunnel_usage WHERE tunnel_id=? AND month=?`,
		t2["id"], tunnel.MonthKey(time.Now())).Scan(&inB, &outB)
	if inB < 1<<20 || outB < 100 {
		t.Fatalf("usage rows in=%d out=%d, want in>=1MiB and out>0", inB, outB)
	}

	// ---- concurrency: parallel requests all succeed ----
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.visitor.Get(s.gwSrv.URL + "/t/" + slug2 + "/echo")
			if err != nil {
				errs <- err
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				errs <- fmt.Errorf("concurrent GET = %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}

	// ---- 101 upgrade passes through end-to-end (raw socket) ----
	conn, err := net.Dial("tcp", strings.TrimPrefix(s.gwSrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /t/%s/up HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: rawtest\r\n\r\n", slug2, s.gwSrv.URL[7:])
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "101") {
		t.Fatalf("upgrade status line: %q", line)
	}
	for {
		h, _ := br.ReadString('\n')
		if h == "\r\n" || h == "" {
			break
		}
	}
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("upgrade echo = %q err=%v", buf, err)
	}
	_ = conn.Close()

	// ---- quota enforcement: tiny quota trips and flips status ----
	t4, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "name": "tiny", "target_port": s.appPort,
		"key_required": false, "monthly_quota_bytes": 4096,
	}, adminToken)
	s.reconcile(t, t4["id"].(string))
	slug4 := t4["slug"].(string)
	resp, _ = s.get(t, "/t/"+slug4+"/big", "", "") // 1MiB response >> 4KiB quota
	if resp.StatusCode != 200 {
		t.Fatalf("first big = %d (should succeed and trip quota)", resp.StatusCode)
	}
	time.Sleep(200 * time.Millisecond) // usage write happens after response
	resp, body = s.get(t, "/t/"+slug4+"/echo", "", "")
	if resp.StatusCode != 503 || !strings.Contains(body, "traffic limit") {
		t.Fatalf("post-quota = %d %.200s, want 503 quota page", resp.StatusCode, body)
	}
	var status string
	_ = s.db.QueryRow(`SELECT status FROM tunnels WHERE id=?`, t4["id"]).Scan(&status)
	if status != "quota_exceeded" {
		t.Fatalf("status = %q, want quota_exceeded", status)
	}

	// ---- key brute force trips the attempt limiter (cookieless visitor) ----
	for i := 0; i < tunnel.KeyAttemptLimit; i++ {
		form := url.Values{"mb_tunnel_key": {fmt.Sprintf("guess-%d", i)}}
		req, _ := http.NewRequest("POST", s.gwSrv.URL+"/t/"+slug1+"/echo", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		pr, _ := bare.Do(req)
		io.Copy(io.Discard, pr.Body)
		pr.Body.Close()
	}
	form2 := url.Values{"mb_tunnel_key": {key1}} // even the RIGHT key is locked out
	req5, _ := http.NewRequest("POST", s.gwSrv.URL+"/t/"+slug1+"/echo", strings.NewReader(form2.Encode()))
	req5.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr5, err := bare.Do(req5)
	if err != nil {
		t.Fatal(err)
	}
	if pr5.StatusCode != 429 {
		t.Fatalf("after burst = %d, want 429", pr5.StatusCode)
	}
	io.Copy(io.Discard, pr5.Body)
	pr5.Body.Close()

	// ---- list endpoint (regression: must not deadlock on the single
	// SQLite connection — usage lookups happen after rows are closed) ----
	{
		done := make(chan struct{})
		go func() {
			defer close(done)
			req, _ := http.NewRequest("GET", s.api.URL+"/api/v1/tunnels", nil)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			resp, err := s.visitor.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var out struct {
				Items []map[string]any `json:"items"`
			}
			_ = json.Unmarshal(body, &out)
			if resp.StatusCode != 200 || len(out.Items) < 3 {
				t.Errorf("list = %d items=%d", resp.StatusCode, len(out.Items))
			}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("GET /api/v1/tunnels deadlocked")
		}
	}

	// ---- authorization: a stranger cannot tunnel someone else's device ----
	_, _, raw3 := apiReq(t, s, "POST", "/api/v1/tunnels", map[string]any{
		"device_id": "dev1", "target_port": 8080,
	}, "stranger-token")
	if raw3.StatusCode != 403 {
		t.Fatalf("stranger create = %d, want 403", raw3.StatusCode)
	}

	// ---- cert-ask: only real tunnel subdomains are approved ----
	if resp, _ := apiGet(t, s, "/api/v1/tunnels/cert-ask?domain="+subHost); resp.StatusCode != 200 {
		t.Fatalf("cert-ask good = %d", resp.StatusCode)
	}
	if resp, _ := apiGet(t, s, "/api/v1/tunnels/cert-ask?domain=evil.example.test"); resp.StatusCode != 404 {
		t.Fatalf("cert-ask evil = %d", resp.StatusCode)
	}
	if resp, _ := apiGet(t, s, "/api/v1/tunnels/cert-ask?domain="+tunnel.PublicHost(tunnel.SubdomainLabel(slug4), baseDomain)); resp.StatusCode != 404 {
		t.Fatalf("cert-ask inactive tunnel = %d (slug4 is quota-stopped)", resp.StatusCode)
	}

	// ---- disable drops the live connection ----
	if resp, _ := apiPatch(t, s, "/api/v1/tunnels/"+t2["id"].(string), map[string]any{"status": "disabled"}); resp.StatusCode != 200 {
		t.Fatalf("disable = %d", resp.StatusCode)
	}
	deadline := time.Now().Add(3 * time.Second)
	for s.gw.Online(t2["id"].(string)) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if s.gw.Online(t2["id"].(string)) {
		t.Fatal("disabled tunnel still online")
	}
	resp, _ = s.get(t, "/t/"+slug2+"/echo", "", "")
	if resp.StatusCode != 503 {
		t.Fatalf("disabled = %d, want 503", resp.StatusCode)
	}
}

// ---- fresh-gateway tests (rate limit + global budget use isolated caches) ----

func TestTunnelRateAndBudget(t *testing.T) {
	s := newStack(t)
	tu, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "target_port": s.appPort, "key_required": false,
	}, adminToken)
	s.reconcile(t, tu["id"].(string))
	slug := tu["slug"].(string)

	mustExec(t, s.db, `INSERT OR REPLACE INTO settings(key,value) VALUES('tunnels_rate_per_min','12')`)
	// Generate some recorded usage through the live gateway first, so the
	// global-budget check below has bytes to compare against.
	t0 := time.Now()
	resp, body := s.get(t, "/t/"+slug+"/big", "", "")
	t.Logf("warm-up took %v status=%d len=%d", time.Since(t0), resp.StatusCode, len(body))
	if resp.StatusCode != 200 {
		t.Fatalf("warm-up request = %d", resp.StatusCode)
	}
	var uIn, uOut int64
	_ = s.db.QueryRow(`SELECT bytes_in,bytes_out FROM tunnel_usage WHERE tunnel_id=?`, tu["id"]).Scan(&uIn, &uOut)
	t.Logf("usage after warm-up: in=%d out=%d", uIn, uOut)
	gw2 := tunnel.NewGateway(tunnel.GatewayConfig{DB: s.db, Secret: []byte("s2")})
	srv2 := httptest.NewServer(gw2.Handler())
	defer srv2.Close()
	plain := &http.Client{Timeout: 10 * time.Second}

	codes := map[int]int{}
	for i := 0; i < 24; i++ {
		resp, err := plain.Get(srv2.URL + "/t/" + slug + "/echo")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		codes[resp.StatusCode]++
	}
	if codes[429] == 0 {
		t.Fatalf("rate limiter never fired: %v", codes)
	}

	// Global budget: set below this month's already-recorded usage.
	mustExec(t, s.db, `INSERT OR REPLACE INTO settings(key,value) VALUES('tunnels_global_monthly_bytes','1')`)
	var sv string
	var sum sql.NullInt64
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key='tunnels_global_monthly_bytes'`).Scan(&sv)
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(bytes_in+bytes_out),0) FROM tunnel_usage WHERE month=?`, tunnel.MonthKey(time.Now())).Scan(&sum)
	t.Logf("budget setting=%q usage_sum=%d month=%q", sv, sum.Int64, tunnel.MonthKey(time.Now()))
	gw3 := tunnel.NewGateway(tunnel.GatewayConfig{DB: s.db, Secret: []byte("s3")})
	srv3 := httptest.NewServer(gw3.Handler())
	defer srv3.Close()
	resp3, err := plain.Get(srv3.URL + "/t/" + slug + "/echo")
	if err != nil {
		t.Fatal(err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != 503 || !strings.Contains(string(body3), "shared monthly") {
		t.Fatalf("global budget = %d %.200s", resp3.StatusCode, body3)
	}
}

// ---- agent refuses targets outside its dial policy ----

func TestAgentDialPolicy(t *testing.T) {
	s := newStack(t)
	// 10.x is private (passes server validation) but NOT loopback: an agent
	// without --tunnel-allow must refuse it.
	tu, _ := s.createTunnel(t, map[string]any{
		"device_id": "dev1", "target_host": "10.99.0.5", "target_port": 8080, "key_required": false,
	}, adminToken)
	s.reconcile(t) // expect NO tunnel online
	if s.gw.Online(tu["id"].(string)) {
		t.Fatal("agent connected to a target outside its dial policy")
	}

	// With the CIDR allowed, it connects (nothing to dial yet — but the
	// tunnel session itself must come up).
	cl2, err := tunnel.NewClient(s.api.URL, deviceToken, []string{"10.99.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl2.Close()
	cl2.Reconcile(context.Background(), []tunnel.AgentConfig{{
		ID: tu["id"].(string), Scheme: "http", Host: "10.99.0.5", Port: 8080,
	}})
	deadline := time.Now().Add(5 * time.Second)
	for !s.gw.Online(tu["id"].(string)) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !s.gw.Online(tu["id"].(string)) {
		t.Fatal("agent did not connect after allowlisting")
	}
}

// ---- helpers ----

func apiReq(t *testing.T, s *stack, method, path string, body map[string]any, token string) (map[string]any, string, *http.Response) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, s.api.URL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out, string(b), resp
}

func apiGet(t *testing.T, s *stack, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", s.api.URL+path, nil)
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func apiPatch(t *testing.T, s *stack, path string, body map[string]any) (*http.Response, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("PATCH", s.api.URL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.visitor.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func statusOf(resp *http.Response) int {
	if resp == nil {
		return -1
	}
	return resp.StatusCode
}
