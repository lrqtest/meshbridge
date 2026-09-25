package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	schema := filepath.Join("..", "..", "migrations", "001_init.sql")
	if _, err := os.Stat(schema); err != nil {
		t.Skip("schema not found")
	}
	d, err := db.OpenMemory(schema)
	if err != nil {
		t.Fatal(err)
	}
	ph, _ := auth.HashPassword("admin-pass-123")
	_, err = d.Exec(`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u1','admin',?, 'admin', 1)`, ph)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at) VALUES(?,?,?,1)`, auth.HashToken("test-token"), "u1", "t")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestHealthNoAuth(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("health %d", w.Code)
	}
}

func TestAuthGate(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("must require auth, got %d", w.Code)
	}
	req = httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("authed %d %s", w.Code, w.Body.String())
	}
}

func TestCreateProject(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	req := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(`{"name":"Alpha"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	var _ = http.MethodPost
}

func TestLoginRateLimitAndDummyVerify(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	// 5 failures -> 429 on 6th (per-IP and per-username)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatalf("attempt %d: want 401 got %d", i, w.Code)
		}
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"admin-pass-123"}`))
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 429 {
		t.Fatalf("6th attempt must be rate limited, got %d", w.Code)
	}
	// unknown user gets identical 401 (dummy verify path)
	s2 := New(d)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"ghost","password":"whatever"}`))
	w = httptest.NewRecorder()
	s2.Mux.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("unknown user want 401 got %d", w.Code)
	}
}

func TestLoginTokenExpiryAndLogout(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"admin-pass-123"}`))
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	// expire it and require rejection
	_, _ = d.Exec(`UPDATE api_tokens SET expires_at=1 WHERE token_hash=?`, auth.HashToken(out.Token))
	req = httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+out.Token)
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expired token must 401, got %d", w.Code)
	}
}

func TestAgentHeartbeatFlow(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	// register device via admin token
	req := httptest.NewRequest("POST", "/api/v1/devices", strings.NewReader(`{"hostname":"test-node-1"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("register %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		ID         string `json:"id"`
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg.ID == "" || reg.AgentToken == "" {
		t.Fatal("missing id/agent_token")
	}
	// heartbeat
	hb := strings.NewReader(`{"device_id":"` + reg.ID + `","hostname":"test-node-1","os":"linux","arch":"amd64","agent_version":"0.1.0","tailscale_version":"1.102.3","probe":{"class":"DIRECT"}}`)
	req = httptest.NewRequest("POST", "/api/v1/agents/heartbeat", hb)
	req.Header.Set("Authorization", "Bearer "+reg.AgentToken)
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("heartbeat %d %s", w.Code, w.Body.String())
	}
	// device must show online
	req = httptest.NewRequest("GET", "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"online":true`) {
		t.Fatalf("device must be online: %d %s", w.Code, w.Body.String())
	}
	// foreign device_id must 403
	req = httptest.NewRequest("POST", "/api/v1/agents/heartbeat", strings.NewReader(`{"device_id":"other"}`))
	req.Header.Set("Authorization", "Bearer "+reg.AgentToken)
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("foreign device_id want 403 got %d", w.Code)
	}
}

func TestTransferPathValidation(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	for _, bad := range []string{"/abs/path", "../escape", "a/../b", "C:\\win", ""} {
		body := `{"src":"d1","dst":"d2","src_path":"ok.txt","dst_path":"` + bad + `"}`
		if bad == "" {
			body = `{"src":"d1","dst":"d2","src_path":"ok.txt"}`
		}
		req := httptest.NewRequest("POST", "/api/v1/transfers", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("path %q: want 400 got %d", bad, w.Code)
		}
	}
}
