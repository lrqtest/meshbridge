package api

import (
	"database/sql"
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
