package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/auth"
)

func TestLoginJSONCapPrecedesDatabaseAndPasswordWork(t *testing.T) {
	s := New(nil)
	for _, body := range []string{`{"username":"admin","password":"x"}` + strings.Repeat(" ", authJSONLimit), `{"password":"` + strings.Repeat("x", authJSONLimit) + `"}`, `{"password":"x"}{}`} {
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("oversized/trailing document: %d", w.Code)
		}
	}
}

func TestLoginAllowsExistingLongPasswordWithinJSONCap(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	password := strings.Repeat("long-password-", 256)
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE users SET password_hash=? WHERE id='u1'`, hash); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(string(body))))
	if w.Code != 200 {
		t.Fatalf("existing password rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestHealthReadinessStatusAndLifetimeCancel(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	s.HSOK = func() bool { return false }
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/health", nil))
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 503 || out["ok"] != false {
		t.Fatalf("not ready: %d %s %v", w.Code, w.Body.String(), err)
	}
	s.healthMu.Lock()
	s.healthUntil = time.Time{}
	s.healthMu.Unlock()
	lifetime, cancel := context.WithCancel(context.Background())
	s.Lifetime = lifetime
	started := make(chan struct{})
	s.HSProbe = func(ctx context.Context) bool { close(started); <-ctx.Done(); return false }
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/health", nil))
		done <- w.Code
	}()
	<-started
	cancel()
	select {
	case code := <-done:
		if code != 503 {
			t.Fatalf("cancelled readiness status=%d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("Headscale probe ignored server cancellation")
	}
}
