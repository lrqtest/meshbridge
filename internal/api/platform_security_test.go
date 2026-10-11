package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/auth"
)

func TestEveryHumanAdminGuardRejectsExpiredOrDisabledToken(t *testing.T) {
	for _, state := range []string{"expired", "disabled"} {
		t.Run(state, func(t *testing.T) {
			s, stub := newMailerTest(t)
			_, err := s.DB.Exec(`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('a','admin','unused','admin',1)`)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at) VALUES(?,'a','test',1)`, auth.HashToken("bad-admin"))
			if err != nil {
				t.Fatal(err)
			}
			if state == "expired" {
				_, err = s.DB.Exec(`UPDATE api_tokens SET expires_at=1`)
			} else {
				_, err = s.DB.Exec(`UPDATE users SET disabled=1`)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range []struct{ method, path string }{
				{"GET", "/api/v1/me"}, {"GET", "/api/v1/setup/smtp"}, {"POST", "/api/v1/setup/smtp"},
				{"POST", "/api/v1/setup/smtp/test"}, {"POST", "/api/v1/setup/registration"},
				{"POST", "/api/v1/devices/enroll"}, {"GET", "/api/v1/tunnels/settings"},
			} {
				r := httptest.NewRequest(entry.method, entry.path, strings.NewReader(`{}`))
				r.Header.Set("Authorization", "Bearer bad-admin")
				w := httptest.NewRecorder()
				s.Mux.ServeHTTP(w, r)
				if w.Code != 401 {
					t.Errorf("%s %s: %d %s", entry.method, entry.path, w.Code, w.Body.String())
				}
			}
			if len(stub.sent) != 0 {
				t.Fatal("invalid token sent email")
			}
			var n int
			_ = s.DB.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&n)
			if n != 0 {
				t.Fatal("invalid token enrolled device")
			}
		})
	}
}

func TestTransferCreationChecksAllObjects(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	for _, q := range []string{
		`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u2','member','unused','user',1)`,
		`INSERT INTO projects(id,name,slug,created_at) VALUES('p','Own','own',1),('other','Other','other',1)`,
		`INSERT INTO project_memberships(project_id,user_id,role) VALUES('p','u2','member')`,
		`INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES('src','src','u2',1),('dst','dst','u2',1),('foreign','foreign','u1',1)`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at) VALUES(?,'u2','test',1)`, auth.HashToken("member-token")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, token, project, src, dst string
		want                           int
	}{
		{"member owned", "member-token", "p", "src", "dst", 200},
		{"foreign source", "member-token", "p", "foreign", "dst", 403},
		{"foreign destination", "member-token", "p", "src", "foreign", 403},
		{"foreign project", "member-token", "other", "src", "dst", 403},
		{"missing source", "member-token", "p", "missing", "dst", 404},
		{"missing destination", "test-token", "p", "src", "missing", 404},
		{"missing project", "test-token", "missing", "src", "dst", 404},
		{"schema requires project", "test-token", "", "src", "dst", 404},
		{"admin existing objects", "test-token", "other", "src", "foreign", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before int
			_ = d.QueryRow(`SELECT COUNT(*) FROM transfer_jobs`).Scan(&before)
			body := fmt.Sprintf(`{"project_id":%q,"src_device_id":%q,"dst_device_id":%q,"src_path":"input.txt","dst_path":"output.txt"}`, tc.project, tc.src, tc.dst)
			w := postJSON(t, s, "/api/v1/transfers", body, tc.token)
			if w.Code != tc.want {
				t.Fatalf("%d %s, want %d", w.Code, w.Body.String(), tc.want)
			}
			var after int
			_ = d.QueryRow(`SELECT COUNT(*) FROM transfer_jobs`).Scan(&after)
			if (tc.want == 200 && after != before+1) || (tc.want != 200 && after != before) {
				t.Fatalf("job count before=%d after=%d", before, after)
			}
		})
	}
}

func TestHealthSharesProbeAndExpiresPresenceWithoutWrites(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	for _, q := range []string{
		`INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES('old','old','u1',1)`,
		`INSERT INTO agents(device_id,last_seen,online) VALUES('old',1,1)`,
		`CREATE TRIGGER reject_presence_writes BEFORE UPDATE ON agents BEGIN SELECT RAISE(ABORT,'health must not write'); END`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	entered := make(chan struct{})
	unblock := make(chan struct{})
	s.HSOK = func() bool {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-unblock
		return true
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			s.Mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/health", nil))
			if w.Code != 200 {
				t.Error(w.Code)
				return
			}
			var out struct {
				OK     bool `json:"ok"`
				Online int  `json:"agents_online"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !out.OK || out.Online != 0 {
				t.Errorf("health %s: %v", w.Body.String(), err)
			}
		}()
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.health(ctx); err != context.Canceled {
		t.Fatalf("cancelled follower: %v", err)
	}
	close(unblock)
	wg.Wait()
	for range 3 {
		if _, err := s.health(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("probe fan-out: %d", calls.Load())
	}
	var stored int
	_ = d.QueryRow(`SELECT online FROM agents WHERE device_id='old'`).Scan(&stored)
	if stored != 1 {
		t.Fatal("health changed stored presence")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/devices", nil)
	r.Header.Set("Authorization", "Bearer test-token")
	s.Mux.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), `"online":true`) {
		t.Fatalf("stale device shown online: %s", w.Body.String())
	}
	s.healthMu.Lock()
	s.healthUntil = time.Now().Add(-time.Second)
	s.healthMu.Unlock()
	if _, err := s.health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("cache did not refresh: %d", calls.Load())
	}
}
