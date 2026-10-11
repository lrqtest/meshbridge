package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/mineai/kit/sso"
)

const meshTestIssuer = "https://mesh.example"
const meshTestVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func newSSOServer(t *testing.T) *Server {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`UPDATE api_tokens SET name='login',expires_at=?`, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	s := New(d)
	if err := s.EnableSSO(meshTestIssuer, map[string]string{"folio": "https://folio.example/sso/callback", "echo": "https://echo.example/sso/callback"}, false); err != nil {
		t.Fatal(err)
	}
	return s
}

func meshAuthorizeRequest() sso.AuthorizeRequest {
	sum := sha256.Sum256([]byte(meshTestVerifier))
	return sso.AuthorizeRequest{ClientID: "folio", RedirectURI: "https://folio.example/sso/callback", State: "0123456789abcdefghijklmnopqrstuv", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), CodeChallengeMethod: "S256"}
}

func ssoHTTP(s *Server, path string, in any, origin, bearer string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(in)
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, r)
	return w
}

func meshSSOGrant(t *testing.T, s *Server) sso.Grant {
	t.Helper()
	w := ssoHTTP(s, "/api/v1/sso/authorize", meshAuthorizeRequest(), meshTestIssuer, "test-token")
	if w.Code != 200 {
		t.Fatalf("authorize %d %s", w.Code, w.Body.String())
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(out.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Host != "folio.example" || callback.Path != "/sso/callback" || callback.Query().Get("iss") != meshTestIssuer || callback.Query().Get("state") != meshAuthorizeRequest().State {
		t.Fatalf("unsafe callback %s", out.RedirectURL)
	}
	w = ssoHTTP(s, "/api/v1/sso/exchange", sso.ExchangeRequest{ClientID: "folio", RedirectURI: meshAuthorizeRequest().RedirectURI, Code: callback.Query().Get("code"), CodeVerifier: meshTestVerifier}, "", "")
	if w.Code != 200 {
		t.Fatalf("exchange %d %s", w.Code, w.Body.String())
	}
	var grant sso.Grant
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestPlatformSSODefaultOffAndMetadata(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sso/status", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := ssoHTTP(s, "/api/v1/sso/authorize", meshAuthorizeRequest(), meshTestIssuer, "test-token"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if err := s.EnableSSO(meshTestIssuer, map[string]string{"folio": "https://folio.example/sso/callback"}, false); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.Mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/setup/status", nil))
	if !strings.Contains(w.Body.String(), `"sso":{"clients"`) || !strings.Contains(w.Body.String(), meshTestIssuer) {
		t.Fatal(w.Body.String())
	}
}

func TestPlatformSSOBrowserOriginAndBoundedStrictJSON(t *testing.T) {
	s := newSSOServer(t)
	for _, origin := range []string{"", "null", "https://t-evil.mesh.example", "https://mesh.example.evil", "http://mesh.example"} {
		if w := ssoHTTP(s, "/api/v1/sso/authorize", meshAuthorizeRequest(), origin, "test-token"); w.Code != 403 {
			t.Fatalf("origin %s: %d", origin, w.Code)
		}
	}
	for _, body := range []string{`{} {}`, `{"unknown":true}`, `{} ` + strings.Repeat(" ", 16<<10)} {
		r := httptest.NewRequest("POST", "/api/v1/sso/authorize", strings.NewReader(body))
		r.Header.Set("Origin", meshTestIssuer)
		r.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, r)
		want := 400
		if len(body) > 16<<10 {
			want = 413
		}
		if w.Code != want {
			t.Fatalf("JSON %d want%d", w.Code, want)
		}
	}
	for _, path := range []string{"exchange", "introspect", "revoke"} {
		w := ssoHTTP(s, "/api/v1/sso/"+path, map[string]string{}, meshTestIssuer, "")
		if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal(path, w.Code, w.Header())
		}
	}
}

func TestPlatformSSORejectsMachineNonExpiringDisabledExpired(t *testing.T) {
	s := newSSOServer(t)
	for _, state := range []struct {
		query string
		args  []any
	}{
		{`UPDATE api_tokens SET name='machine'`, nil}, {`UPDATE api_tokens SET name='setup'`, nil},
		{`UPDATE api_tokens SET name='login',expires_at=0`, nil}, {`UPDATE api_tokens SET expires_at=1`, nil},
		{`UPDATE api_tokens SET expires_at=?`, []any{time.Now().Add(time.Hour).Unix()}},
	} {
		if _, err := s.DB.Exec(state.query, state.args...); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(state.query, "expires_at=?") {
			if _, err := s.DB.Exec(`UPDATE users SET disabled=1`); err != nil {
				t.Fatal(err)
			}
		}
		if w := ssoHTTP(s, "/api/v1/sso/authorize", meshAuthorizeRequest(), meshTestIssuer, "test-token"); w.Code != 401 {
			t.Fatal(state.query, w.Code, w.Body.String())
		}
	}
}

func TestPlatformSSOUnverifiedCLIIdentityAndRevocation(t *testing.T) {
	s := newSSOServer(t)
	grant := meshSSOGrant(t, s)
	if grant.Identity.Email != "" || grant.Identity.EmailVerified || grant.Identity.Subject != "u1" {
		t.Fatalf("CLI identity: %+v", grant.Identity)
	}
	raw, _ := json.Marshal(grant)
	if strings.Contains(string(raw), `"role"`) {
		t.Fatal("platform role escaped")
	}
	if _, err := s.DB.Exec(`UPDATE users SET email='verified@example.test',email_verified=1`); err != nil {
		t.Fatal(err)
	}
	w := ssoHTTP(s, "/api/v1/sso/introspect", sso.GrantRequest{ClientID: "folio", AccessToken: grant.AccessToken}, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"email_verified":true`) || strings.Contains(w.Body.String(), `"role"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := s.DB.Exec(`UPDATE users SET disabled=1`); err != nil {
		t.Fatal(err)
	}
	if w = ssoHTTP(s, "/api/v1/sso/introspect", sso.GrantRequest{ClientID: "folio", AccessToken: grant.AccessToken}, "", ""); w.Code != 401 {
		t.Fatal("disabled grant", w.Code)
	}
	if _, err := s.DB.Exec(`UPDATE users SET disabled=0`); err != nil {
		t.Fatal(err)
	}
	w = postJSON(t, s, "/api/v1/auth/logout", `{}`, "test-token")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sso_grants`).Scan(&count); err != nil || count != 0 {
		t.Fatal("logout cascade", count, err)
	}
	if w = ssoHTTP(s, "/api/v1/sso/introspect", sso.GrantRequest{ClientID: "folio", AccessToken: grant.AccessToken}, "", ""); w.Code != 401 {
		t.Fatal("logout grant", w.Code)
	}
}

func TestPlatformSSODatabaseFailure503AndNoFalseLoginLogout(t *testing.T) {
	s := newSSOServer(t)
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_token_insert BEFORE INSERT ON api_tokens BEGIN SELECT RAISE(FAIL,'temporary fault'); END`); err != nil {
		t.Fatal(err)
	}
	w := postJSON(t, s, "/api/v1/auth/login", `{"username":"admin","password":"admin-pass-123"}`, "")
	if w.Code != 503 || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("failed SQL login emitted token", w.Code, w.Body.String())
	}
	if _, err := s.DB.Exec(`DROP TRIGGER fail_token_insert; CREATE TRIGGER fail_token_delete BEFORE DELETE ON api_tokens BEGIN SELECT RAISE(FAIL,'temporary fault'); END`); err != nil {
		t.Fatal(err)
	}
	grant := meshSSOGrant(t, s)
	w = postJSON(t, s, "/api/v1/auth/logout", `{}`, "test-token")
	if w.Code != 503 {
		t.Fatal("false logout success", w.Code, w.Body.String())
	}
	if w = ssoHTTP(s, "/api/v1/sso/introspect", sso.GrantRequest{ClientID: "folio", AccessToken: grant.AccessToken}, "", ""); w.Code != 200 {
		t.Fatal("failed logout unexpectedly revoked", w.Code)
	}
	s.DB.Close()
	if w = ssoHTTP(s, "/api/v1/sso/authorize", meshAuthorizeRequest(), meshTestIssuer, "test-token"); w.Code != 503 {
		t.Fatal("DB outage classification", w.Code)
	}
}

func TestPlatformSSORequiresForeignKeyEnforcement(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	if _, err := d.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	s := New(d)
	if err := s.EnableSSO(meshTestIssuer, map[string]string{"folio": "https://folio.example/sso/callback"}, false); err == nil {
		t.Fatal("SSO enabled without logout cascade")
	}
	var present int
	d.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE token_hash=?`, auth.HashToken("test-token")).Scan(&present)
	if present != 1 {
		t.Fatal("test lost parent")
	}
}
