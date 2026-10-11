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
)

const (
	testPlatform = meshTestIssuer
	testProject  = "https://meshbridge.example"
)

// newProjectServer is a split deployment: platform origin = SSO issuer, the
// MeshBridge project on its own origin and registered as a seventh client.
func newProjectServer(t *testing.T) *Server {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`UPDATE api_tokens SET name='login',expires_at=?`, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	s := New(d)
	s.BaseURL, s.ProjectURL = testPlatform, testProject
	if err := s.EnableSSO(testPlatform, map[string]string{
		"folio": "https://folio.example/sso/callback", "meshbridge": testProject + "/sso/callback",
	}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableProjectSSO(false); err != nil {
		t.Fatal(err)
	}
	return s
}

type projectRequest struct {
	method, path, origin, bearer, cookie, site string
	host                                       string
	body                                       any
}

func (s *Server) projectDo(p projectRequest) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if p.body != nil {
		raw, _ := json.Marshal(p.body)
		rd = strings.NewReader(string(raw))
	} else {
		rd = strings.NewReader("")
	}
	if p.method == "" {
		p.method = http.MethodPost
	}
	r := httptest.NewRequest(p.method, p.path, rd)
	r.Header.Set("Content-Type", "application/json")
	if p.host != "" {
		r.Host = p.host
	}
	if p.origin != "" {
		r.Header.Set("Origin", p.origin)
	}
	if p.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+p.bearer)
	}
	if p.cookie != "" {
		r.Header.Set("Cookie", p.cookie)
	}
	if p.site != "" {
		r.Header.Set("Sec-Fetch-Site", p.site)
	}
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, r)
	return w
}

type projectFlow struct {
	cookie, state, challenge string
}

func startProjectFlow(t *testing.T, s *Server, next string) projectFlow {
	t.Helper()
	w := s.projectDo(projectRequest{path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{"next": next}})
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(out.AuthorizeURL)
	if err != nil || u.Scheme+"://"+u.Host != testPlatform || u.Path != "/" || !strings.HasPrefix(u.Fragment, "/sso?") {
		t.Fatalf("authorize url must target the platform hash route only: %q", out.AuthorizeURL)
	}
	q, _ := url.ParseQuery(strings.TrimPrefix(u.Fragment, "/sso?"))
	if q.Get("client_id") != "meshbridge" || q.Get("redirect_uri") != testProject+"/sso/callback" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize parameters: %v", q)
	}
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-meshbridge-sso" {
			if c.Domain != "" || c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("flow cookie must be host-only, secure, HttpOnly and Lax: %+v", c)
			}
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("start did not set the flow cookie")
	}
	for _, leaked := range []string{"verifier", "access_token", "token"} {
		if strings.Contains(w.Body.String(), leaked) {
			t.Fatalf("start leaked %q: %s", leaked, w.Body.String())
		}
	}
	return projectFlow{cookie: cookie, state: q.Get("state"), challenge: q.Get("code_challenge")}
}

// platformCode authorizes the flow with a platform session, as the platform
// page would, and returns the single-use code from the redirect.
func platformCode(t *testing.T, s *Server, f projectFlow, bearer string) string {
	t.Helper()
	w := s.projectDo(projectRequest{path: "/api/v1/sso/authorize", origin: testPlatform, bearer: bearer, body: map[string]string{
		"client_id": "meshbridge", "redirect_uri": testProject + "/sso/callback", "state": f.state,
		"code_challenge": f.challenge, "code_challenge_method": "S256",
	}})
	if w.Code != 200 {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	u, err := url.Parse(out.RedirectURL)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != testProject+"/sso/callback" || u.Fragment != "" {
		t.Fatalf("redirect must be the exact callback: %q", out.RedirectURL)
	}
	if strings.Contains(out.RedirectURL, bearer) {
		t.Fatal("redirect carried the platform token")
	}
	return u.Query().Get("code")
}

func completeProject(s *Server, f projectFlow, code string) *httptest.ResponseRecorder {
	return s.projectDo(projectRequest{path: "/api/v1/auth/sso/complete", origin: testProject, cookie: f.cookie,
		body: map[string]string{"code": code, "state": f.state, "iss": testPlatform}})
}

type projectSession struct {
	Token string         `json:"token"`
	Next  string         `json:"next"`
	SSO   bool           `json:"sso"`
	User  map[string]any `json:"user"`
}

func signInThroughPlatform(t *testing.T, s *Server, next string) projectSession {
	t.Helper()
	f := startProjectFlow(t, s, next)
	w := completeProject(s, f, platformCode(t, s, f, "test-token"))
	if w.Code != 200 {
		t.Fatalf("complete: %d %s", w.Code, w.Body.String())
	}
	var out projectSession
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSurfaceFollowsTheRequestHost(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	single := New(d)
	single.BaseURL = "https://mesh.standalone.example"
	type surface struct {
		Kind, PlatformURL, ProjectURL, BaseURL string
		Split, SSO                             bool
	}
	get := func(s *Server, host string) (surface, *httptest.ResponseRecorder) {
		w := s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/surface", host: host})
		var raw map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
			t.Fatal(w.Body.String())
		}
		out := surface{Kind: raw["kind"].(string), PlatformURL: raw["platform_url"].(string), ProjectURL: raw["project_url"].(string), BaseURL: raw["base_url"].(string)}
		out.Split, out.SSO = raw["split"].(bool), raw["sso"].(bool)
		return out, w
	}

	// Standalone: the project is the only surface on every host.
	for _, host := range []string{"mesh.standalone.example", "127.0.0.1:8081", "anything.example"} {
		if got, _ := get(single, host); got.Kind != "project" || got.Split || got.SSO || got.PlatformURL != "" || got.BaseURL != "https://mesh.standalone.example" {
			t.Fatalf("standalone %s: %+v", host, got)
		}
	}

	s := newProjectServer(t)
	cases := []struct {
		host, kind string
		sso        bool
	}{
		{"mesh.example", "platform", false},     // platform host
		{"MESH.example", "platform", false},     // host names are case-insensitive
		{"mesh.example:443", "platform", false}, // default port is the same origin
		{"meshbridge.example", "project", true}, // project host
		{"127.0.0.1:8081", "project", true},     // direct hit never shows the platform
		{"meshbridge.example.evil", "project", true},
		{"", "project", true},
	}
	for _, c := range cases {
		got, w := get(s, c.host)
		if got.Kind != c.kind || got.SSO != c.sso || !got.Split || got.PlatformURL != testPlatform || got.ProjectURL != testProject || got.BaseURL != testPlatform {
			t.Errorf("host %q: %+v", c.host, got)
		}
		if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Vary"), "Host") {
			t.Errorf("host-dependent answer must not be cacheable: %v", w.Header())
		}
	}
	if w := s.projectDo(projectRequest{path: "/api/v1/surface"}); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST surface: %d", w.Code)
	}
}

func TestProjectSSOIssuesADerivedProjectSession(t *testing.T) {
	s := newProjectServer(t)
	got := signInThroughPlatform(t, s, "#/app/devices")
	if got.Token == "" || got.Token == "test-token" || got.Next != "#/app/devices" || !got.SSO || got.User["username"] != "admin" || got.User["role"] != "admin" {
		t.Fatalf("session: %+v", got)
	}

	var name string
	var grant *string
	var expires int64
	if err := s.DB.QueryRow(`SELECT name,grant_hash,expires_at FROM api_tokens WHERE token_hash=?`, auth.HashToken(got.Token)).Scan(&name, &grant, &expires); err != nil {
		t.Fatal(err)
	}
	if name != "sso:meshbridge" || grant == nil || expires <= time.Now().Unix() || expires > time.Now().Add(time.Hour+time.Minute).Unix() {
		t.Fatalf("derived session row: name=%q grant=%v expires=%d (must not outlive the platform session)", name, grant, expires)
	}
	// It is a real MeshBridge session: the same bearer policy accepts it.
	w := s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/me", bearer: got.Token})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"sso":true`) || !strings.Contains(w.Body.String(), `"role":"admin"`) {
		t.Fatalf("/me with derived session: %d %s", w.Code, w.Body.String())
	}
	// The platform session itself is not marked as derived.
	w = s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/me", bearer: "test-token"})
	if !strings.Contains(w.Body.String(), `"sso":false`) {
		t.Fatalf("platform session mislabelled: %s", w.Body.String())
	}
	// Both audit and cookie hygiene.
	var logins int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE event='login' AND detail LIKE 'platform ·%'`).Scan(&logins)
	if logins != 1 {
		t.Fatalf("platform-derived login must be audited once, got %d", logins)
	}
}

func TestProjectSessionDiesWithThePlatformSession(t *testing.T) {
	s := newProjectServer(t)
	got := signInThroughPlatform(t, s, "")
	me := func() int {
		return s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/me", bearer: got.Token}).Code
	}
	if me() != 200 {
		t.Fatal("derived session should work")
	}
	// Platform sign-out deletes the parent token. The grant, and with it the
	// project session, must disappear at once -- no polling window.
	if w := s.projectDo(projectRequest{path: "/api/v1/auth/logout", bearer: "test-token"}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if code := me(); code != 401 {
		t.Fatalf("project session survived platform sign-out: %d", code)
	}
	var grants, sessions int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM sso_grants`).Scan(&grants)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE name='sso:meshbridge'`).Scan(&sessions)
	if grants != 0 || sessions != 0 {
		t.Fatalf("orphans after platform sign-out: grants=%d sessions=%d", grants, sessions)
	}
}

func TestProjectSignOutKeepsPlatformSessionAndFreesTheGrant(t *testing.T) {
	s := newProjectServer(t)
	got := signInThroughPlatform(t, s, "")
	w := s.projectDo(projectRequest{path: "/api/v1/auth/sso/logout", origin: testProject, bearer: got.Token})
	if w.Code != 200 || !strings.Contains(w.Body.String(), testPlatform+"/#/sso/logout") {
		t.Fatalf("project sso logout: %d %s", w.Code, w.Body.String())
	}
	if s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/me", bearer: got.Token}).Code != 401 {
		t.Fatal("project session survived its own sign-out")
	}
	if s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/me", bearer: "test-token"}).Code != 200 {
		t.Fatal("project sign-out must not end the platform session")
	}
	var grants int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM sso_grants`).Scan(&grants)
	if grants != 0 {
		t.Fatalf("project sign-out left %d grants consuming the per-session budget", grants)
	}
	// The generic logout used by the console behaves the same way.
	second := signInThroughPlatform(t, s, "")
	if w := s.projectDo(projectRequest{path: "/api/v1/auth/logout", bearer: second.Token}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM sso_grants`).Scan(&grants)
	if grants != 0 {
		t.Fatalf("generic logout left %d grants", grants)
	}
}

func TestProjectSSORejectsEveryBrokenRequest(t *testing.T) {
	s := newProjectServer(t)
	body := map[string]string{"next": ""}
	for name, p := range map[string]projectRequest{
		"platform origin":    {path: "/api/v1/auth/sso/start", origin: testPlatform, body: body},
		"no origin":          {path: "/api/v1/auth/sso/start", body: body},
		"null origin":        {path: "/api/v1/auth/sso/start", origin: "null", body: body},
		"suffix origin":      {path: "/api/v1/auth/sso/start", origin: testProject + ".evil", body: body},
		"cross-site":         {path: "/api/v1/auth/sso/start", origin: testProject, site: "cross-site", body: body},
		"absolute next":      {path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{"next": "https://evil.example/"}},
		"protocol-rel next":  {path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{"next": "//evil.example"}},
		"double slash next":  {path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{"next": "#//evil.example"}},
		"backslash next":     {path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{"next": "#/app\\evil"}},
		"GET start":          {method: http.MethodGet, path: "/api/v1/auth/sso/start", origin: testProject},
		"complete no cookie": {path: "/api/v1/auth/sso/complete", origin: testProject, body: map[string]string{"code": "c", "state": "s", "iss": testPlatform}},
		"complete bad iss":   {path: "/api/v1/auth/sso/complete", origin: testProject, body: map[string]string{"code": "c", "state": "s", "iss": "https://evil.example"}},
		"complete platform":  {path: "/api/v1/auth/sso/complete", origin: testPlatform, body: map[string]string{"code": "c", "state": "s", "iss": testPlatform}},
		"logout no origin":   {path: "/api/v1/auth/sso/logout", bearer: "test-token"},
	} {
		if w := s.projectDo(p); w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s: want a 4xx refusal, got %d %s", name, w.Code, w.Body.String())
		}
	}
	// Unknown fields and oversized bodies never reach the flow store.
	w := s.projectDo(projectRequest{path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{"next": "#/" + strings.Repeat("a", 4096)}})
	if w.Code < 400 {
		t.Fatalf("oversized next accepted: %d", w.Code)
	}
	if len(s.ProjectSSO.CookieName()) == 0 || strings.Contains(s.ProjectSSO.CookieName(), "Domain") {
		t.Fatal("cookie name")
	}
}

func TestProjectSSOFlowIsBoundToItsBrowserAndSingleUse(t *testing.T) {
	s := newProjectServer(t)

	// A code redeemed in a browser that does not hold the flow cookie.
	f := startProjectFlow(t, s, "")
	code := platformCode(t, s, f, "test-token")
	stranger := projectFlow{cookie: "__Host-meshbridge-sso=" + strings.Repeat("A", 43), state: f.state}
	if w := completeProject(s, stranger, code); w.Code != 401 {
		t.Fatalf("foreign cookie accepted: %d %s", w.Code, w.Body.String())
	}
	// The state must be the one this browser started.
	other := startProjectFlow(t, s, "")
	if w := completeProject(s, projectFlow{cookie: other.cookie, state: f.state}, code); w.Code != 401 {
		t.Fatalf("cookie/state swap accepted: %d", w.Code)
	}

	// Happy path once, then replay of the very same code and flow.
	f = startProjectFlow(t, s, "")
	code = platformCode(t, s, f, "test-token")
	if w := completeProject(s, f, code); w.Code != 200 {
		t.Fatalf("first completion: %d %s", w.Code, w.Body.String())
	}
	if w := completeProject(s, f, code); w.Code != 401 {
		t.Fatalf("code replay accepted: %d", w.Code)
	}

	// PKCE: a code authorized for someone else's challenge is useless here.
	f = startProjectFlow(t, s, "")
	mine := f.challenge
	foreign := sha256.Sum256([]byte("somebody else's verifier"))
	f.challenge = base64.RawURLEncoding.EncodeToString(foreign[:])
	code = platformCode(t, s, f, "test-token")
	f.challenge = mine
	if w := completeProject(s, f, code); w.Code != 401 {
		t.Fatalf("PKCE mismatch accepted: %d %s", w.Code, w.Body.String())
	}

	// Only a platform *login* session can authorize. A project session cannot
	// bootstrap further authorizations, and neither can an unknown token.
	derived := signInThroughPlatform(t, s, "")
	f = startProjectFlow(t, s, "")
	for _, bearer := range []string{derived.Token, "nonexistent-token", ""} {
		w := s.projectDo(projectRequest{path: "/api/v1/sso/authorize", origin: testPlatform, bearer: bearer, body: map[string]string{
			"client_id": "meshbridge", "redirect_uri": testProject + "/sso/callback", "state": f.state,
			"code_challenge": f.challenge, "code_challenge_method": "S256"}})
		if w.Code != 401 {
			t.Fatalf("bearer %q authorized another client: %d %s", bearer, w.Code, w.Body.String())
		}
	}
}

func TestProjectSSORefusesDisabledAndMissingAccounts(t *testing.T) {
	s := newProjectServer(t)
	f := startProjectFlow(t, s, "")
	code := platformCode(t, s, f, "test-token")
	if _, err := s.DB.Exec(`UPDATE users SET disabled=1 WHERE id='u1'`); err != nil {
		t.Fatal(err)
	}
	w := completeProject(s, f, code)
	if w.Code != 401 || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("disabled account got a session: %d %s", w.Code, w.Body.String())
	}
	var grants, sessions int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM sso_grants`).Scan(&grants)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE name='sso:meshbridge'`).Scan(&sessions)
	if grants != 0 || sessions != 0 {
		t.Fatalf("a refused sign-in left state behind: grants=%d sessions=%d", grants, sessions)
	}
}

func TestProjectSSOStatusReflectsTheSurface(t *testing.T) {
	s := newProjectServer(t)
	status := func(host, bearer string) map[string]any {
		w := s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/auth/sso/status", host: host, bearer: bearer})
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
			t.Fatalf("status: %d %s", w.Code, w.Body.String())
		}
		return out
	}
	if got := status("meshbridge.example", ""); got["enabled"] != true || got["issuer"] != testPlatform || got["session"] != false {
		t.Fatalf("project status: %v", got)
	}
	if got := status("mesh.example", ""); got["enabled"] != false {
		t.Fatalf("the platform must not offer to continue with itself: %v", got)
	}
	derived := signInThroughPlatform(t, s, "")
	if got := status("meshbridge.example", derived.Token); got["session"] != true {
		t.Fatalf("derived session not reported: %v", got)
	}
	if got := status("meshbridge.example", "test-token"); got["session"] != false {
		t.Fatalf("local session reported as derived: %v", got)
	}

	// Without SSO the client endpoints are inert, not errors for the page.
	d := testDB(t)
	defer d.Close()
	plain := New(d)
	plain.ProjectURL, plain.BaseURL = testProject, testPlatform
	if got := func() map[string]any {
		w := plain.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/auth/sso/status", host: "meshbridge.example"})
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}(); got["enabled"] != false {
		t.Fatalf("SSO off: %v", got)
	}
	if w := plain.projectDo(projectRequest{path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{}}); w.Code != 404 {
		t.Fatalf("start with SSO off: %d", w.Code)
	}
}

func TestProjectSSOGrantBudgetIsEnforcedAndReleased(t *testing.T) {
	s := newProjectServer(t)
	var sessions []projectSession
	for i := 0; i < 8; i++ {
		sessions = append(sessions, signInThroughPlatform(t, s, ""))
	}
	f := startProjectFlow(t, s, "")
	w := completeProject(s, f, platformCode(t, s, f, "test-token"))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "sso_busy") {
		t.Fatalf("ninth session for one platform login: %d %s", w.Code, w.Body.String())
	}
	if w := s.projectDo(projectRequest{path: "/api/v1/auth/sso/logout", origin: testProject, bearer: sessions[0].Token}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if got := signInThroughPlatform(t, s, ""); got.Token == "" {
		t.Fatal("slot was not released by sign-out")
	}
}

func TestProjectSSOStartIsRateLimitedPerClient(t *testing.T) {
	s := newProjectServer(t)
	var limited bool
	for i := 0; i < 60 && !limited; i++ {
		w := s.projectDo(projectRequest{path: "/api/v1/auth/sso/start", origin: testProject, body: map[string]string{}})
		limited = w.Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("anonymous flow creation is unbounded")
	}
}
