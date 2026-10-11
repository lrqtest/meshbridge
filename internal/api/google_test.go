package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	meshauth "github.com/meshbridge/meshbridge/internal/auth"
	"github.com/mineai/kit/auth"
)

const meshGoogleClientID = "1234-test.apps.googleusercontent.com"

func signMeshGoogleToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc.EncodeToString(sig)
}

func meshGoogleJWKS(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	enc := base64.RawURLEncoding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
			"n": enc.EncodeToString(key.PublicKey.N.Bytes()), "e": "AQAB",
		}}})
	}))
	t.Cleanup(server.Close)
	return server
}

func meshGoogleClaims(sub, email string) map[string]any {
	return map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            meshGoogleClientID,
		"sub":            sub,
		"email":          email,
		"email_verified": true,
		"name":           "Google User",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func TestGoogleLoginCreatesAndReusesIdentity(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	if _, err := d.Exec(`INSERT INTO settings(key,value) VALUES('google_client_id',?)`, meshGoogleClientID); err != nil {
		t.Fatal(err)
	}
	s := New(d)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.Google = &auth.GoogleVerifier{KeysURL: meshGoogleJWKS(t, key, "mesh-test").URL}
	token := signMeshGoogleToken(t, key, "mesh-test", meshGoogleClaims("google-sub-1", "person@example.com"))

	login := func() (string, int) {
		req := httptest.NewRequest("POST", "/api/v1/auth/google", strings.NewReader(`{"credential":"`+token+`"}`))
		w := httptest.NewRecorder()
		s.Mux.ServeHTTP(w, req)
		var out struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(w.Body).Decode(&out)
		return out.Token, w.Code
	}
	first, code := login()
	if code != http.StatusOK || first == "" {
		t.Fatalf("first Google login: status=%d token=%q", code, first)
	}
	second, code := login()
	if code != http.StatusOK || second == "" || second == first {
		t.Fatalf("second Google login: status=%d tokens %q %q", code, first, second)
	}
	var users, identities int
	if err := d.QueryRow(`SELECT COUNT(*) FROM users WHERE email='person@example.com'`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM user_identities WHERE provider='google' AND provider_sub='google-sub-1'`).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if users != 1 || identities != 1 {
		t.Fatalf("Google login created duplicate rows: users=%d identities=%d", users, identities)
	}
}

// googleServer is a MeshBridge with Google sign-in configured and a verifier
// whose key set the test controls.
func googleServer(t *testing.T) (*Server, *rsa.PrivateKey) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`INSERT INTO settings(key,value) VALUES('google_client_id',?)`, meshGoogleClientID); err != nil {
		t.Fatal(err)
	}
	s := New(d)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.Google = &auth.GoogleVerifier{KeysURL: meshGoogleJWKS(t, key, "mesh-test").URL}
	return s, key
}

func googleCredential(t *testing.T, key *rsa.PrivateKey, sub, email string, mutate ...func(map[string]any)) string {
	t.Helper()
	claims := meshGoogleClaims(sub, email)
	for _, m := range mutate {
		m(claims)
	}
	return signMeshGoogleToken(t, key, "mesh-test", claims)
}

type googleResult struct {
	Code    int
	Status  string `json:"code"`
	Token   string `json:"token"`
	Message string `json:"error"`
}

func googleSignIn(s *Server, credential string) googleResult {
	w := s.projectDo(projectRequest{path: "/api/v1/auth/google", body: map[string]string{"credential": credential}})
	var out googleResult
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	out.Code = w.Code
	return out
}

func addUser(t *testing.T, s *Server, id, name, role, email string, verified, disabled bool) {
	t.Helper()
	hash, _ := meshauth.HashPassword("password-" + id + "-long-enough")
	if _, err := s.DB.Exec(`INSERT INTO users(id,username,password_hash,role,email,email_verified,disabled,created_at) VALUES(?,?,?,?,?,?,?,1)`,
		id, name, hash, role, email, map[bool]int{true: 1}[verified], map[bool]int{true: 1}[disabled]); err != nil {
		t.Fatal(err)
	}
}

func identityCount(t *testing.T, s *Server, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM user_identities WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGoogleSignInFailuresAreDistinguishable(t *testing.T) {
	// Not configured at all.
	d := testDB(t)
	defer d.Close()
	plain := New(d)
	if got := googleSignIn(plain, "x.y.z"); got.Code != 503 || got.Status != "google_not_configured" {
		t.Fatalf("unconfigured: %+v", got)
	}

	s, key := googleServer(t)
	cases := []struct {
		name   string
		cred   string
		code   int
		status string
	}{
		{"garbage", "not-a-jwt", 401, "google_invalid"},
		{"wrong audience", googleCredential(t, key, "s1", "a@example.com", func(c map[string]any) { c["aud"] = "someone-else.apps.googleusercontent.com" }), 401, "google_invalid"},
		{"expired", googleCredential(t, key, "s1", "a@example.com", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), 401, "google_invalid"},
		{"wrong issuer", googleCredential(t, key, "s1", "a@example.com", func(c map[string]any) { c["iss"] = "https://evil.example" }), 401, "google_invalid"},
		{"unverified address", googleCredential(t, key, "s1", "a@example.com", func(c map[string]any) { c["email_verified"] = false }), 403, "google_email_unverified"},
		{"no address", googleCredential(t, key, "s1", ""), 403, "google_email_unverified"},
	}
	for _, c := range cases {
		if got := googleSignIn(s, c.cred); got.Code != c.code || got.Status != c.status || got.Token != "" {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	var created int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email='a@example.com'`).Scan(&created)
	if created != 0 {
		t.Fatal("a refused sign-in created an account")
	}
}

func TestGoogleOutageIsNotTheVisitorsFailure(t *testing.T) {
	s, key := googleServer(t)
	down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	down.Close()
	s.Google = &auth.GoogleVerifier{KeysURL: down.URL}
	cred := googleCredential(t, key, "s1", "a@example.com")
	for i := 0; i < 12; i++ { // far beyond the failure budget
		if got := googleSignIn(s, cred); got.Code != 503 || got.Status != "google_unavailable" {
			t.Fatalf("attempt %d during a Google outage: %+v", i, got)
		}
	}
}

func TestGoogleCredentialFailuresAreRateLimited(t *testing.T) {
	s, _ := googleServer(t)
	limited := false
	for i := 0; i < 12 && !limited; i++ {
		limited = googleSignIn(s, "forged.credential.value").Code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("forged credentials are not rate limited")
	}
}

func TestGoogleNeverAbsorbsAdministratorsOrUnverifiedAccountsByEmail(t *testing.T) {
	s, key := googleServer(t)
	if _, err := s.DB.Exec(`UPDATE users SET email='root@example.com',email_verified=1 WHERE id='u1'`); err != nil {
		t.Fatal(err)
	}
	addUser(t, s, "u2", "alice", "user", "alice@example.com", true, false)
	addUser(t, s, "u3", "bob", "user", "bob@example.com", false, false)

	// A verified Google address equal to the administrator's address is not
	// proof of being the administrator.
	got := googleSignIn(s, googleCredential(t, key, "g-root", "root@example.com"))
	if got.Code != 409 || got.Status != "google_link_required" || got.Token != "" {
		t.Fatalf("administrator absorbed by e-mail: %+v", got)
	}
	// ... nor is it for an account whose own address was never verified.
	got = googleSignIn(s, googleCredential(t, key, "g-bob", "bob@example.com"))
	if got.Code != 409 || got.Status != "google_link_required" || got.Token != "" {
		t.Fatalf("unverified account absorbed by e-mail: %+v", got)
	}
	if n := identityCount(t, s, `provider_sub IN ('g-root','g-bob')`); n != 0 {
		t.Fatalf("a refused sign-in left %d identities", n)
	}

	// An ordinary account with a verified address is claimed exactly once.
	got = googleSignIn(s, googleCredential(t, key, "g-alice", "alice@example.com"))
	if got.Code != 200 || got.Token == "" {
		t.Fatalf("ordinary verified account not linked: %+v", got)
	}
	if n := identityCount(t, s, `user_id='u2' AND provider_sub='g-alice'`); n != 1 {
		t.Fatalf("identity not recorded: %d", n)
	}
	var owner string
	if err := s.DB.QueryRow(`SELECT user_id FROM api_tokens WHERE token_hash=?`, meshauth.HashToken(got.Token)).Scan(&owner); err != nil || owner != "u2" {
		t.Fatalf("session belongs to %q (%v)", owner, err)
	}
	// A reassigned mailbox (new Google subject, same address) inherits nothing.
	got = googleSignIn(s, googleCredential(t, key, "g-alice-new-owner", "alice@example.com"))
	if got.Code != 409 || got.Status != "google_already_linked" || got.Token != "" {
		t.Fatalf("second subject inherited an account: %+v", got)
	}
	// The original subject keeps working through its identity.
	if got = googleSignIn(s, googleCredential(t, key, "g-alice", "alice@example.com")); got.Code != 200 {
		t.Fatalf("linked identity stopped working: %+v", got)
	}
	// The address is irrelevant once linked: a changed Google address still
	// reaches the same account through the immutable subject.
	if got = googleSignIn(s, googleCredential(t, key, "g-alice", "alice.renamed@example.com")); got.Code != 200 {
		t.Fatalf("subject lookup depends on e-mail: %+v", got)
	}
}

func TestGoogleRefusesDisabledAccountsAndClosedRegistration(t *testing.T) {
	s, key := googleServer(t)
	addUser(t, s, "u2", "carol", "user", "carol@example.com", true, true)
	got := googleSignIn(s, googleCredential(t, key, "g-carol", "carol@example.com"))
	if got.Code != 403 || got.Status != "account_disabled" || got.Token != "" {
		t.Fatalf("disabled (by e-mail): %+v", got)
	}
	// Disabled after linking: the identity path refuses too.
	addUser(t, s, "u4", "dave", "user", "dave@example.com", true, false)
	if got = googleSignIn(s, googleCredential(t, key, "g-dave", "dave@example.com")); got.Code != 200 {
		t.Fatalf("link dave: %+v", got)
	}
	if _, err := s.DB.Exec(`UPDATE users SET disabled=1 WHERE id='u4'`); err != nil {
		t.Fatal(err)
	}
	if got = googleSignIn(s, googleCredential(t, key, "g-dave", "dave@example.com")); got.Code != 403 || got.Status != "account_disabled" || got.Token != "" {
		t.Fatalf("disabled (by identity): %+v", got)
	}

	if _, err := s.DB.Exec(`INSERT INTO settings(key,value) VALUES('allow_registration','0') ON CONFLICT(key) DO UPDATE SET value='0'`); err != nil {
		t.Fatal(err)
	}
	got = googleSignIn(s, googleCredential(t, key, "g-new", "new@example.com"))
	if got.Code != 403 || got.Status != "registration_closed" {
		t.Fatalf("closed registration: %+v", got)
	}
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email='new@example.com'`).Scan(&n)
	if n != 0 {
		t.Fatal("closed registration still created an account")
	}
	// Existing linked accounts are unaffected by closing registration.
	addUser(t, s, "u5", "erin", "user", "erin@example.com", true, false)
	_, _ = s.DB.Exec(`UPDATE settings SET value='1' WHERE key='allow_registration'`)
	if got = googleSignIn(s, googleCredential(t, key, "g-erin", "erin@example.com")); got.Code != 200 {
		t.Fatal(got)
	}
	_, _ = s.DB.Exec(`UPDATE settings SET value='0' WHERE key='allow_registration'`)
	if got = googleSignIn(s, googleCredential(t, key, "g-erin", "erin@example.com")); got.Code != 200 {
		t.Fatalf("closing registration locked out a linked user: %+v", got)
	}
}

func TestGoogleAdministratorLinksExplicitlyFromTheirOwnSession(t *testing.T) {
	s, key := googleServer(t)
	if _, err := s.DB.Exec(`UPDATE users SET email='root@example.com',email_verified=1 WHERE id='u1'`); err != nil {
		t.Fatal(err)
	}
	addUser(t, s, "u2", "alice", "user", "alice@example.com", true, false)
	link := func(bearer, cred string) (int, string) {
		w := s.projectDo(projectRequest{method: http.MethodPut, path: "/api/v1/me/google", bearer: bearer, body: map[string]string{"credential": cred}})
		var out googleResult
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out.Status
	}
	if code, _ := link("", googleCredential(t, key, "g-root", "root@example.com")); code != 401 {
		t.Fatalf("anonymous link: %d", code)
	}
	w := s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/me/google", bearer: "test-token"})
	if !strings.Contains(w.Body.String(), `"linked":false`) || !strings.Contains(w.Body.String(), `"configured":true`) {
		t.Fatalf("status before: %s", w.Body.String())
	}
	if code, status := link("test-token", "forged.credential.value"); code != 401 || status != "google_invalid" {
		t.Fatalf("forged link: %d %s", code, status)
	}
	if code, status := link("test-token", googleCredential(t, key, "g-root", "different@example.com")); code != 200 {
		t.Fatalf("link: %d %s", code, status) // the Google address need not equal the account address
	}
	// Now the administrator can sign in with Google, through the identity.
	if got := googleSignIn(s, googleCredential(t, key, "g-root", "root@example.com")); got.Code != 200 || got.Token == "" {
		t.Fatalf("sign in after link: %+v", got)
	}
	// One Google identity per account, one account per Google identity.
	if code, status := link("test-token", googleCredential(t, key, "g-other", "root@example.com")); code != 409 || status != "google_already_linked" {
		t.Fatalf("second identity for one account: %d %s", code, status)
	}
	aliceToken := "alice-session"
	if _, err := s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,1,?)`,
		meshauth.HashToken(aliceToken), "u2", "login", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if code, status := link(aliceToken, googleCredential(t, key, "g-root", "root@example.com")); code != 409 || status != "google_already_linked" {
		t.Fatalf("stealing another account's identity: %d %s", code, status)
	}
	// Unlinking is allowed because the account keeps its password.
	if w = s.projectDo(projectRequest{method: http.MethodDelete, path: "/api/v1/me/google", bearer: "test-token"}); w.Code != 200 {
		t.Fatalf("unlink: %d %s", w.Code, w.Body.String())
	}
	if got := googleSignIn(s, googleCredential(t, key, "g-root", "root@example.com")); got.Code != 409 || got.Status != "google_link_required" {
		t.Fatalf("after unlink the e-mail must not re-admit the administrator: %+v", got)
	}
}

func TestGoogleOnlyAccountCannotUnlinkItself(t *testing.T) {
	s, key := googleServer(t)
	got := googleSignIn(s, googleCredential(t, key, "g-new", "new@example.com"))
	if got.Code != 200 {
		t.Fatal(got)
	}
	w := s.projectDo(projectRequest{method: http.MethodDelete, path: "/api/v1/me/google", bearer: got.Token})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "google_last_login") {
		t.Fatalf("unlinking the only way in: %d %s", w.Code, w.Body.String())
	}
	if n := identityCount(t, s, `provider_sub='g-new'`); n != 1 {
		t.Fatal("identity vanished")
	}
	// A Google-created account has no usable password.
	var hash string
	_ = s.DB.QueryRow(`SELECT password_hash FROM users WHERE email='new@example.com'`).Scan(&hash)
	if hash != "" {
		t.Fatal("Google-created account has a password hash")
	}
}

func TestGoogleFirstSignInRaceCreatesOneAccount(t *testing.T) {
	s, key := googleServer(t)
	cred := googleCredential(t, key, "g-race", "race@example.com")
	var wg sync.WaitGroup
	results := make([]googleResult, 8)
	for i := range results {
		wg.Add(1)
		go func() { defer wg.Done(); results[i] = googleSignIn(s, cred) }()
	}
	wg.Wait()
	for i, r := range results {
		if r.Code != 200 || r.Token == "" {
			t.Fatalf("concurrent first sign-in %d: %+v", i, r)
		}
	}
	var users int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email='race@example.com'`).Scan(&users)
	if users != 1 || identityCount(t, s, `provider_sub='g-race'`) != 1 {
		t.Fatalf("race produced users=%d identities=%d", users, identityCount(t, s, `provider_sub='g-race'`))
	}
}

func TestGoogleIdentityUniquenessIsEnforcedByTheDatabase(t *testing.T) {
	s, _ := googleServer(t)
	now := time.Now().Unix()
	if _, err := s.DB.Exec(`INSERT INTO user_identities(user_id,provider,provider_sub,created_at) VALUES('u1','google','a',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO user_identities(user_id,provider,provider_sub,created_at) VALUES('u1','google','b',?)`, now); err == nil {
		t.Fatal("one account received two Google identities")
	}
	addUser(t, s, "u2", "alice", "user", "alice@example.com", true, false)
	if _, err := s.DB.Exec(`INSERT INTO user_identities(user_id,provider,provider_sub,created_at) VALUES('u2','google','a',?)`, now); err == nil {
		t.Fatal("one Google identity was bound to two accounts")
	}
}

func TestGoogleSettingsReportTheEffectiveConfigurationSource(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	s := New(d)
	s.BaseURL, s.ProjectURL = "https://mineai.example", "https://mesh.mineai.example"
	get := func() map[string]any {
		w := s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/setup/google", bearer: "test-token"})
		if w.Code != 200 {
			t.Fatalf("get: %d %s", w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	put := func(id string) int {
		return s.projectDo(projectRequest{method: http.MethodPut, path: "/api/v1/setup/google", bearer: "test-token", body: map[string]string{"client_id": id}}).Code
	}
	if got := get(); got["source"] != "none" || got["configured"] != false || got["client_id"] != "" {
		t.Fatalf("unconfigured: %v", got)
	}
	origins, _ := get()["origins"].([]any)
	if len(origins) != 2 || origins[0] != "https://mineai.example" || origins[1] != "https://mesh.mineai.example" {
		t.Fatalf("the Google Cloud origins to authorize must name both surfaces: %v", origins)
	}
	s.GoogleClientID = "env-123.apps.googleusercontent.com"
	if got := get(); got["source"] != "environment" || got["configured"] != true || got["env_set"] != true {
		t.Fatalf("environment: %v", got)
	}
	if put("db_456-x.apps.googleusercontent.com") != 200 {
		t.Fatal("valid id rejected")
	}
	if got := get(); got["source"] != "settings" || got["client_id"] != "db_456-x.apps.googleusercontent.com" {
		t.Fatalf("settings must win over the environment: %v", got)
	}
	for _, bad := range []string{"not-a-client-id", "evil.example.com", "x.apps.googleusercontent.com.evil.com", "<script>.apps.googleusercontent.com"} {
		if put(bad) != 400 {
			t.Errorf("accepted %q", bad)
		}
	}
	// An explicit empty value disables Google even though the environment has one.
	if put("") != 200 {
		t.Fatal("clear")
	}
	if got := get(); got["source"] != "settings" || got["configured"] != false || got["env_set"] != true {
		t.Fatalf("explicit disable: %v", got)
	}
	w := s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/setup/status"})
	if strings.Contains(w.Body.String(), "apps.googleusercontent.com") {
		t.Fatalf("public status must not advertise a disabled client: %s", w.Body.String())
	}
	// Only an administrator may read or change it.
	addUser(t, s, "u2", "alice", "user", "alice@example.com", true, false)
	if _, err := s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,1,?)`,
		meshauth.HashToken("alice-session"), "u2", "login", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if w := s.projectDo(projectRequest{method: m, path: "/api/v1/setup/google", bearer: "alice-session", body: map[string]string{"client_id": ""}}); w.Code != 403 {
			t.Errorf("%s as a member: %d", m, w.Code)
		}
	}
	// New sign-ins see a change immediately: no restart is involved.
	if put("live-789.apps.googleusercontent.com") != 200 {
		t.Fatal("set")
	}
	w = s.projectDo(projectRequest{method: http.MethodGet, path: "/api/v1/setup/status"})
	if !strings.Contains(w.Body.String(), `"google_client_id":"live-789.apps.googleusercontent.com"`) {
		t.Fatalf("status did not follow the saved setting: %s", w.Body.String())
	}
}
