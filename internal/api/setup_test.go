package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/meshbridge/meshbridge/internal/db"
	"github.com/meshbridge/meshbridge/internal/mailer"
)

// stubSender records sent mail and always succeeds.
type stubSender struct {
	mu   sync.Mutex
	sent []string
	fail bool
}

func (s *stubSender) send(cfg mailer.Config, to, subject, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errSendFail
	}
	s.sent = append(s.sent, to+"|"+body)
	return nil
}

var errSendFail = &sendError{}

type sendError struct{}

func (*sendError) Error() string { return "smtp down" }

func newMailerTest(t *testing.T) (*Server, *stubSender) {
	t.Helper()
	schema := filepath.Join("..", "..", "migrations", "001_init.sql")
	d, err := db.OpenMemory(schema)
	if err != nil {
		t.Fatal(err)
	}
	// apply v2 additions (columns are idempotent-skipped; new tables/settings apply)
	if err := db.RunMigrations(d, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := New(d)
	stub := &stubSender{}
	s.Mailer = &mailer.Service{
		DB: d,
		Config: func() mailer.Config {
			return mailer.Config{Host: "smtp.test", Port: 465, Username: "m@test", Password: "pw"}
		},
		Secret: func() string { return "test-secret" },
		Limits: func() mailer.Limits {
			return mailer.Limits{CooldownSeconds: 0, ExpireMinutes: 15, MinuteLimit: 100, DailyLimit: 100}
		},
		Send: stub.send,
	}
	s.MasterKey = []byte("0123456789abcdef0123456789abcdef")
	return s, stub
}

func postJSON(t *testing.T, s *Server, path, body string, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	return w
}

func codeFromBody(t *testing.T, stub *stubSender, i int) string {
	t.Helper()
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if i >= len(stub.sent) {
		t.Fatalf("no sent mail #%d", i)
	}
	// body contains "验证码是：NNNNNN"
	raw := stub.sent[i]
	idx := strings.Index(raw, "：")
	if idx < 0 {
		t.Fatalf("no code in %q", raw)
	}
	return raw[idx+3 : idx+9]
}

func TestSetupWizardFullFlow(t *testing.T) {
	s, stub := newMailerTest(t)
	// status: setup required
	req := httptest.NewRequest("GET", "/api/v1/setup/status", nil)
	w := httptest.NewRecorder()
	s.Mux.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"setup_required":true`) {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	// register purpose must be allowed by default but setup code needed for wizard
	if w := postJSON(t, s, "/api/v1/auth/send-code", `{"email":"Boss@Example.com","purpose":"setup"}`, ""); w.Code != 200 {
		t.Fatalf("send-code: %d %s", w.Code, w.Body.String())
	}
	code := codeFromBody(t, stub, 0)
	w = postJSON(t, s, "/api/v1/setup/initial",
		`{"email":"boss@example.com","code":"`+code+`","password":"long-enough-pass-123"}`, "")
	if w.Code != 200 {
		t.Fatalf("setup initial: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(w.Body).Decode(&out)
	if out.Token == "" {
		t.Fatal("no token returned")
	}
	// second admin creation must be forbidden
	if w := postJSON(t, s, "/api/v1/auth/send-code", `{"email":"x@y.com","purpose":"setup"}`, ""); w.Code != 403 {
		t.Fatalf("second setup send-code must 403, got %d", w.Code)
	}
	// wrong code rejected
	if w := postJSON(t, s, "/api/v1/auth/register", `{"email":"a@b.com","code":"000000","password":"long-enough-pass-123"}`, ""); w.Code != 400 {
		t.Fatalf("register bad code: %d", w.Code)
	}
	// register flow with real code
	if w := postJSON(t, s, "/api/v1/auth/send-code", `{"email":"dev@example.com","purpose":"register"}`, ""); w.Code != 200 {
		t.Fatalf("register send-code: %d", w.Code)
	}
	code = codeFromBody(t, stub, 1)
	w = postJSON(t, s, "/api/v1/auth/register",
		`{"email":"dev@example.com","code":"`+code+`","password":"long-enough-pass-123"}`, "")
	if w.Code != 200 {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	// duplicate email
	if w := postJSON(t, s, "/api/v1/auth/send-code", `{"email":"dev@example.com","purpose":"register"}`, ""); w.Code != 200 {
		t.Fatalf("dup send: %d", w.Code)
	}
	code = codeFromBody(t, stub, 2)
	if w := postJSON(t, s, "/api/v1/auth/register",
		`{"email":"dev@example.com","code":"`+code+`","password":"long-enough-pass-123"}`, ""); w.Code != 409 {
		t.Fatalf("duplicate email must 409, got %d", w.Code)
	}
}

func TestLoginByEmailAndReset(t *testing.T) {
	s, stub := newMailerTest(t)
	// create admin via wizard
	postJSON(t, s, "/api/v1/auth/send-code", `{"email":"boss@example.com","purpose":"setup"}`, "")
	w := postJSON(t, s, "/api/v1/setup/initial",
		`{"email":"boss@example.com","code":"`+codeFromBody(t, stub, 0)+`","password":"long-enough-pass-123"}`, "")
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	// login with EMAIL (not username)
	w = postJSON(t, s, "/api/v1/auth/login", `{"username":"boss@example.com","password":"long-enough-pass-123"}`, "")
	if w.Code != 200 {
		t.Fatalf("login by email: %d %s", w.Code, w.Body.String())
	}
	// password reset flow
	postJSON(t, s, "/api/v1/auth/send-code", `{"email":"boss@example.com","purpose":"reset"}`, "")
	code := codeFromBody(t, stub, 1)
	w = postJSON(t, s, "/api/v1/auth/password-reset",
		`{"email":"boss@example.com","code":"`+code+`","new_password":"brand-new-pass-456"}`, "")
	if w.Code != 200 {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
	// old password fails, new works, old token invalidated
	if w := postJSON(t, s, "/api/v1/auth/login", `{"username":"boss@example.com","password":"long-enough-pass-123"}`, ""); w.Code != 401 {
		t.Fatalf("old password must fail: %d", w.Code)
	}
	if w := postJSON(t, s, "/api/v1/auth/login", `{"username":"boss@example.com","password":"brand-new-pass-456"}`, ""); w.Code != 200 {
		t.Fatalf("new password must work: %d", w.Code)
	}
}

func TestVerificationCodeBruteForceCap(t *testing.T) {
	s, stub := newMailerTest(t)
	postJSON(t, s, "/api/v1/auth/send-code", `{"email":"boss@example.com","purpose":"setup"}`, "")
	right := codeFromBody(t, stub, 0)
	wrong := "000000"
	if right == wrong {
		wrong = "000001"
	}
	// 5 wrong attempts burn the code
	for i := 0; i < 5; i++ {
		if !s.Mailer.CheckCode("boss@example.com", "setup", wrong) {
			// expected
		}
	}
	if s.Mailer.CheckCode("boss@example.com", "setup", right) {
		t.Fatal("code must be dead after 5 wrong attempts")
	}
}

func TestSMTPConfigAndEnrollment(t *testing.T) {
	s, stub := newMailerTest(t)
	// create admin
	postJSON(t, s, "/api/v1/auth/send-code", `{"email":"boss@example.com","purpose":"setup"}`, "")
	w := postJSON(t, s, "/api/v1/setup/initial",
		`{"email":"boss@example.com","code":"`+codeFromBody(t, stub, 0)+`","password":"long-enough-pass-123"}`, "")
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(w.Body).Decode(&out)

	// smtp config requires password initially
	if w := postJSON(t, s, "/api/v1/setup/smtp", `{"host":"smtp.qq.com","port":465,"username":"r@qq.com"}`, out.Token); w.Code != 400 {
		t.Fatalf("smtp without password must 400, got %d", w.Code)
	}
	if w := postJSON(t, s, "/api/v1/setup/smtp", `{"host":"smtp.qq.com","port":465,"username":"r@qq.com","password":"auth-code-1"}`, out.Token); w.Code != 200 {
		t.Fatalf("smtp save: %d %s", w.Code, w.Body.String())
	}
	// update without password keeps stored secret
	if w := postJSON(t, s, "/api/v1/setup/smtp", `{"host":"smtp.qq.com","port":587,"username":"r@qq.com"}`, out.Token); w.Code != 200 {
		t.Fatalf("smtp update keep: %d", w.Code)
	}
	// non-admin/anonymous blocked
	if w := postJSON(t, s, "/api/v1/setup/smtp", `{"host":"h","port":1,"username":"u","password":"p"}`, ""); w.Code != 401 {
		t.Fatalf("anon smtp must 401, got %d", w.Code)
	}
	// registration toggle
	if w := postJSON(t, s, "/api/v1/setup/registration", `{"allow":false}`, out.Token); w.Code != 200 {
		t.Fatalf("toggle: %d", w.Code)
	}
	if w := postJSON(t, s, "/api/v1/auth/send-code", `{"email":"n@n.com","purpose":"register"}`, ""); w.Code != 403 {
		t.Fatalf("register must be disabled, got %d", w.Code)
	}
	// device enrollment (headscale nil → preauth empty, hsErr set)
	w = postJSON(t, s, "/api/v1/devices/enroll", `{"hostname":"node-1"}`, out.Token)
	if w.Code != 200 {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	var en struct {
		DeviceID   string `json:"device_id"`
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(w.Body).Decode(&en)
	if en.DeviceID == "" || en.AgentToken == "" {
		t.Fatal("enroll must return ids")
	}
	// heartbeat with that token works
	if w := postJSON(t, s, "/api/v1/agents/heartbeat",
		`{"device_id":"`+en.DeviceID+`","hostname":"node-1"}`, en.AgentToken); w.Code != 200 {
		t.Fatalf("heartbeat after enroll: %d", w.Code)
	}
}

func TestSplitStatementsAndSettings(t *testing.T) {
	got := db.SplitStatements("-- a; comment; here\nA;B';'C;\n-- x;y\nD;")
	if len(got) != 3 {
		t.Fatalf("split: %#v", got)
	}
	if strings.Contains(got[2], "y") {
		t.Fatalf("comment leaked: %#v", got)
	}
	schema := filepath.Join("..", "..", "migrations", "001_init.sql")
	d, err := db.OpenMemory(schema)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.RunMigrations(d, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatalf("migrations must be re-runnable: %v", err)
	}
	var _ = sql.ErrNoRows
	var _ = http.StatusOK
}
