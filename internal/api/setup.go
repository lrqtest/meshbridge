// Setup wizard, email-verified registration, password reset, SMTP config,
// and device enrollment command generation. Endpoints here are the web
// onboarding surface: the whole control-plane bootstrap is doable from UI.
package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/meshbridge/meshbridge/internal/audit"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/mailer"
	"github.com/meshbridge/meshbridge/internal/secret"
	"github.com/meshbridge/meshbridge/internal/settings"
)

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	var admins int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&admins)
	smtpHost, _ := settings.Get(s.DB, "smtp_host")
	allowReg := settings.GetDefault(s.DB, "allow_registration", "1")
	writeJSON(w, map[string]any{
		"setup_required":     admins == 0,
		"smtp_configured":    smtpHost != "",
		"allow_registration": allowReg == "1",
		"server_time":        time.Now().Unix(),
	})
}

// handleSendCode emails a verification code. Purposes are gated:
// setup → only while no admin exists; register → allow_registration;
// reset → responds OK regardless (no account enumeration), sends only if
// the address belongs to an account.
func (s *Server) handleSendCode(w http.ResponseWriter, r *http.Request) {
	if s.Mailer == nil {
		writeErr(w, 503, "mailer", "email not configured on this server")
		return
	}
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	var in struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))

	switch in.Purpose {
	case "setup":
		var admins int
		_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&admins)
		if admins > 0 {
			writeErr(w, 403, "forbidden", "setup already completed")
			return
		}
	case "register":
		if settings.GetDefault(s.DB, "allow_registration", "1") != "1" {
			writeErr(w, 403, "forbidden", "registration is disabled")
			return
		}
	case "reset":
		var n int
		_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, in.Email).Scan(&n)
		if n == 0 {
			writeJSON(w, map[string]any{"ok": true, "cooldown_seconds": 0})
			return
		}
	default:
		writeErr(w, 400, "bad_request", "purpose must be setup|register|reset")
		return
	}

	cooldown, err := s.Mailer.SendCode(in.Email, in.Purpose)
	if err != nil {
		// Rate limits → 429; delivery/config problems → 502 for visibility.
		msg := err.Error()
		if strings.Contains(msg, "wait") || strings.Contains(msg, "busy") || strings.Contains(msg, "limit reached") {
			writeErr(w, 429, "rate_limited", msg)
			return
		}
		writeErr(w, 502, "mail_send_failed", msg)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "cooldown_seconds": cooldown})
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{1,31}$`)

func sanitizeUsername(db *sql.DB, email, want string) string {
	base := want
	if base == "" {
		local := strings.SplitN(email, "@", 2)[0]
		base = regexp.MustCompile(`[^a-z0-9_.-]+`).ReplaceAllString(strings.ToLower(local), "-")
	}
	base = strings.Trim(base, "-_.")
	if !usernameRe.MatchString(base) {
		base = "user"
	}
	for i := 0; ; i++ {
		cand := base
		if i > 0 {
			cand = fmt.Sprintf("%s-%d", base, i+1)
		}
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM users WHERE username=?`, cand).Scan(&n)
		if n == 0 {
			return cand
		}
	}
}

const minPasswordLen = 12

func passwordOK(p string) bool { return len(p) >= minPasswordLen && len(p) <= 128 }

// handleSetupInitial creates the first admin (email+code+password). Only
// permitted while no admin exists; flips setup_completed.
func (s *Server) handleSetupInitial(w http.ResponseWriter, r *http.Request) {
	if s.Mailer == nil {
		writeErr(w, 503, "mailer", "email not configured on this server")
		return
	}
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	var admins int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&admins)
	if admins > 0 {
		writeErr(w, 403, "forbidden", "setup already completed")
		return
	}
	var in struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	if !passwordOK(in.Password) {
		writeErr(w, 400, "bad_request", fmt.Sprintf("password must be at least %d characters", minPasswordLen))
		return
	}
	if !s.Mailer.CheckCode(in.Email, "setup", in.Code) {
		writeErr(w, 400, "bad_code", "invalid or expired verification code")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	username := sanitizeUsername(s.DB, in.Email, strings.ToLower(strings.TrimSpace(in.Username)))
	id := auth.HashToken(in.Email + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
	if _, err := s.DB.Exec(`INSERT INTO users(id,username,password_hash,role,email,email_verified,created_at)
		VALUES(?,?,?,?,?,1,?)`, id, username, hash, "admin", in.Email, time.Now().Unix()); err != nil {
		writeErr(w, 500, "db", "could not create admin")
		return
	}
	_ = settings.Set(s.DB, "setup_completed", "1")
	_ = audit.Log(r.Context(), s.DB, username, "setup admin created", "", "", "", in.Email)
	raw, _ := auth.RandomToken(32)
	_, _ = s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,?,?)`,
		auth.HashToken(raw), id, "setup", time.Now().Unix(), time.Now().Add(loginTokenTTL).Unix())
	writeJSON(w, map[string]any{"ok": true, "username": username, "token": raw})
}

// handleRegister creates a regular user with email verification.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.Mailer == nil {
		writeErr(w, 503, "mailer", "email not configured on this server")
		return
	}
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	if settings.GetDefault(s.DB, "allow_registration", "1") != "1" {
		writeErr(w, 403, "forbidden", "registration is disabled")
		return
	}
	var in struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	if !passwordOK(in.Password) {
		writeErr(w, 400, "bad_request", fmt.Sprintf("password must be at least %d characters", minPasswordLen))
		return
	}
	var exists int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, in.Email).Scan(&exists)
	if exists > 0 {
		writeErr(w, 409, "conflict", "this email is already registered")
		return
	}
	if !s.Mailer.CheckCode(in.Email, "register", in.Code) {
		writeErr(w, 400, "bad_code", "invalid or expired verification code")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	username := sanitizeUsername(s.DB, in.Email, strings.ToLower(strings.TrimSpace(in.Username)))
	id := auth.HashToken(in.Email + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
	if _, err := s.DB.Exec(`INSERT INTO users(id,username,password_hash,role,email,email_verified,created_at)
		VALUES(?,?,?,'user',?,1,?)`, id, username, hash, in.Email, time.Now().Unix()); err != nil {
		writeErr(w, 500, "db", "could not create user")
		return
	}
	_ = audit.Log(r.Context(), s.DB, username, "user registered", "", "", "", in.Email)
	raw, _ := auth.RandomToken(32)
	_, _ = s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,?,?)`,
		auth.HashToken(raw), id, "login", time.Now().Unix(), time.Now().Add(loginTokenTTL).Unix())
	writeJSON(w, map[string]any{"ok": true, "username": username, "token": raw})
}

// handlePasswordReset consumes a reset code and rotates the password,
// invalidating existing API tokens for that user.
func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if s.Mailer == nil {
		writeErr(w, 503, "mailer", "email not configured on this server")
		return
	}
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	var in struct {
		Email   string `json:"email"`
		Code    string `json:"code"`
		NewPass string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	if !passwordOK(in.NewPass) {
		writeErr(w, 400, "bad_request", fmt.Sprintf("password must be at least %d characters", minPasswordLen))
		return
	}
	var uid string
	err := s.DB.QueryRow(`SELECT id FROM users WHERE email=?`, in.Email).Scan(&uid)
	if err != nil {
		// Do not reveal account existence; burn the code attempt anyway.
		s.Mailer.CheckCode(in.Email, "reset", in.Code)
		writeErr(w, 400, "bad_code", "invalid or expired verification code")
		return
	}
	if !s.Mailer.CheckCode(in.Email, "reset", in.Code) {
		writeErr(w, 400, "bad_code", "invalid or expired verification code")
		return
	}
	hash, err := auth.HashPassword(in.NewPass)
	if err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	if _, err := s.DB.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, uid); err != nil {
		writeErr(w, 500, "db", "update failed")
		return
	}
	_, _ = s.DB.Exec(`DELETE FROM api_tokens WHERE user_id=?`, uid)
	_ = audit.Log(r.Context(), s.DB, in.Email, "password reset", "", "", "", "")
	writeJSON(w, map[string]any{"ok": true})
}

// ---- SMTP configuration (admin) ----

func (s *Server) handleSetupSMTP(w http.ResponseWriter, r *http.Request) {
	if s.Mailer == nil {
		writeErr(w, 503, "mailer", "email not configured on this server")
		return
	}
	switch r.Method {
	case "GET":
		host, _ := settings.Get(s.DB, "smtp_host")
		port, _ := settings.Get(s.DB, "smtp_port")
		user, _ := settings.Get(s.DB, "smtp_username")
		from, _ := settings.Get(s.DB, "smtp_from")
		writeJSON(w, map[string]any{
			"host": host, "port": port, "username": user, "from": from,
			"configured": host != "",
		})
	case "POST":
		if !s.requireAdminToken(w, r) {
			return
		}
		var in struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			From     string `json:"from"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
			writeErr(w, 400, "bad_request", "bad json")
			return
		}
		in.Host = strings.TrimSpace(in.Host)
		if in.Host == "" || in.Port == 0 || in.Username == "" {
			writeErr(w, 400, "bad_request", "host, port and username are required")
			return
		}
		if in.Password == "" {
			// blank password on update keeps the stored secret
			stored, _ := settings.Get(s.DB, "smtp_password_enc")
			if stored == "" {
				writeErr(w, 400, "bad_request", "password required (none stored yet)")
				return
			}
		}
		if in.Port != 465 && in.Port != 587 && in.Port != 25 {
			writeErr(w, 400, "bad_request", "port must be 465, 587 or 25")
			return
		}
		if in.Password != "" {
			enc, err := secret.Encrypt(s.MasterKey, in.Password)
			if err != nil {
				writeErr(w, 500, "encrypt", "could not encrypt password")
				return
			}
			_ = settings.Set(s.DB, "smtp_password_enc", enc)
		}
		_ = settings.Set(s.DB, "smtp_host", in.Host)
		_ = settings.Set(s.DB, "smtp_port", strconv.Itoa(in.Port))
		_ = settings.Set(s.DB, "smtp_username", in.Username)
		_ = settings.Set(s.DB, "smtp_from", strings.TrimSpace(in.From))
		_ = audit.Log(r.Context(), s.DB, "api", "smtp configured", "", "", "", in.Host)
		writeJSON(w, map[string]any{"ok": true})
	default:
		writeErr(w, 405, "method", "GET/POST only")
	}
}

// handleSMTPTest sends a verification email to the authenticated admin's own
// address (or "to" if provided) to confirm delivery works end-to-end.
func (s *Server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminToken(w, r) {
		return
	}
	var in struct {
		To string `json:"to"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10)).Decode(&in)
	if strings.TrimSpace(in.To) == "" {
		var uid string
		hash := auth.HashToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err := s.DB.QueryRow(`SELECT user_id FROM api_tokens WHERE token_hash=?`, hash).Scan(&uid); err != nil {
			writeErr(w, 401, "unauthorized", "bad token")
			return
		}
		_ = s.DB.QueryRow(`SELECT email FROM users WHERE id=?`, uid).Scan(&in.To)
	}
	if !mailer.ValidEmail(strings.TrimSpace(in.To)) {
		writeErr(w, 400, "bad_request", "no valid target address (admin has no email on file)")
		return
	}
	cooldown, err := s.Mailer.SendCode(strings.TrimSpace(strings.ToLower(in.To)), "reset")
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "wait") || strings.Contains(msg, "busy") || strings.Contains(msg, "limit reached") {
			writeErr(w, 429, "rate_limited", msg)
			return
		}
		writeErr(w, 502, "mail_send_failed", msg)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "cooldown_seconds": cooldown})
}

// handleSetupRegistration toggles public registration (admin only).
func (s *Server) handleSetupRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	if !s.requireAdminToken(w, r) {
		return
	}
	var in struct {
		Allow bool `json:"allow"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	v := "0"
	if in.Allow {
		v = "1"
	}
	if err := settings.Set(s.DB, "allow_registration", v); err != nil {
		writeErr(w, 500, "db", "update failed")
		return
	}
	_ = audit.Log(r.Context(), s.DB, "api", "registration toggled", "", "", "", v)
	writeJSON(w, map[string]any{"ok": true, "allow_registration": in.Allow})
}

// requireAdminToken authenticates and asserts role=admin.
func (s *Server) requireAdminToken(w http.ResponseWriter, r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		writeErr(w, 401, "unauthorized", "missing bearer token")
		return false
	}
	var role string
	err := s.DB.QueryRow(`SELECT u.role FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`,
		auth.HashToken(strings.TrimPrefix(h, "Bearer "))).Scan(&role)
	if err != nil {
		writeErr(w, 401, "unauthorized", "bad token")
		return false
	}
	if role != "admin" {
		writeErr(w, 403, "forbidden", "admin only")
		return false
	}
	return true
}

// handleMe returns the authenticated user's profile for the UI.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		writeErr(w, 401, "unauthorized", "missing bearer token")
		return
	}
	var username, role, email string
	err := s.DB.QueryRow(`SELECT u.username, u.role, COALESCE(u.email,'') FROM api_tokens t
		JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`,
		auth.HashToken(strings.TrimPrefix(h, "Bearer "))).Scan(&username, &role, &email)
	if err != nil {
		writeErr(w, 401, "unauthorized", "bad token")
		return
	}
	writeJSON(w, map[string]any{"username": username, "role": role, "email": email})
}

// ---- device enrollment command ----

// handleDeviceEnroll registers a device, creates a headscale preauth key and
// returns copy-paste bootstrap commands for the target machine. The preauth
// key and agent token are shown exactly once.
func (s *Server) handleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	if !s.requireAdminToken(w, r) {
		return
	}
	var in struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil || in.Hostname == "" {
		writeErr(w, 400, "bad_request", "hostname required")
		return
	}
	in.Hostname = strings.ToLower(strings.TrimSpace(in.Hostname))
	if len(in.Hostname) > 63 || strings.ContainsAny(in.Hostname, " \t/") {
		writeErr(w, 400, "bad_request", "bad hostname")
		return
	}
	// register device in our DB first (reuses POST /api/v1/devices logic shape)
	var owner string
	if err := s.DB.QueryRow(`SELECT user_id FROM api_tokens WHERE token_hash=?`,
		auth.HashToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))).Scan(&owner); err != nil {
		writeErr(w, 401, "unauthorized", "bad token")
		return
	}
	id := auth.HashToken(in.Hostname + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
	if _, err := s.DB.Exec(`INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES(?,?,?,?)`,
		id, in.Hostname, owner, time.Now().Unix()); err != nil {
		writeErr(w, 500, "db", "insert failed")
		return
	}
	raw, _ := auth.RandomToken(32)
	if _, err := s.DB.Exec(`INSERT INTO device_tokens(token_hash,device_id,created_at) VALUES(?,?,?)`,
		auth.HashToken(raw), id, time.Now().Unix()); err != nil {
		writeErr(w, 500, "db", "token insert failed")
		return
	}
	// headscale preauth key (best effort: without headscale the agent still
	// heartbeats but mesh routes need the tailnet; surface the error).
	preauth := ""
	hsErr := ""
	if s.HS != nil {
		userID, err := s.HS.CreateUser(r.Context(), "mb-admin")
		if err == nil {
			key, kerr := s.HS.CreatePreAuthKey(r.Context(), userID, true, time.Now().Add(24*time.Hour))
			if kerr == nil {
				preauth = key
			} else {
				hsErr = kerr.Error()
			}
		} else {
			hsErr = err.Error()
		}
	}
	_ = audit.Log(r.Context(), s.DB, "api", "device enrolled", "", id, "", in.Hostname)
	writeJSON(w, map[string]any{
		"device_id":       id,
		"agent_token":     raw,
		"preauth_key":     preauth,
		"headscale_error": hsErr,
	})
}
