// Package api implements the versioned REST API (/api/v1) + minimal auth middleware.
// All list endpoints paginate; all mutating endpoints require auth; unified error schema.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/meshbridge/meshbridge/internal/audit"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/headscale"
	"github.com/meshbridge/meshbridge/internal/mailer"
	"github.com/meshbridge/meshbridge/internal/policy"
	"github.com/meshbridge/meshbridge/internal/tunnel"
	kitauth "github.com/mineai/kit/auth"
	"github.com/mineai/kit/httpx"
	"github.com/mineai/kit/sso"
)

type Server struct {
	DB               *sql.DB
	Mux              *http.ServeMux
	HSURL            string
	HSOK             func() bool
	HSProbe          func(context.Context) bool
	Lifetime         context.Context
	HS               *headscale.Client
	Mailer           *mailer.Service
	MasterKey        []byte
	BaseURL          string // platform origin, e.g. https://mineai.top (the SSO issuer)
	ProjectURL       string // MeshBridge project origin, e.g. https://meshbridge.mineai.top; empty = single surface
	ProjectSSO       *sso.Client
	Gateway          *tunnel.Gateway
	SSO              *sso.Provider
	SSOIssuer        string
	SSOClients       map[string]string
	Google           *kitauth.GoogleVerifier
	GoogleClientID   string // optional deployment fallback; the DB setting wins
	loginFailures    *loginLimiter
	startLimiter     *windowLimiter
	healthMu         sync.Mutex
	healthUntil      time.Time
	healthDone       chan struct{}
	healthSnapshot   map[string]any
	healthGeneration uint64
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	httpx.WriteErr(w, httpx.E(code, errCode, msg))
}

func writeJSON(w http.ResponseWriter, v any) {
	httpx.WriteJSON(w, v)
}

func New(db *sql.DB) *Server {
	s := &Server{DB: db, Mux: http.NewServeMux(), HSOK: func() bool { return true }, loginFailures: newLoginLimiter(), startLimiter: newStartLimiter(), Google: &kitauth.GoogleVerifier{}}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.Mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.Mux.HandleFunc("/api/v1/surface", s.handleSurface)
	s.Mux.HandleFunc("/api/v1/me", s.requireAuth(s.handleMe))
	s.Mux.HandleFunc("/api/v1/me/google", s.requireAuth(s.handleMeGoogle))
	s.Mux.HandleFunc("/api/v1/setup/status", s.handleSetupStatus)
	s.Mux.HandleFunc("/api/v1/setup/initial", s.handleSetupInitial)
	s.Mux.HandleFunc("/api/v1/setup/smtp", s.handleSetupSMTP)
	s.Mux.HandleFunc("/api/v1/setup/smtp/test", s.handleSMTPTest)
	s.Mux.HandleFunc("/api/v1/setup/registration", s.handleSetupRegistration)
	s.Mux.HandleFunc("/api/v1/setup/google", s.handleGoogleSettings)
	s.Mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.Mux.HandleFunc("/api/v1/auth/google", s.handleGoogleLogin)
	s.Mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	s.Mux.HandleFunc("/api/v1/auth/send-code", s.handleSendCode)
	s.Mux.HandleFunc("/api/v1/auth/register", s.handleRegister)
	s.Mux.HandleFunc("/api/v1/auth/password-reset", s.handlePasswordReset)
	s.Mux.HandleFunc("/api/v1/devices/enroll", s.handleDeviceEnroll)
	s.Mux.HandleFunc("/api/v1/devices/{id}", s.requireAuth(s.handleDeviceDelete))
	s.Mux.HandleFunc("/api/v1/projects", s.requireAuth(s.handleProjects))
	s.Mux.HandleFunc("/api/v1/devices", s.requireAuth(s.handleDevices))
	s.Mux.HandleFunc("/api/v1/agents/heartbeat", s.handleAgentHeartbeat)
	s.Mux.HandleFunc("/api/v1/transfers", s.requireAuth(s.handleTransfers))
	s.Mux.HandleFunc("/api/v1/relays", s.requireAuth(s.handleRelays))
	s.Mux.HandleFunc("/api/v1/audit", s.requireAuth(s.handleAudit))
	s.routesSSO()
	s.routesProjectSSO()
	s.routesTunnels()
	s.Mux.HandleFunc("/health", s.handleHealth)
}

// ---- login rate limiting (anti brute force; Argon2 also slows attempts) ----

const (
	loginMaxFailures = 5
	loginWindow      = 15 * time.Minute
)

type loginLimiter struct {
	mu   sync.Mutex
	seen map[string]*failState
}

type failState struct {
	count int
	until time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{seen: make(map[string]*failState)}
}

func (l *loginLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	fs, ok := l.seen[key]
	if !ok {
		return false
	}
	if now.Before(fs.until) {
		return true
	}
	// GC only entries that actually have an expiry set (zero until = counting).
	if !fs.until.IsZero() && now.After(fs.until.Add(loginWindow)) {
		delete(l.seen, key)
	}
	return false
}

func (l *loginLimiter) recordFailure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 10000 { // bound memory under key spray
		l.seen = make(map[string]*failState)
	}
	fs := l.seen[key]
	if fs == nil {
		fs = &failState{}
		l.seen[key] = fs
	}
	fs.count++
	if fs.count >= loginMaxFailures {
		fs.until = now.Add(loginWindow)
		fs.count = 0
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, key)
}

// Use the same trusted local-proxy policy as the app family and tunnel gate.
func clientIP(r *http.Request) string {
	return httpx.ClientIP(r)
}

func pagParams(r *http.Request) (limit, offset int) {
	return httpx.Page(r, 50, 200)
}

// requireAuth accepts a Bearer API token (hashed at rest). Tokens with a
// nonzero expires_at in the past are rejected; 0 means non-expiring. The
// owning account must still be enabled — a disable must take effect on
// already-issued tokens — and the user rides the request context.
type ctxKey int

const userCtxKey ctxKey = 0

type authUser struct {
	ID, Role string
}

func requestUser(r *http.Request) authUser {
	u, _ := r.Context().Value(userCtxKey).(authUser)
	return u
}

// authenticateBearer is the single policy for every human bearer token.
func (s *Server) authenticateBearer(r *http.Request) (authUser, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return authUser{}, false
	}
	var u authUser
	var disabled, exp int64
	err := s.DB.QueryRowContext(r.Context(), `SELECT t.user_id,u.role,u.disabled,t.expires_at
 FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`,
		auth.HashToken(strings.TrimPrefix(h, "Bearer "))).Scan(&u.ID, &u.Role, &disabled, &exp)
	return u, err == nil && disabled == 0 && (exp == 0 || exp > time.Now().Unix())
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.authenticateBearer(r)
		if !ok {
			writeErr(w, 401, "unauthorized", "invalid bearer token")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, u)))
	}
}

// requireDeviceToken authenticates agents via issued device tokens. Revoked
// or expired tokens are dead, and so is every token of a device whose owner
// has been disabled.
func (s *Server) requireDeviceToken(next func(w http.ResponseWriter, r *http.Request, deviceID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, 401, "unauthorized", "missing device token")
			return
		}
		hash := auth.HashToken(strings.TrimPrefix(h, "Bearer "))
		var deviceID string
		err := s.DB.QueryRow(`SELECT dt.device_id FROM device_tokens dt
			JOIN devices d ON d.id=dt.device_id JOIN users u ON u.id=d.owner_user_id
			WHERE dt.token_hash=? AND dt.revoked=0 AND (dt.expires_at=0 OR dt.expires_at>?) AND u.disabled=0`,
			hash, time.Now().Unix()).Scan(&deviceID)
		if err != nil {
			writeErr(w, 401, "unauthorized", "bad device token")
			return
		}
		_, _ = s.DB.Exec(`UPDATE device_tokens SET last_used=? WHERE token_hash=?`, time.Now().Unix(), hash)
		next(w, r, deviceID)
	}
}

// Health snapshots share a synchronous probe: followers wait on one channel,
// and cancelled followers leave promptly. No background goroutine or per-request
// presence write is needed; stale presence is calculated from last_seen.
func (s *Server) health(ctx context.Context) (map[string]any, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.healthMu.Lock()
		if s.healthSnapshot != nil && time.Now().Before(s.healthUntil) {
			out := s.healthSnapshot
			s.healthMu.Unlock()
			return out, nil
		}
		if done := s.healthDone; done != nil {
			s.healthMu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		s.healthDone = make(chan struct{})
		generation := s.healthGeneration
		s.healthMu.Unlock()
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		stopLifetime := func() bool { return false }
		if s.Lifetime != nil {
			stopLifetime = context.AfterFunc(s.Lifetime, cancel)
		}
		dbOK := s.DB.PingContext(probeCtx) == nil
		var online, jobs int
		if dbOK {
			dbOK = s.DB.QueryRowContext(probeCtx, `SELECT COUNT(*) FROM agents WHERE online=1 AND last_seen>=?`, time.Now().Unix()-120).Scan(&online) == nil
			if err := s.DB.QueryRowContext(probeCtx, `SELECT COUNT(*) FROM transfer_jobs WHERE state IN ('QUEUED','PROBING','TRANSFERRING','VERIFYING')`).Scan(&jobs); err != nil {
				dbOK = false
			}
		}
		hs := "ok"
		if (s.HSProbe != nil && !s.HSProbe(probeCtx)) || (s.HSProbe == nil && s.HSOK != nil && !s.HSOK()) {
			hs = "unreachable"
		}
		stopLifetime()
		cancel()
		out := map[string]any{"ok": dbOK && hs == "ok", "headscale": hs, "agents_online": online,
			"jobs_active": jobs, "time": time.Now().UTC().Format(time.RFC3339)}
		s.healthMu.Lock()
		if ctx.Err() == nil && s.healthGeneration == generation {
			s.healthSnapshot = out
			duration := 15 * time.Second
			if !dbOK || hs != "ok" {
				duration = 5 * time.Second // retry outages sooner than healthy probes
			}
			s.healthUntil = time.Now().Add(duration)
		}
		close(s.healthDone)
		s.healthDone = nil
		s.healthMu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	out, err := s.health(r.Context())
	if err != nil {
		writeErr(w, 503, "unavailable", "health probe cancelled")
		return
	}
	// Copy the cached snapshot: meter degradation and shutdown must take
	// effect immediately, without mutating data shared by concurrent callers.
	response := make(map[string]any, len(out)+1)
	for k, v := range out {
		response[k] = v
	}
	meterOK := s.Gateway == nil || s.Gateway.MeterReady()
	response["meter_degraded"] = !meterOK
	ready, _ := out["ok"].(bool)
	ready = ready && meterOK && (s.Lifetime == nil || s.Lifetime.Err() == nil)
	response["ok"] = ready
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	httpx.WriteStatus(w, status, response)
}

const loginTokenTTL = 24 * time.Hour

// deviceTokenTTL bounds an agent's credentials; re-enroll to renew. A leaked
// device token must not be valid forever, and DELETE /api/v1/devices/{id}
// revokes a device's tokens immediately.
const deviceTokenTTL = 90 * 24 * time.Hour

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	ip := clientIP(r)
	ipKey := "ip:" + ip
	if s.loginFailures.blocked(ipKey, time.Now()) {
		writeErr(w, 429, "rate_limited", "too many attempts; retry later")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeAuthJSON(w, r, &in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	userKey := "u:" + strings.ToLower(in.Username)
	if s.loginFailures.blocked(userKey, time.Now()) {
		writeErr(w, 429, "rate_limited", "too many attempts; retry later")
		return
	}
	var id, phash string
	var disabled int64
	err := s.DB.QueryRow(`SELECT id,password_hash,disabled FROM users WHERE username=? OR email=?`,
		in.Username, strings.ToLower(strings.TrimSpace(in.Username))).Scan(&id, &phash, &disabled)
	if err != nil || disabled == 1 {
		if err := auth.DummyVerifyContext(r.Context(), in.Password); err != nil {
			return
		} // equal work
		s.loginFailures.recordFailure(ipKey, time.Now())
		s.loginFailures.recordFailure(userKey, time.Now())
		writeErr(w, 401, "unauthorized", "bad credentials")
		return
	}
	ok, verifyErr := auth.VerifyPasswordContext(r.Context(), phash, in.Password)
	if verifyErr != nil && r.Context().Err() != nil {
		return
	}
	if !ok {
		s.loginFailures.recordFailure(ipKey, time.Now())
		s.loginFailures.recordFailure(userKey, time.Now())
		writeErr(w, 401, "unauthorized", "bad credentials")
		return
	}
	s.loginFailures.reset(ipKey)
	s.loginFailures.reset(userKey)
	raw, err := auth.RandomToken(32)
	if err != nil {
		writeErr(w, 503, "unavailable", "login temporarily unavailable")
		return
	}
	now := time.Now()
	expiry := now.Add(loginTokenTTL).Unix()
	if _, err := s.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,?,?)`, auth.HashToken(raw), id, "login", now.Unix(), expiry); err != nil {
		writeErr(w, 503, "unavailable", "login temporarily unavailable")
		return
	}
	_ = audit.Log(r.Context(), s.DB, in.Username, "login", "", "", "", "login ok")
	writeJSON(w, map[string]any{"token": raw, "expires_at": expiry})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "DELETE" {
		writeErr(w, 405, "method", "POST/DELETE only")
		return
	}
	if err := s.revokeBearer(r); err != nil {
		writeErr(w, 503, "unavailable", "logout temporarily unavailable")
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handleAgentHeartbeat is the agent's only mandatory call: upserts agent
// presence + probe snapshot. Data plane never touches this endpoint.
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
		return
	}
	s.requireDeviceToken(func(w http.ResponseWriter, r *http.Request, tokenDevice string) {
		var in struct {
			DeviceID         string          `json:"device_id"`
			Hostname         string          `json:"hostname"`
			OS               string          `json:"os"`
			Arch             string          `json:"arch"`
			AgentVersion     string          `json:"agent_version"`
			TailscaleVersion string          `json:"tailscale_version"`
			TailscaleIP      string          `json:"tailscale_ip"`
			Probe            json.RawMessage `json:"probe"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
			writeErr(w, 400, "bad_request", "bad json")
			return
		}
		if in.DeviceID != "" && in.DeviceID != tokenDevice {
			writeErr(w, 403, "forbidden", "device_id does not match token")
			return
		}
		now := time.Now().Unix()
		info, _ := json.Marshal(map[string]any{
			"os": in.OS, "arch": in.Arch, "agent_version": in.AgentVersion, "probe": json.RawMessage(orEmptyJSON(in.Probe)),
		})
		_, err := s.DB.Exec(`INSERT INTO agents(device_id,agent_version,tailscale_version,last_seen,online,info_json)
			VALUES(?,?,?,?,1,?)
			ON CONFLICT(device_id) DO UPDATE SET agent_version=excluded.agent_version,
			  tailscale_version=excluded.tailscale_version, last_seen=excluded.last_seen,
			  online=1, info_json=excluded.info_json`,
			tokenDevice, in.AgentVersion, firstLine(in.TailscaleVersion), now, string(info))
		if err != nil {
			writeErr(w, 500, "db", "upsert failed")
			return
		}
		if in.Hostname != "" {
			_, _ = s.DB.Exec(`UPDATE devices SET hostname=? WHERE id=?`, in.Hostname, tokenDevice)
		}
		if in.TailscaleIP != "" {
			_, _ = s.DB.Exec(`UPDATE devices SET tailscale_ip=? WHERE id=?`, in.TailscaleIP, tokenDevice)
		}
		if p := probeClass(in.Probe); p != "" {
			_, _ = s.DB.Exec(`INSERT INTO path_observations(src_device_id,dst_device_id,class,created_at) VALUES(?,'',?,?)`,
				tokenDevice, p, now)
		}
		// Active tunnels for this device: the agent reconciles its outbound
		// connections against this list (config-driven, no agent restart).
		tunnels := []tunnel.AgentConfig{}
		if rows, err := s.DB.Query(`SELECT id,target_scheme,target_host,target_port FROM tunnels WHERE device_id=? AND status='active'`, tokenDevice); err == nil {
			for rows.Next() {
				var t tunnel.AgentConfig
				if rows.Scan(&t.ID, &t.Scheme, &t.Host, &t.Port) == nil {
					tunnels = append(tunnels, t)
				}
			}
			rows.Close()
		}
		writeJSON(w, map[string]any{"ok": true, "server_time": now, "tunnels": tunnels})
	})(w, r)
}

func orEmptyJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func probeClass(raw json.RawMessage) string {
	var p struct {
		Class string `json:"class"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return ""
	}
	switch p.Class {
	case "DIRECT", "PEER_RELAY", "DERP", "UNREACHABLE":
		return p.Class
	}
	return ""
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	me := requestUser(r)
	switch r.Method {
	case "GET":
		limit, offset := pagParams(r)
		where, args := "", []any{}
		if me.Role != "admin" {
			where = ` WHERE p.id IN (SELECT project_id FROM project_memberships WHERE user_id=?)`
			args = append(args, me.ID)
		}
		rows, err := s.DB.Query(`SELECT p.id,p.name,p.slug,p.created_at FROM projects p`+where+` ORDER BY p.created_at DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
		if err != nil {
			writeErr(w, 500, "db", "query failed")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, name, slug string
			var ts int64
			_ = rows.Scan(&id, &name, &slug, &ts)
			out = append(out, map[string]any{"id": id, "name": name, "slug": slug, "created_at": ts})
		}
		writeJSON(w, map[string]any{"items": out, "limit": limit, "offset": offset})
	case "POST":
		var in struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Name == "" {
			writeErr(w, 400, "bad_request", "name required")
			return
		}
		id := auth.HashToken(in.Name + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
		slug := policy.Slugify(in.Name)
		if _, err := s.DB.Exec(`INSERT INTO projects(id,name,slug,created_at) VALUES(?,?,?,?)`, id, in.Name, slug, time.Now().Unix()); err != nil {
			writeErr(w, 409, "conflict", "project exists?")
			return
		}
		// the creator owns the project: membership drives every visibility check
		_, _ = s.DB.Exec(`INSERT OR IGNORE INTO project_memberships(project_id,user_id,role) VALUES(?,?,'owner')`, id, me.ID)
		_ = audit.Log(r.Context(), s.DB, "api", "project created", id, "", "", in.Name)
		writeJSON(w, map[string]any{"id": id, "slug": slug})
	default:
		writeErr(w, 405, "method", "unsupported")
	}
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	me := requestUser(r)
	switch r.Method {
	case "GET":
		limit, offset := pagParams(r)
		// tenants see their own fleet; only admins see every device
		where, args := "", []any{}
		if me.Role != "admin" {
			where = ` WHERE d.owner_user_id=?`
			args = append(args, me.ID)
		}
		rows, err := s.DB.Query(`SELECT d.id,d.hostname,d.tailscale_ip,(a.online=1 AND a.last_seen>=unixepoch()-120),a.last_seen FROM devices d LEFT JOIN agents a ON a.device_id=d.id`+where+` ORDER BY d.created_at DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
		if err != nil {
			writeErr(w, 500, "db", "query failed")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, host string
			var ip sql.NullString
			var online sql.NullInt64
			var seen sql.NullInt64
			_ = rows.Scan(&id, &host, &ip, &online, &seen)
			out = append(out, map[string]any{"id": id, "hostname": host, "tailscale_ip": ip.String, "online": online.Int64 == 1, "last_seen": seen.Int64})
		}
		writeJSON(w, map[string]any{"items": out})
	case "POST":
		// Register a device and mint its one-time agent token (shown once).
		var in struct {
			Hostname string `json:"hostname"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Hostname == "" {
			writeErr(w, 400, "bad_request", "hostname required")
			return
		}
		if len(in.Hostname) > 63 || strings.ContainsAny(in.Hostname, " \t/") {
			writeErr(w, 400, "bad_request", "bad hostname")
			return
		}
		id := auth.HashToken(in.Hostname + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
		if _, err := s.DB.Exec(`INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES(?,?,?,?)`, id, in.Hostname, me.ID, time.Now().Unix()); err != nil {
			writeErr(w, 500, "db", "insert failed")
			return
		}
		raw, _ := auth.RandomToken(32)
		// device tokens age out (re-enroll to renew); revoke via DELETE /devices/{id}
		if _, err := s.DB.Exec(`INSERT INTO device_tokens(token_hash,device_id,created_at,expires_at) VALUES(?,?,?,?)`,
			auth.HashToken(raw), id, time.Now().Unix(), time.Now().Add(deviceTokenTTL).Unix()); err != nil {
			writeErr(w, 500, "db", "token insert failed")
			return
		}
		_ = audit.Log(r.Context(), s.DB, "api", "device registered", "", id, "", in.Hostname)
		writeJSON(w, map[string]any{"id": id, "hostname": in.Hostname, "agent_token": raw, "token_expires_at": time.Now().Add(deviceTokenTTL).Unix()})
	default:
		writeErr(w, 405, "method", "unsupported")
	}
}

// handleDeviceDelete revokes a device: every token dies and the device row is
// removed (agents cascade). Owner or admin.
func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		writeErr(w, 405, "method", "DELETE only")
		return
	}
	me := requestUser(r)
	id := r.PathValue("id")
	var owner string
	if err := s.DB.QueryRow(`SELECT owner_user_id FROM devices WHERE id=?`, id).Scan(&owner); err != nil {
		writeErr(w, 404, "not_found", "no such device")
		return
	}
	if me.Role != "admin" && owner != me.ID {
		writeErr(w, 403, "forbidden", "not your device")
		return
	}
	if _, err := s.DB.Exec(`UPDATE device_tokens SET revoked=1 WHERE device_id=?`, id); err != nil {
		writeErr(w, 500, "db", "revoke failed")
		return
	}
	if _, err := s.DB.Exec(`DELETE FROM devices WHERE id=?`, id); err != nil {
		writeErr(w, 500, "db", "delete failed")
		return
	}
	_ = audit.Log(r.Context(), s.DB, "api", "device revoked", "", id, "", "")
	writeJSON(w, map[string]any{"ok": true})
}

// transferPathOK rejects absolute paths and traversal segments early; the
// authoritative root containment check stays in transfer.SafeJoin on agents.
func transferPathOK(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return false
	}
	if len(p) >= 2 && p[1] == ':' { // windows drive letter
		return false
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." || seg == "" {
			return false
		}
	}
	return true
}

func (s *Server) handleTransfers(w http.ResponseWriter, r *http.Request) {
	me := requestUser(r)
	switch r.Method {
	case "GET":
		limit, offset := pagParams(r)
		// transfer metadata (paths, sizes, devices) stays inside the project:
		// members see their projects' jobs, device owners the jobs touching
		// their machines; admins see everything
		where, args := "", []any{}
		if me.Role != "admin" {
			where = ` WHERE (j.project_id IN (SELECT project_id FROM project_memberships WHERE user_id=?)
				OR j.src_device_id IN (SELECT id FROM devices WHERE owner_user_id=?)
				OR j.dst_device_id IN (SELECT id FROM devices WHERE owner_user_id=?))`
			args = append(args, me.ID, me.ID, me.ID)
		}
		rows, err := s.DB.Query(`SELECT j.id,j.project_id,j.src_device_id,j.dst_device_id,j.state,j.route_type,j.bytes_total,j.bytes_done,j.error FROM transfer_jobs j`+where+` ORDER BY j.created_at DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
		if err != nil {
			writeErr(w, 500, "db", "query failed")
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, pid, src, dst, state, route, errStr string
			var total, done int64
			_ = rows.Scan(&id, &pid, &src, &dst, &state, &route, &total, &done, &errStr)
			out = append(out, map[string]any{"id": id, "project_id": pid, "src": src, "dst": dst, "state": state, "route": route, "bytes_total": total, "bytes_done": done, "error": errStr})
		}
		writeJSON(w, map[string]any{"items": out})
	case "POST":
		var in struct {
			ProjectID string `json:"project_id"`
			Src       string `json:"src_device_id"`
			Dst       string `json:"dst_device_id"`
			SrcPath   string `json:"src_path"`
			DstPath   string `json:"dst_path"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Src == "" || in.Dst == "" {
			writeErr(w, 400, "bad_request", "src/dst required")
			return
		}
		if in.Src == in.Dst {
			writeErr(w, 400, "bad_request", "src and dst device must differ")
			return
		}
		if !transferPathOK(in.SrcPath) || !transferPathOK(in.DstPath) {
			writeErr(w, 400, "bad_request", "paths must be relative and traversal-free (resolved against agent allowed_roots)")
			return
		}
		// The schema requires a project; verify every referenced object before
		// admitting a job so foreign devices cannot be targeted through IDs.
		var srcOwner, dstOwner string
		if err := s.DB.QueryRowContext(r.Context(), `SELECT owner_user_id FROM devices WHERE id=?`, in.Src).Scan(&srcOwner); err != nil {
			writeErr(w, 404, "not_found", "source device not found")
			return
		}
		if err := s.DB.QueryRowContext(r.Context(), `SELECT owner_user_id FROM devices WHERE id=?`, in.Dst).Scan(&dstOwner); err != nil {
			writeErr(w, 404, "not_found", "destination device not found")
			return
		}
		var projectExists int
		if err := s.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM projects WHERE id=?`, in.ProjectID).Scan(&projectExists); err != nil || projectExists == 0 {
			writeErr(w, 404, "not_found", "project not found")
			return
		}
		if me.Role != "admin" {
			var member int
			if err := s.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM project_memberships WHERE project_id=? AND user_id=?`, in.ProjectID, me.ID).Scan(&member); err != nil || member == 0 || srcOwner != me.ID || dstOwner != me.ID {
				writeErr(w, 403, "forbidden", "project membership and device ownership required")
				return
			}
		}
		raw, _ := auth.RandomToken(16)
		id := auth.HashToken(raw + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
		if _, err := s.DB.Exec(`INSERT INTO transfer_jobs(id,project_id,src_device_id,dst_device_id,src_path,dst_path,state,created_at) VALUES(?,?,?,?,?,?,'QUEUED',?)`,
			id, in.ProjectID, in.Src, in.Dst, in.SrcPath, in.DstPath, time.Now().Unix()); err != nil {
			writeErr(w, 500, "db", "insert failed")
			return
		}
		_ = audit.Log(r.Context(), s.DB, "api", "transfer created", in.ProjectID, in.Src, id, in.Dst)
		writeJSON(w, map[string]any{"id": id, "state": "QUEUED"})
	default:
		writeErr(w, 405, "method", "unsupported")
	}
}

func (s *Server) handleRelays(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeErr(w, 405, "method", "GET only")
		return
	}
	rows, err := s.DB.Query(`SELECT id,name,region,udp_port,monthly_quota_bytes,bytes_out_month,healthy,last_seen FROM relay_nodes`)
	if err != nil {
		writeErr(w, 500, "db", "query failed")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, region string
		var port int
		var quota, outm, healthy, seen int64
		_ = rows.Scan(&id, &name, &region, &port, &quota, &outm, &healthy, &seen)
		out = append(out, map[string]any{"id": id, "name": name, "region": region, "udp_port": port, "quota": quota, "bytes_out_month": outm, "healthy": healthy == 1, "last_seen": seen})
	}
	writeJSON(w, map[string]any{"items": out})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeErr(w, 405, "method", "GET only")
		return
	}
	// the audit trail spans every user (entries carry actor e-mail addresses
	// and hostnames): it is admin-only, not part of any tenant's API
	if u := requestUser(r); u.Role != "admin" {
		writeErr(w, 403, "forbidden", "admin only")
		return
	}
	limit, offset := pagParams(r)
	rows, err := s.DB.Query(`SELECT ts,actor,event,project_id,device_id,job_id,detail FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		writeErr(w, 500, "db", "query failed")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ts int64
		var actor, event, pid, did, jid, detail string
		_ = rows.Scan(&ts, &actor, &event, &pid, &did, &jid, &detail)
		out = append(out, map[string]any{"ts": ts, "actor": actor, "event": event, "project_id": pid, "device_id": did, "job_id": jid, "detail": detail})
	}
	writeJSON(w, map[string]any{"items": out})
}
