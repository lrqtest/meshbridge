// Package api implements the versioned REST API (/api/v1) + minimal auth middleware.
// All list endpoints paginate; all mutating endpoints require auth; unified error schema.
package api

import (
	"database/sql"
	"encoding/json"
	"net"
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
	"github.com/meshbridge/meshbridge/internal/metrics"
	"github.com/meshbridge/meshbridge/internal/policy"
)

type Server struct {
	DB            *sql.DB
	Mux           *http.ServeMux
	HSURL         string
	HSOK          func() bool
	HS            *headscale.Client
	Mailer        *mailer.Service
	MasterKey     []byte
	BaseURL       string // public base URL, e.g. https://mineai.top
	loginFailures *loginLimiter
}

type ErrBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(ErrBody{Error: msg, Code: errCode})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func New(db *sql.DB) *Server {
	s := &Server{DB: db, Mux: http.NewServeMux(), HSOK: func() bool { return true }, loginFailures: newLoginLimiter()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.Mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.Mux.HandleFunc("/api/v1/me", s.requireAuth(s.handleMe))
	s.Mux.HandleFunc("/api/v1/setup/status", s.handleSetupStatus)
	s.Mux.HandleFunc("/api/v1/setup/initial", s.handleSetupInitial)
	s.Mux.HandleFunc("/api/v1/setup/smtp", s.handleSetupSMTP)
	s.Mux.HandleFunc("/api/v1/setup/smtp/test", s.handleSMTPTest)
	s.Mux.HandleFunc("/api/v1/setup/registration", s.handleSetupRegistration)
	s.Mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.Mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	s.Mux.HandleFunc("/api/v1/auth/send-code", s.handleSendCode)
	s.Mux.HandleFunc("/api/v1/auth/register", s.handleRegister)
	s.Mux.HandleFunc("/api/v1/auth/password-reset", s.handlePasswordReset)
	s.Mux.HandleFunc("/api/v1/devices/enroll", s.handleDeviceEnroll)
	s.Mux.HandleFunc("/api/v1/projects", s.requireAuth(s.handleProjects))
	s.Mux.HandleFunc("/api/v1/devices", s.requireAuth(s.handleDevices))
	s.Mux.HandleFunc("/api/v1/agents/heartbeat", s.handleAgentHeartbeat)
	s.Mux.HandleFunc("/api/v1/transfers", s.requireAuth(s.handleTransfers))
	s.Mux.HandleFunc("/api/v1/relays", s.requireAuth(s.handleRelays))
	s.Mux.HandleFunc("/api/v1/audit", s.requireAuth(s.handleAudit))
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

// clientIP trusts X-Forwarded-For only from loopback (Caddy); otherwise
// RemoteAddr, so a direct attacker cannot spoof its IP through the header.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	return host
}

func pagParams(r *http.Request) (limit, offset int) {
	limit, offset = 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1 {
			offset = (n - 1) * limit
		}
	}
	return limit, offset
}

// requireAuth accepts a Bearer API token (hashed at rest). Tokens with a
// nonzero expires_at in the past are rejected; 0 means non-expiring.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, 401, "unauthorized", "missing bearer token")
			return
		}
		raw := strings.TrimPrefix(h, "Bearer ")
		hash := auth.HashToken(raw)
		var uid string
		var exp int64
		err := s.DB.QueryRow(`SELECT user_id, expires_at FROM api_tokens WHERE token_hash=?`, hash).Scan(&uid, &exp)
		if err != nil {
			writeErr(w, 401, "unauthorized", "bad token")
			return
		}
		if exp != 0 && time.Now().Unix() > exp {
			_, _ = s.DB.Exec(`DELETE FROM api_tokens WHERE token_hash=?`, hash)
			writeErr(w, 401, "unauthorized", "token expired")
			return
		}
		next(w, r)
	}
}

// requireDeviceToken authenticates agents via one-time-issued device tokens.
func (s *Server) requireDeviceToken(next func(w http.ResponseWriter, r *http.Request, deviceID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, 401, "unauthorized", "missing device token")
			return
		}
		hash := auth.HashToken(strings.TrimPrefix(h, "Bearer "))
		var deviceID string
		err := s.DB.QueryRow(`SELECT device_id FROM device_tokens WHERE token_hash=? AND revoked=0`, hash).Scan(&deviceID)
		if err != nil {
			writeErr(w, 401, "unauthorized", "bad device token")
			return
		}
		_, _ = s.DB.Exec(`UPDATE device_tokens SET last_used=? WHERE token_hash=?`, time.Now().Unix(), hash)
		next(w, r, deviceID)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Sweep: agents silent for 3 heartbeat windows are offline.
	_, _ = s.DB.Exec(`UPDATE agents SET online=0 WHERE online=1 AND last_seen < ?`, time.Now().Unix()-120)
	sum := metrics.SummaryFromDB(s.DB)
	hs := "ok"
	if s.HSOK != nil && !s.HSOK() {
		hs = "unreachable"
	}
	writeJSON(w, map[string]any{
		"ok":            hs == "ok",
		"headscale":     hs,
		"agents_online": sum.AgentsOnline,
		"jobs_active":   sum.JobsActive,
		"time":          time.Now().UTC().Format(time.RFC3339),
	})
}

const loginTokenTTL = 24 * time.Hour

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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
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
		auth.DummyVerify(in.Password) // equal Argon2 work: no timing-based username probing
		s.loginFailures.recordFailure(ipKey, time.Now())
		s.loginFailures.recordFailure(userKey, time.Now())
		writeErr(w, 401, "unauthorized", "bad credentials")
		return
	}
	ok, _ := auth.VerifyPassword(phash, in.Password)
	if !ok {
		s.loginFailures.recordFailure(ipKey, time.Now())
		s.loginFailures.recordFailure(userKey, time.Now())
		writeErr(w, 401, "unauthorized", "bad credentials")
		return
	}
	s.loginFailures.reset(ipKey)
	s.loginFailures.reset(userKey)
	raw, _ := auth.RandomToken(32)
	_, _ = s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,?,?)`,
		auth.HashToken(raw), id, "login", time.Now().Unix(), time.Now().Add(loginTokenTTL).Unix())
	_ = audit.Log(r.Context(), s.DB, in.Username, "login", "", "", "", "login ok")
	writeJSON(w, map[string]any{"token": raw, "expires_at": time.Now().Add(loginTokenTTL).Unix()})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "DELETE" {
		writeErr(w, 405, "method", "POST/DELETE only")
		return
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		_, _ = s.DB.Exec(`DELETE FROM api_tokens WHERE token_hash=?`, auth.HashToken(strings.TrimPrefix(h, "Bearer ")))
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
		writeJSON(w, map[string]any{"ok": true, "server_time": now})
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
	switch r.Method {
	case "GET":
		limit, offset := pagParams(r)
		rows, err := s.DB.Query(`SELECT id,name,slug,created_at FROM projects ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
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
		_ = audit.Log(r.Context(), s.DB, "api", "project created", id, "", "", in.Name)
		writeJSON(w, map[string]any{"id": id, "slug": slug})
	default:
		writeErr(w, 405, "method", "unsupported")
	}
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		limit, offset := pagParams(r)
		rows, err := s.DB.Query(`SELECT d.id,d.hostname,d.tailscale_ip,a.online,a.last_seen FROM devices d LEFT JOIN agents a ON a.device_id=d.id ORDER BY d.created_at DESC LIMIT ? OFFSET ?`, limit, offset)
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
		var owner string
		if err := s.DB.QueryRow(`SELECT user_id FROM api_tokens WHERE token_hash=?`, auth.HashToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))).Scan(&owner); err != nil {
			writeErr(w, 401, "unauthorized", "bad token")
			return
		}
		id := auth.HashToken(in.Hostname + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
		if _, err := s.DB.Exec(`INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES(?,?,?,?)`, id, in.Hostname, owner, time.Now().Unix()); err != nil {
			writeErr(w, 500, "db", "insert failed")
			return
		}
		raw, _ := auth.RandomToken(32)
		if _, err := s.DB.Exec(`INSERT INTO device_tokens(token_hash,device_id,created_at) VALUES(?,?,?)`, auth.HashToken(raw), id, time.Now().Unix()); err != nil {
			writeErr(w, 500, "db", "token insert failed")
			return
		}
		_ = audit.Log(r.Context(), s.DB, "api", "device registered", "", id, "", in.Hostname)
		writeJSON(w, map[string]any{"id": id, "hostname": in.Hostname, "agent_token": raw})
	default:
		writeErr(w, 405, "method", "unsupported")
	}
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
	switch r.Method {
	case "GET":
		limit, offset := pagParams(r)
		rows, err := s.DB.Query(`SELECT id,project_id,src_device_id,dst_device_id,state,route_type,bytes_total,bytes_done,error FROM transfer_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
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
