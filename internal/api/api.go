// Package api implements the versioned REST API (/api/v1) + minimal auth middleware.
// All list endpoints paginate; all mutating endpoints require auth; unified error schema.
package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/meshbridge/meshbridge/internal/audit"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/metrics"
)

type Server struct {
	DB     *sql.DB
	Mux    *http.ServeMux
	HSURL  string
	HSOK   func() bool
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
	s := &Server{DB: db, Mux: http.NewServeMux(), HSOK: func() bool { return true }}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.Mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.Mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.Mux.HandleFunc("/api/v1/projects", s.requireAuth(s.handleProjects))
	s.Mux.HandleFunc("/api/v1/devices", s.requireAuth(s.handleDevices))
	s.Mux.HandleFunc("/api/v1/transfers", s.requireAuth(s.handleTransfers))
	s.Mux.HandleFunc("/api/v1/relays", s.requireAuth(s.handleRelays))
	s.Mux.HandleFunc("/api/v1/audit", s.requireAuth(s.handleAudit))
	s.Mux.HandleFunc("/health", s.handleHealth)
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

// requireAuth accepts either session cookie (MVP: Bearer API token).
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
		err := s.DB.QueryRow(`SELECT user_id FROM api_tokens WHERE token_hash=?`, hash).Scan(&uid)
		if err != nil {
			writeErr(w, 401, "unauthorized", "bad token")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method", "POST only")
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
	var id, phash string
	err := s.DB.QueryRow(`SELECT id,password_hash FROM users WHERE username=?`, in.Username).Scan(&id, &phash)
	if err != nil {
		writeErr(w, 401, "unauthorized", "bad credentials")
		return
	}
	ok, _ := auth.VerifyPassword(phash, in.Password)
	if !ok {
		writeErr(w, 401, "unauthorized", "bad credentials")
		return
	}
	raw, _ := auth.RandomToken(32)
	_, _ = s.DB.Exec(`INSERT INTO api_tokens(token_hash,user_id,name,created_at) VALUES(?,?,?,?)`,
		auth.HashToken(raw), id, "login", time.Now().Unix())
	_ = audit.Log(r.Context(), s.DB, in.Username, "login", "", "", "", "login ok")
	writeJSON(w, map[string]any{"token": raw})
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
		slug := slugify(in.Name)
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

func slugify(name string) string {
	s := ""
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			s += string(r)
		case r == ' ' || r == '_' || r == '-':
			s += "-"
		}
	}
	s = strings.Trim(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if s == "" {
		s = "proj"
	}
	return s
}
