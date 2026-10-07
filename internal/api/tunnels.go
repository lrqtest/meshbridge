// tunnels.go — tunnel CRUD (admin/owner), the agent WebSocket endpoint and
// the Caddy on-demand-TLS ask endpoint.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/meshbridge/meshbridge/internal/audit"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/settings"
	"github.com/meshbridge/meshbridge/internal/tunnel"
)

func (s *Server) routesTunnels() {
	s.Mux.HandleFunc("GET /api/v1/tunnels", s.requireAuth(s.handleTunnelsList))
	s.Mux.HandleFunc("POST /api/v1/tunnels", s.requireAuth(s.handleTunnelsCreate))
	s.Mux.HandleFunc("GET /api/v1/tunnels/cert-ask", s.handleTunnelCertAsk)
	s.Mux.HandleFunc("GET /api/v1/tunnels/{id}/connect", s.handleTunnelConnect)
	s.Mux.HandleFunc("PATCH /api/v1/tunnels/{id}", s.requireAuth(s.handleTunnelPatch))
	s.Mux.HandleFunc("DELETE /api/v1/tunnels/{id}", s.requireAuth(s.handleTunnelDelete))
	s.Mux.HandleFunc("POST /api/v1/tunnels/{id}/rotate-key", s.requireAuth(s.handleTunnelRotateKey))
	s.Mux.HandleFunc("GET /api/v1/tunnels/settings", s.requireAdmin(s.handleTunnelSettingsGet))
	s.Mux.HandleFunc("PUT /api/v1/tunnels/settings", s.requireAdmin(s.handleTunnelSettingsPut))
}

// requireAdmin gates tunnel-global settings (only admins may flip them).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, role := s.tokenUser(r); role != "admin" {
			writeErr(w, 403, "forbidden", "admin only")
			return
		}
		next(w, r)
	}
}

func tunnelSettingsFromDB(db *sql.DB) map[string]string {
	out := map[string]string{
		"enabled":              "1",
		"global_monthly_bytes": "21474836480",
		"rate_per_min":         "240",
	}
	for k := range out {
		if v, err := settings.Get(db, "tunnels_"+k); err == nil && v != "" {
			out[k] = v
		}
	}
	return out
}

func (s *Server) handleTunnelSettingsGet(w http.ResponseWriter, r *http.Request) {
	if _, role := s.tokenUser(r); role != "admin" {
		writeErr(w, 403, "forbidden", "admin only")
		return
	}
	v := tunnelSettingsFromDB(s.DB)
	enabled := v["enabled"] == "1"
	global, _ := strconv.ParseInt(v["global_monthly_bytes"], 10, 64)
	rate, _ := strconv.Atoi(v["rate_per_min"])
	writeJSON(w, map[string]any{"enabled": enabled, "global_monthly_bytes": global, "rate_per_min": rate})
}

func (s *Server) handleTunnelSettingsPut(w http.ResponseWriter, r *http.Request) {
	if _, role := s.tokenUser(r); role != "admin" {
		writeErr(w, 403, "forbidden", "admin only")
		return
	}
	var in struct {
		Enabled            *bool  `json:"enabled"`
		GlobalMonthlyBytes *int64 `json:"global_monthly_bytes"`
		RatePerMin         *int   `json:"rate_per_min"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	sets := map[string]string{}
	if in.Enabled != nil {
		if *in.Enabled {
			sets["tunnels_enabled"] = "1"
		} else {
			sets["tunnels_enabled"] = "0"
		}
	}
	if in.GlobalMonthlyBytes != nil {
		if *in.GlobalMonthlyBytes < 0 || *in.GlobalMonthlyBytes > 1<<40 {
			writeErr(w, 400, "bad_request", "global budget out of range")
			return
		}
		sets["tunnels_global_monthly_bytes"] = strconv.FormatInt(*in.GlobalMonthlyBytes, 10)
	}
	if in.RatePerMin != nil {
		if *in.RatePerMin < 10 || *in.RatePerMin > 100000 {
			writeErr(w, 400, "bad_request", "rate must be 10..100000")
			return
		}
		sets["tunnels_rate_per_min"] = strconv.Itoa(*in.RatePerMin)
	}
	for k, v := range sets {
		if _, err := s.DB.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v); err != nil {
			writeErr(w, 500, "db", "settings write failed")
			return
		}
	}
	uid, _ := s.tokenUser(r)
	_ = audit.Log(r.Context(), s.DB, uid, "tunnel settings updated", "", "", "", fmt.Sprintf("%d keys", len(sets)))
	s.handleTunnelSettingsGet(w, r)
}

// tunnelView is the API/JSON shape (never exposes the key hash).
type tunnelView struct {
	ID               string `json:"id"`
	DeviceID         string `json:"device_id"`
	DeviceHost       string `json:"device_hostname"`
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	URLPath          string `json:"url_path"`
	URLSubdomain     string `json:"url_subdomain,omitempty"`
	Target           string `json:"target"`
	KeyRequired      bool   `json:"key_required"`
	Status           string `json:"status"`
	Online           bool   `json:"online"`
	StripPrefix      bool   `json:"strip_prefix"`
	Sandbox          bool   `json:"sandbox"`
	MonthlyQuotaByte int64  `json:"monthly_quota_bytes"`
	BytesInMonth     int64  `json:"bytes_in_month"`
	MaxRequestBytes  int64  `json:"max_request_bytes"`
	CreatedAt        int64  `json:"created_at"`
}

func (s *Server) tunnelView(t *tunnel.Tunnel, host string) tunnelView {
	v := tunnelView{
		ID: t.ID, DeviceID: t.DeviceID, DeviceHost: host, Name: t.Name, Slug: t.Slug,
		URLPath:     tunnel.PathPrefix(t.Slug) + "/",
		Target:      t.TargetScheme + "://" + net.JoinHostPort(t.TargetHost, strconv.Itoa(t.TargetPort)),
		KeyRequired: t.KeyRequired, Status: t.Status, StripPrefix: t.StripPrefix, Sandbox: t.Sandbox,
		MonthlyQuotaByte: t.MonthlyQuotaByte, MaxRequestBytes: t.MaxRequestBytes, CreatedAt: t.CreatedAt,
	}
	if s.Gateway != nil {
		v.Online = s.Gateway.Online(t.ID)
		if s.Gateway.BaseDomain() != "" {
			v.URLSubdomain = tunnel.PublicHost(tunnel.SubdomainLabel(t.Slug), s.Gateway.BaseDomain())
		}
	}
	_ = s.DB.QueryRow(`SELECT COALESCE(bytes_in,0)+COALESCE(bytes_out,0) FROM tunnel_usage WHERE tunnel_id=? AND month=?`,
		t.ID, tunnel.MonthKey(time.Now())).Scan(&v.BytesInMonth)
	return v
}

// tokenUser resolves the bearer token to (userID, role). A disabled account
// loses its tokens immediately, and expired tokens are dead.
func (s *Server) tokenUser(r *http.Request) (string, string) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var uid, role string
	var disabled, exp int64
	err := s.DB.QueryRow(`SELECT u.id,u.role,u.disabled,t.expires_at FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`,
		auth.HashToken(raw)).Scan(&uid, &role, &disabled, &exp)
	if err != nil || disabled == 1 || (exp != 0 && time.Now().Unix() > exp) {
		return "", ""
	}
	return uid, role
}

// mayManageDevice: admins manage everything; users only their own devices.
func (s *Server) mayManageDevice(r *http.Request, deviceID string) bool {
	uid, role := s.tokenUser(r)
	if uid == "" {
		return false
	}
	if role == "admin" {
		return true
	}
	var owner string
	if err := s.DB.QueryRow(`SELECT owner_user_id FROM devices WHERE id=?`, deviceID).Scan(&owner); err != nil {
		return false
	}
	return owner == uid
}

func (s *Server) loadTunnel(id string) *tunnel.Tunnel {
	var t tunnel.Tunnel
	var keyReq, strip, sandbox int
	err := s.DB.QueryRow(`SELECT id,device_id,name,slug,target_scheme,target_host,target_port,
		key_required,access_key_hash,status,strip_prefix,sandbox,monthly_quota_bytes,max_request_bytes,created_by,created_at,updated_at
		FROM tunnels WHERE id=?`, id).
		Scan(&t.ID, &t.DeviceID, &t.Name, &t.Slug, &t.TargetScheme, &t.TargetHost, &t.TargetPort,
			&keyReq, &t.AccessKeyHash, &t.Status, &strip, &sandbox, &t.MonthlyQuotaByte, &t.MaxRequestBytes,
			&t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil
	}
	t.KeyRequired = keyReq == 1
	t.StripPrefix = strip == 1
	t.Sandbox = sandbox == 1
	return &t
}

func (s *Server) handleTunnelsList(w http.ResponseWriter, r *http.Request) {
	uid, role := s.tokenUser(r)
	if uid == "" {
		writeErr(w, 401, "unauthorized", "bad token")
		return
	}
	q := `SELECT t.id,t.device_id,t.name,t.slug,t.target_scheme,t.target_host,t.target_port,
		t.key_required,t.access_key_hash,t.status,t.strip_prefix,t.sandbox,t.monthly_quota_bytes,t.max_request_bytes,t.created_by,t.created_at,t.updated_at,d.hostname
		FROM tunnels t JOIN devices d ON d.id=t.device_id`
	args := []any{}
	if role != "admin" {
		q += ` WHERE t.device_id IN (SELECT id FROM devices WHERE owner_user_id=?)`
		args = append(args, uid)
	}
	q += ` ORDER BY t.created_at DESC LIMIT 200`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		writeErr(w, 500, "db", "query failed")
		return
	}
	// Collect rows fully BEFORE building views: tunnelView queries usage,
	// and with MaxOpenConns(1) a query inside the open rows would deadlock.
	type row struct {
		t    tunnel.Tunnel
		host string
	}
	var list []row
	for rows.Next() {
		var r row
		var keyReq, strip, sandbox int
		if err := rows.Scan(&r.t.ID, &r.t.DeviceID, &r.t.Name, &r.t.Slug, &r.t.TargetScheme, &r.t.TargetHost, &r.t.TargetPort,
			&keyReq, &r.t.AccessKeyHash, &r.t.Status, &strip, &sandbox, &r.t.MonthlyQuotaByte, &r.t.MaxRequestBytes,
			&r.t.CreatedBy, &r.t.CreatedAt, &r.t.UpdatedAt, &r.host); err != nil {
			continue
		}
		r.t.KeyRequired = keyReq == 1
		r.t.StripPrefix = strip == 1
		r.t.Sandbox = sandbox == 1
		list = append(list, r)
	}
	rows.Close()
	out := []tunnelView{}
	for _, r := range list {
		out = append(out, s.tunnelView(&r.t, r.host))
	}
	writeJSON(w, map[string]any{"items": out})
}

func (s *Server) handleTunnelsCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceID         string `json:"device_id"`
		Name             string `json:"name"`
		TargetScheme     string `json:"target_scheme"`
		TargetHost       string `json:"target_host"`
		TargetPort       int    `json:"target_port"`
		KeyRequired      *bool  `json:"key_required"`
		StripPrefix      *bool  `json:"strip_prefix"`
		Sandbox          *bool  `json:"sandbox"`
		MonthlyQuotaByte int64  `json:"monthly_quota_bytes"`
		MaxRequestBytes  int64  `json:"max_request_bytes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.DeviceID == "" {
		writeErr(w, 400, "bad_request", "device_id required")
		return
	}
	if !s.mayManageDevice(r, in.DeviceID) {
		writeErr(w, 403, "forbidden", "not your device")
		return
	}
	if in.TargetScheme == "" {
		in.TargetScheme = "http"
	}
	if in.TargetHost == "" {
		in.TargetHost = "127.0.0.1"
	}
	if err := tunnel.TargetOK(in.TargetScheme, in.TargetHost, in.TargetPort); err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	if len(in.Name) > 64 {
		writeErr(w, 400, "bad_request", "name too long")
		return
	}
	if in.MonthlyQuotaByte < 0 || in.MonthlyQuotaByte > 1<<40 {
		writeErr(w, 400, "bad_request", "quota out of range")
		return
	}
	if in.MaxRequestBytes < 0 || in.MaxRequestBytes > 1<<30 {
		writeErr(w, 400, "bad_request", "max request size out of range")
		return
	}
	keyRequired := true
	if in.KeyRequired != nil {
		keyRequired = *in.KeyRequired
	}
	stripPrefix := true
	if in.StripPrefix != nil {
		stripPrefix = *in.StripPrefix
	}
	sandbox := true // default ON: path mode shares the console origin
	if in.Sandbox != nil {
		sandbox = *in.Sandbox
	}
	if in.MonthlyQuotaByte == 0 {
		in.MonthlyQuotaByte = 5 << 30 // 5 GiB default
	}
	if in.MaxRequestBytes == 0 {
		in.MaxRequestBytes = 100 << 20
	}

	uid, _ := s.tokenUser(r)
	id := auth.HashToken(in.DeviceID + strconv.FormatInt(time.Now().UnixNano(), 10))[:16]
	slug := tunnel.NewSlug()
	var accessKey, keyHash string
	if keyRequired {
		accessKey, keyHash = tunnel.NewAccessKey()
	}
	now := time.Now().Unix()
	_, err := s.DB.Exec(`INSERT INTO tunnels(id,device_id,name,slug,target_scheme,target_host,target_port,
		key_required,access_key_hash,status,strip_prefix,sandbox,monthly_quota_bytes,max_request_bytes,created_by,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?)`,
		id, in.DeviceID, in.Name, slug, in.TargetScheme, in.TargetHost, in.TargetPort,
		b2i(keyRequired), keyHash, b2i(stripPrefix), b2i(sandbox), in.MonthlyQuotaByte, in.MaxRequestBytes, uid, now, now)
	if err != nil {
		writeErr(w, 500, "db", "insert failed")
		return
	}
	_ = audit.Log(r.Context(), s.DB, uid, "tunnel created", "", in.DeviceID, id, in.Name+" "+slug[:8])
	v := s.tunnelView(s.loadTunnel(id), deviceHost(s.DB, in.DeviceID))
	if accessKey != "" {
		writeJSON(w, map[string]any{"tunnel": v, "access_key": accessKey})
		return
	}
	writeJSON(w, map[string]any{"tunnel": v})
}

func deviceHost(db *sql.DB, id string) string {
	var h string
	_ = db.QueryRow(`SELECT hostname FROM devices WHERE id=?`, id).Scan(&h)
	return h
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Server) handleTunnelPatch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t := s.loadTunnel(id)
	if t == nil {
		writeErr(w, 404, "not_found", "no such tunnel")
		return
	}
	if !s.mayManageDevice(r, t.DeviceID) {
		writeErr(w, 403, "forbidden", "not your device")
		return
	}
	var in struct {
		Name             *string `json:"name"`
		Status           *string `json:"status"`
		TargetScheme     *string `json:"target_scheme"`
		TargetHost       *string `json:"target_host"`
		TargetPort       *int    `json:"target_port"`
		StripPrefix      *bool   `json:"strip_prefix"`
		Sandbox          *bool   `json:"sandbox"`
		MonthlyQuotaByte *int64  `json:"monthly_quota_bytes"`
		MaxRequestBytes  *int64  `json:"max_request_bytes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "bad_request", "bad json")
		return
	}
	scheme, host, port := t.TargetScheme, t.TargetHost, t.TargetPort
	if in.TargetScheme != nil {
		scheme = *in.TargetScheme
	}
	if in.TargetHost != nil {
		host = *in.TargetHost
	}
	if in.TargetPort != nil {
		port = *in.TargetPort
	}
	if err := tunnel.TargetOK(scheme, host, port); err != nil {
		writeErr(w, 400, "bad_request", err.Error())
		return
	}
	if in.Name != nil && len(*in.Name) > 64 {
		writeErr(w, 400, "bad_request", "name too long")
		return
	}
	if in.MonthlyQuotaByte != nil && (*in.MonthlyQuotaByte < 0 || *in.MonthlyQuotaByte > 1<<40) {
		writeErr(w, 400, "bad_request", "quota out of range")
		return
	}
	if in.MaxRequestBytes != nil && (*in.MaxRequestBytes < 0 || *in.MaxRequestBytes > 1<<30) {
		writeErr(w, 400, "bad_request", "max request size out of range")
		return
	}
	status := t.Status
	if in.Status != nil {
		switch *in.Status {
		case "active", "disabled":
			status = *in.Status
		default:
			writeErr(w, 400, "bad_request", "status must be active or disabled")
			return
		}
	}
	_, err := s.DB.Exec(`UPDATE tunnels SET name=COALESCE(?,name),status=?,target_scheme=?,target_host=?,target_port=?,
		strip_prefix=COALESCE(?,strip_prefix),sandbox=COALESCE(?,sandbox),monthly_quota_bytes=COALESCE(?,monthly_quota_bytes),
		max_request_bytes=COALESCE(?,max_request_bytes),updated_at=? WHERE id=?`,
		nameArg(in.Name), status, scheme, host, port,
		boolArg(in.StripPrefix, t.StripPrefix), boolArg(in.Sandbox, t.Sandbox),
		int64Arg(in.MonthlyQuotaByte, t.MonthlyQuotaByte),
		int64Arg(in.MaxRequestBytes, t.MaxRequestBytes), time.Now().Unix(), id)
	if err != nil {
		writeErr(w, 500, "db", "update failed")
		return
	}
	// Config changed: rebuild the cached proxy bundle from fresh DB state.
	if s.Gateway != nil {
		s.Gateway.ResetProxy(id)
	}
	// Re-enabling resets a quota stop; raising a quota re-arms the warn flag.
	if status == "active" && t.Status != "active" {
		_, _ = s.DB.Exec(`UPDATE tunnel_usage SET warned=0 WHERE tunnel_id=? AND month=?`, id, tunnel.MonthKey(time.Now()))
	}
	if status == "disabled" && s.Gateway != nil {
		s.Gateway.Forget(id)
	}
	uid, _ := s.tokenUser(r)
	_ = audit.Log(r.Context(), s.DB, uid, "tunnel updated", "", t.DeviceID, id, "status="+status)
	writeJSON(w, map[string]any{"tunnel": s.tunnelView(s.loadTunnel(id), deviceHost(s.DB, t.DeviceID))})
}

func nameArg(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func boolArg(v *bool, def bool) any {
	if v == nil {
		return b2i(def)
	}
	return b2i(*v)
}

func int64Arg(v *int64, def int64) any {
	if v == nil {
		return def
	}
	return *v
}

func (s *Server) handleTunnelDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t := s.loadTunnel(id)
	if t == nil {
		writeErr(w, 404, "not_found", "no such tunnel")
		return
	}
	if !s.mayManageDevice(r, t.DeviceID) {
		writeErr(w, 403, "forbidden", "not your device")
		return
	}
	if s.Gateway != nil {
		s.Gateway.Forget(id)
	}
	if _, err := s.DB.Exec(`DELETE FROM tunnels WHERE id=?`, id); err != nil {
		writeErr(w, 500, "db", "delete failed")
		return
	}
	uid, _ := s.tokenUser(r)
	_ = audit.Log(r.Context(), s.DB, uid, "tunnel deleted", "", t.DeviceID, id, t.Name)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleTunnelRotateKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t := s.loadTunnel(id)
	if t == nil {
		writeErr(w, 404, "not_found", "no such tunnel")
		return
	}
	if !s.mayManageDevice(r, t.DeviceID) {
		writeErr(w, 403, "forbidden", "not your device")
		return
	}
	raw, hash := tunnel.NewAccessKey()
	if _, err := s.DB.Exec(`UPDATE tunnels SET access_key_hash=?, key_required=1, updated_at=? WHERE id=?`,
		hash, time.Now().Unix(), id); err != nil {
		writeErr(w, 500, "db", "update failed")
		return
	}
	uid, _ := s.tokenUser(r)
	_ = audit.Log(r.Context(), s.DB, uid, "tunnel key rotated", "", t.DeviceID, id, "")
	writeJSON(w, map[string]any{"access_key": raw})
}

// handleTunnelConnect is the agent's outbound WebSocket endpoint: bearer
// device token → yamux client session handed to the gateway.
func (s *Server) handleTunnelConnect(w http.ResponseWriter, r *http.Request) {
	if s.Gateway == nil {
		writeErr(w, 503, "unavailable", "tunnel gateway not running")
		return
	}
	id := r.PathValue("id")
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
	t := s.loadTunnel(id)
	if t == nil || t.DeviceID != deviceID {
		writeErr(w, 403, "forbidden", "no such tunnel for this device")
		return
	}
	if t.Status != "active" {
		writeErr(w, 403, "forbidden", "tunnel not active")
		return
	}
	// Token auth (not cookies) governs this endpoint; no Origin restriction.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	// The socket must outlive this handler: never tie it to r.Context(),
	// which the server cancels the moment the handler returns. A background
	// ctx + blocking on the session keeps the upgrade alive until the agent
	// disconnects (the gateway's watcher detaches it from the registry).
	netConn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 64
	cfg.KeepAliveInterval = 20 * time.Second
	sess, err := yamux.Client(netConn, cfg)
	if err != nil {
		netConn.Close()
		return
	}
	_, _ = s.DB.Exec(`UPDATE device_tokens SET last_used=? WHERE token_hash=?`, time.Now().Unix(), hash)
	s.Gateway.Attach(t.ID, sess)
	<-sess.CloseChan()
}

// handleTunnelCertAsk answers Caddy's on_demand_tls ask endpoint: 200 only
// for active tunnels' subdomains of the configured base domain. Loopback
// only — Caddy is the sole intended caller.
func (s *Server) handleTunnelCertAsk(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		writeErr(w, 403, "forbidden", "loopback only")
		return
	}
	domain := r.URL.Query().Get("domain")
	if s.Gateway == nil || s.Gateway.BaseDomain() == "" {
		writeErr(w, 404, "not_found", "subdomain mode disabled")
		return
	}
	prefix := tunnel.ParseSubdomainSlug(domain, s.Gateway.BaseDomain())
	if prefix == "" {
		writeErr(w, 404, "not_found", "not a tunnel host")
		return
	}
	var id string
	if err := s.DB.QueryRow(`SELECT id FROM tunnels WHERE slug LIKE ?||'%' AND length(slug)=32 AND status='active'`, prefix).Scan(&id); err != nil {
		writeErr(w, 404, "not_found", "unknown tunnel")
		return
	}
	w.WriteHeader(http.StatusOK)
}
