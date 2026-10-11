package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/meshbridge/meshbridge/internal/audit"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/config"
	"github.com/mineai/kit/httpx"
	"github.com/mineai/kit/sso"
)

// The MeshBridge project is an ordinary client of the platform sign-in that
// this same process hosts. A platform session on the platform origin yields,
// through the authorization-code + PKCE protocol, a separate session on the
// project origin: no cookie is shared between the origins and no token is
// ever placed in a URL. The two origins keep separate localStorage; the only
// thing that crosses is a single-use code the project's own server redeems.
//
// The platform identity store and the MeshBridge user table are the same
// table, so the identity subject is the MeshBridge user id. The platform
// admin role is therefore the MeshBridge admin role by construction; other
// projects never inherit either (they receive an Identity without a role).

// projectSessionName marks api_tokens rows issued from a platform grant. It
// is deliberately not "login": such a session can never act as the parent of
// another SSO authorization, and it is recognisable in audits.
const projectSessionName = "sso:meshbridge"

// EnableProjectSSO wires the project client. It requires the platform SSO
// provider (EnableSSO) because the code exchange happens in-process.
func (s *Server) EnableProjectSSO(dev bool) error {
	if s.SSO == nil || s.ProjectURL == "" {
		return errors.New("project SSO requires the platform SSO provider and a project origin")
	}
	client, err := sso.NewClient(sso.ClientConfig{
		Issuer: s.SSOIssuer, Origin: s.ProjectURL, ClientID: config.ProjectSSOClientID, Dev: dev,
		Exchange: s.SSO.Exchange,
	})
	if err != nil {
		return err
	}
	s.ProjectSSO = client
	return nil
}

func (s *Server) routesProjectSSO() {
	s.Mux.HandleFunc("/api/v1/auth/sso/status", s.handleProjectSSOStatus)
	s.Mux.HandleFunc("/api/v1/auth/sso/start", s.handleProjectSSOStart)
	s.Mux.HandleFunc("/api/v1/auth/sso/complete", s.handleProjectSSOComplete)
	s.Mux.HandleFunc("/api/v1/auth/sso/logout", s.handleProjectSSOLogout)
}

// projectSSORequest accepts only browser POSTs issued by the project origin.
func (s *Server) projectSSORequest(w http.ResponseWriter, r *http.Request) bool {
	ssoHeaders(w)
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method", "POST only")
		return false
	}
	if s.ProjectSSO == nil {
		writeErr(w, http.StatusNotFound, "sso_disabled", "platform sign-in is not enabled for this project")
		return false
	}
	if !s.ProjectSSO.SameOrigin(r) {
		writeErr(w, http.StatusForbidden, "origin", "same-origin request required")
		return false
	}
	return true
}

func (s *Server) handleProjectSSOStatus(w http.ResponseWriter, r *http.Request) {
	ssoHeaders(w)
	w.Header().Set("Vary", "Host")
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	out := map[string]any{"enabled": false, "issuer": "", "session": false}
	if s.ProjectSSO != nil && s.surfaceOf(r).Kind == SurfaceProject {
		out["enabled"], out["issuer"] = true, s.SSOIssuer
		if u, ok := s.authenticateBearer(r); ok && u.ID != "" {
			var grant sql.NullString
			err := s.DB.QueryRowContext(r.Context(), `SELECT grant_hash FROM api_tokens WHERE token_hash=?`,
				auth.HashToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))).Scan(&grant)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				writeErr(w, http.StatusServiceUnavailable, "unavailable", "status temporarily unavailable")
				return
			}
			out["session"] = grant.Valid
		}
	}
	writeJSON(w, out)
}

// newStartLimiter bounds anonymous flow creation per client address: the flow
// store is global and small, so one address must not be able to fill it.
func newStartLimiter() *windowLimiter {
	return &windowLimiter{max: 30, window: time.Minute, seen: map[string]*windowState{}}
}

type windowState struct {
	count int
	reset time.Time
}

type windowLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string]*windowState
}

func (l *windowLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 10000 { // bound memory under key spray
		l.seen = map[string]*windowState{}
	}
	st := l.seen[key]
	if st == nil || !now.Before(st.reset) {
		st = &windowState{reset: now.Add(l.window)}
		l.seen[key] = st
	}
	st.count++
	return st.count <= l.max
}

func (s *Server) handleProjectSSOStart(w http.ResponseWriter, r *http.Request) {
	if !s.projectSSORequest(w, r) {
		return
	}
	if !s.startLimiter.allow(httpx.RateKey(r), time.Now()) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; retry later")
		return
	}
	var in struct {
		Next string `json:"next"`
	}
	if err := httpx.Read(w, r, &in, 2<<10); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	if !sso.SafeNext(in.Next) {
		writeErr(w, http.StatusBadRequest, "bad_request", "next must be a local hash route")
		return
	}
	flow, err := s.ProjectSSO.Start(in.Next)
	if err != nil {
		ssoError(w, err)
		return
	}
	http.SetCookie(w, s.ProjectSSO.Cookie(flow.Cookie))
	writeJSON(w, map[string]string{"authorize_url": flow.AuthorizeURL})
}

func (s *Server) handleProjectSSOComplete(w http.ResponseWriter, r *http.Request) {
	if !s.projectSSORequest(w, r) {
		return
	}
	var in struct {
		Code   string `json:"code"`
		State  string `json:"state"`
		Issuer string `json:"iss"`
	}
	if err := httpx.Read(w, r, &in, 4<<10); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	cookie := ""
	if c, err := r.Cookie(s.ProjectSSO.CookieName()); err == nil {
		cookie = c.Value
	}
	// Redeem before touching the database: the provider takes the only
	// SQLite connection for its own grant transaction.
	grant, next, err := s.ProjectSSO.Complete(r.Context(), cookie, in.State, in.Issuer, in.Code)
	if err != nil {
		ssoError(w, err)
		return
	}
	var username, role, email string
	var disabled int64
	err = s.DB.QueryRowContext(r.Context(), `SELECT username,role,COALESCE(email,''),disabled FROM users WHERE id=?`, grant.Identity.Subject).
		Scan(&username, &role, &email, &disabled)
	if errors.Is(err, sql.ErrNoRows) || err == nil && disabled != 0 {
		s.revokeGrant(r, grant.AccessToken)
		ssoError(w, sso.ErrInvalid)
		return
	}
	if err != nil {
		s.revokeGrant(r, grant.AccessToken)
		writeErr(w, http.StatusServiceUnavailable, "sso_unavailable", "platform SSO temporarily unavailable")
		return
	}
	raw, err := auth.RandomToken(32)
	if err != nil {
		s.revokeGrant(r, grant.AccessToken)
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "login temporarily unavailable")
		return
	}
	now := time.Now()
	expires := now.Add(loginTokenTTL).Unix()
	if grant.Identity.ExpiresAt < expires {
		expires = grant.Identity.ExpiresAt
	}
	if _, err = s.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at,grant_hash) VALUES(?,?,?,?,?,?)`,
		auth.HashToken(raw), grant.Identity.Subject, projectSessionName, now.Unix(), expires, auth.HashToken(grant.AccessToken)); err != nil {
		s.revokeGrant(r, grant.AccessToken)
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "login temporarily unavailable")
		return
	}
	_ = audit.Log(r.Context(), s.DB, username, "login", "", "", "", "platform · "+clientIP(r))
	http.SetCookie(w, s.ProjectSSO.ClearCookie())
	writeJSON(w, map[string]any{
		"token": raw, "expires_at": expires, "next": next, "sso": true,
		"user": map[string]any{"username": username, "role": role, "email": email},
	})
}

// handleProjectSSOLogout ends the project session. The caller then decides
// whether to continue to the platform sign-out (logout_url).
func (s *Server) handleProjectSSOLogout(w http.ResponseWriter, r *http.Request) {
	if !s.projectSSORequest(w, r) {
		return
	}
	if err := s.revokeBearer(r); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "logout temporarily unavailable")
		return
	}
	http.SetCookie(w, s.ProjectSSO.ClearCookie())
	writeJSON(w, map[string]any{"ok": true, "logout_url": s.SSOIssuer + "/#/sso/logout"})
}

// revokeGrant drops a grant that never became a session (or whose session is
// being ended) so it stops counting against the per-session grant budget.
func (s *Server) revokeGrant(r *http.Request, rawGrant string) {
	_, _ = s.DB.ExecContext(r.Context(), `DELETE FROM sso_grants WHERE token_hash=?`, auth.HashToken(rawGrant))
}

// revokeBearer deletes the presented session. A session derived from a
// platform grant also deletes that grant (the cascade removes the session),
// which frees its slot; the platform session itself is left alone.
func (s *Server) revokeBearer(r *http.Request) error {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil
	}
	hash := auth.HashToken(strings.TrimPrefix(h, "Bearer "))
	if _, err := s.DB.ExecContext(r.Context(), `DELETE FROM sso_grants WHERE token_hash=(SELECT grant_hash FROM api_tokens WHERE token_hash=?)`, hash); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(r.Context(), `DELETE FROM api_tokens WHERE token_hash=?`, hash)
	return err
}
