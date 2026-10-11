package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/mineai/kit/sso"
)

// EnableSSO is called once at startup with trusted deployment configuration.
// Human platform tokens stay private to Mesh; applications receive only a
// client-bound opaque grant and an identity that contains no platform role.
func (s *Server) EnableSSO(issuer string, clients map[string]string, dev bool) error {
	p, err := sso.NewProvider(sso.ProviderConfig{
		DB: s.DB, Issuer: issuer, Clients: clients, Dev: dev,
		Resolve: func(ctx context.Context, parentHash string) (sso.Identity, error) {
			var identity sso.Identity
			var verified, disabled int64
			var name string
			err := s.DB.QueryRowContext(ctx, `SELECT u.id,u.username,COALESCE(u.email,''),u.email_verified,u.disabled,t.name,t.expires_at
    FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`, parentHash).
				Scan(&identity.Subject, &identity.Username, &identity.Email, &verified, &disabled, &name, &identity.ExpiresAt)
			if errors.Is(err, sql.ErrNoRows) {
				return sso.Identity{}, sso.ErrInvalid
			}
			if err != nil {
				return sso.Identity{}, fmt.Errorf("%w: platform session lookup", sso.ErrUnavailable)
			}
			if disabled != 0 || name != "login" || identity.ExpiresAt <= time.Now().Unix() {
				return sso.Identity{}, sso.ErrInvalid
			}
			identity.Issuer = issuer
			identity.EmailVerified = verified == 1 && identity.Email != ""
			return identity, nil
		},
	})
	if err != nil {
		return err
	}
	var foreignKeys int
	if err := s.DB.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		return fmt.Errorf("platform SSO requires SQLite foreign keys")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sso_grants`).Scan(&count); err != nil {
		return fmt.Errorf("platform SSO migration unavailable: %w", err)
	}
	s.SSO = p
	s.SSOIssuer = issuer
	s.SSOClients = make(map[string]string, len(clients))
	for client, callback := range clients {
		s.SSOClients[client] = callback
	}
	return nil
}

func (s *Server) ssoMetadata() map[string]any {
	clients := map[string]string{}
	if s.SSO != nil {
		for id, uri := range s.SSOClients {
			clients[id] = uri
		}
	}
	issuer := ""
	if s.SSO != nil {
		issuer = s.SSOIssuer
	}
	return map[string]any{"enabled": s.SSO != nil, "issuer": issuer, "clients": clients}
}

func (s *Server) routesSSO() {
	s.Mux.HandleFunc("/api/v1/sso/status", s.handleSSOStatus)
	s.Mux.HandleFunc("/api/v1/sso/authorize", s.handleSSOAuthorize)
	s.Mux.HandleFunc("/api/v1/sso/exchange", s.handleSSOExchange)
	s.Mux.HandleFunc("/api/v1/sso/introspect", s.handleSSOIntrospect)
	s.Mux.HandleFunc("/api/v1/sso/revoke", s.handleSSORevoke)
}

func ssoHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Server) handleSSOStatus(w http.ResponseWriter, r *http.Request) {
	ssoHeaders(w)
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method", "GET only")
		return
	}
	writeJSON(w, s.ssoMetadata())
}

func (s *Server) ssoPost(w http.ResponseWriter, r *http.Request, browser bool) bool {
	ssoHeaders(w)
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method", "POST only")
		return false
	}
	if s.SSO == nil {
		writeErr(w, 404, "sso_disabled", "platform SSO is disabled")
		return false
	}
	// Browser authorization must come from the configured console origin.
	// Backchannel endpoints never accept browser-origin requests or enable CORS.
	if browser && r.Header.Get("Origin") != s.SSOIssuer || !browser && r.Header.Get("Origin") != "" {
		writeErr(w, 403, "origin", "origin is not permitted")
		return false
	}
	return true
}

func readSSOJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, 413, "too_large", "request body too large")
		} else {
			writeErr(w, 400, "bad_request", "invalid JSON")
		}
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		writeErr(w, 400, "bad_request", "invalid JSON")
		return false
	}
	if decoder.Decode(new(any)) != io.EOF {
		writeErr(w, 400, "bad_request", "one JSON document required")
		return false
	}
	return true
}

func ssoError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sso.ErrBusy):
		writeErr(w, 503, "sso_busy", "platform SSO capacity reached; retry later")
	case errors.Is(err, sso.ErrUnavailable):
		writeErr(w, 503, "sso_unavailable", "platform SSO temporarily unavailable")
	default:
		writeErr(w, 401, "sso_invalid", "invalid or expired SSO authorization")
	}
}

func (s *Server) handleSSOAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.ssoPost(w, r, true) {
		return
	}
	var in sso.AuthorizeRequest
	if !readSSOJSON(w, r, &in) {
		return
	}
	bearer := r.Header.Get("Authorization")
	if !strings.HasPrefix(bearer, "Bearer ") || len(bearer) > 256 {
		ssoError(w, sso.ErrInvalid)
		return
	}
	code, err := s.SSO.Authorize(r.Context(), auth.HashToken(strings.TrimPrefix(bearer, "Bearer ")), in)
	if err != nil {
		ssoError(w, err)
		return
	}
	callback, _ := url.Parse(s.SSOClients[in.ClientID])
	query := callback.Query()
	query.Set("code", code)
	query.Set("state", in.State)
	query.Set("iss", s.SSOIssuer)
	callback.RawQuery = query.Encode()
	writeJSON(w, map[string]string{"redirect_url": callback.String()})
}

func (s *Server) handleSSOExchange(w http.ResponseWriter, r *http.Request) {
	if !s.ssoPost(w, r, false) {
		return
	}
	var in sso.ExchangeRequest
	if !readSSOJSON(w, r, &in) {
		return
	}
	grant, err := s.SSO.Exchange(r.Context(), in)
	if err != nil {
		ssoError(w, err)
		return
	}
	writeJSON(w, grant)
}

func (s *Server) handleSSOIntrospect(w http.ResponseWriter, r *http.Request) {
	if !s.ssoPost(w, r, false) {
		return
	}
	var in sso.GrantRequest
	if !readSSOJSON(w, r, &in) {
		return
	}
	identity, err := s.SSO.Introspect(r.Context(), in.AccessToken, in.ClientID)
	if err != nil {
		ssoError(w, err)
		return
	}
	writeJSON(w, identity)
}

func (s *Server) handleSSORevoke(w http.ResponseWriter, r *http.Request) {
	if !s.ssoPost(w, r, false) {
		return
	}
	var in sso.GrantRequest
	if !readSSOJSON(w, r, &in) {
		return
	}
	if err := s.SSO.Revoke(r.Context(), in.AccessToken, in.ClientID); err != nil {
		ssoError(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
