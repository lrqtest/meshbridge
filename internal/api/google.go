package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/meshbridge/meshbridge/internal/audit"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/settings"
	kitauth "github.com/mineai/kit/auth"
)

// Google Sign-In is optional and additive: the browser obtains an ID token,
// the server alone decides whether to trust it (signature, issuer, audience,
// expiry, verified e-mail). Identities are keyed by Google's immutable
// subject, never by e-mail alone.
var googleClientIDRe = regexp.MustCompile(`^[0-9A-Za-z_-]+\.apps\.googleusercontent\.com$`)

// googleConfig resolves the effective Web client id and where it came from.
// A persisted empty value is an explicit admin disable and must win over the
// deployment fallback. settings.Get intentionally hides sql.ErrNoRows, so the
// row is queried directly to preserve that distinction. Settings are read per
// request: saving takes effect immediately, while the environment value is
// only read at start-up.
func (s *Server) googleConfig() (id, source string) {
	var v string
	if err := s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, "google_client_id").Scan(&v); err == nil {
		return strings.TrimSpace(v), "settings"
	}
	if env := strings.TrimSpace(s.GoogleClientID); env != "" {
		return env, "environment"
	}
	return "", "none"
}

func (s *Server) googleClientID() string {
	id, _ := s.googleConfig()
	return id
}

// googleRefusal is a sign-in that is understood and declined, as opposed to a
// fault. Each carries its own code so the page can explain what to do next.
type googleRefusal struct {
	status    int
	code, msg string
}

func (e *googleRefusal) write(w http.ResponseWriter) { writeErr(w, e.status, e.code, e.msg) }

var (
	errGoogleNotConfigured = &googleRefusal{http.StatusServiceUnavailable, "google_not_configured", "Google sign-in is not configured on this platform"}
	errGoogleUnavailable   = &googleRefusal{http.StatusServiceUnavailable, "google_unavailable", "Google sign-in is temporarily unavailable"}
	errGoogleInvalid       = &googleRefusal{http.StatusUnauthorized, "google_invalid", "invalid google credential"}
	errGoogleUnverified    = &googleRefusal{http.StatusForbidden, "google_email_unverified", "the Google account's email address is not verified"}
	errAccountDisabled     = &googleRefusal{http.StatusForbidden, "account_disabled", "this account is disabled"}
	errRegistrationClosed  = &googleRefusal{http.StatusForbidden, "registration_closed", "registration is disabled"}
	errGoogleLinkRequired  = &googleRefusal{http.StatusConflict, "google_link_required", "an account with this email already exists; sign in with its password and link Google from Settings"}
	errGoogleLinked        = &googleRefusal{http.StatusConflict, "google_already_linked", "this account or Google identity is already linked"}
	errUnavailable         = &googleRefusal{http.StatusServiceUnavailable, "unavailable", "login temporarily unavailable"}
)

// verifyGoogle turns a browser credential into verified claims, counting only
// real credential failures against the caller's rate budget: a Google outage
// is not the visitor's doing.
func (s *Server) verifyGoogle(ctx context.Context, clientID, credential, key string) (*kitauth.GoogleClaims, *googleRefusal) {
	claims, err := s.Google.VerifyFor(ctx, clientID, strings.TrimSpace(credential))
	switch {
	case err == nil:
	case errors.Is(err, kitauth.ErrGoogleUnavailable):
		return nil, errGoogleUnavailable
	default:
		s.loginFailures.recordFailure(key, time.Now())
		return nil, errGoogleInvalid
	}
	if !claims.EmailVerified || claims.Email == "" {
		return nil, errGoogleUnverified
	}
	return claims, nil
}

func (s *Server) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method", "POST only")
		return
	}
	clientID := s.googleClientID()
	if clientID == "" {
		errGoogleNotConfigured.write(w)
		return
	}
	key := "google:" + clientIP(r)
	if s.loginFailures.blocked(key, time.Now()) {
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; retry later")
		return
	}
	var in struct {
		Credential string `json:"credential"`
	}
	if err := decodeAuthJSON(w, r, &in); err != nil {
		return
	}
	claims, refusal := s.verifyGoogle(r.Context(), clientID, in.Credential, key)
	if refusal != nil {
		refusal.write(w)
		return
	}
	s.loginFailures.reset(key)

	userID, username, refusal := s.googleAccount(r.Context(), claims)
	if refusal != nil {
		if refusal != errUnavailable {
			_ = audit.Log(r.Context(), s.DB, claims.Email, "google sign-in refused", "", "", "", refusal.code)
		}
		refusal.write(w)
		return
	}

	raw, err := auth.RandomToken(32)
	if err != nil {
		errUnavailable.write(w)
		return
	}
	now := time.Now()
	expires := now.Add(loginTokenTTL).Unix()
	if _, err := s.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(token_hash,user_id,name,created_at,expires_at) VALUES(?,?,?,?,?)`,
		auth.HashToken(raw), userID, "login", now.Unix(), expires); err != nil {
		errUnavailable.write(w)
		return
	}
	_ = audit.Log(r.Context(), s.DB, username, "login", "", "", "", "google · "+clientIP(r))
	writeJSON(w, map[string]any{"token": raw, "expires_at": expires})
}

type googleUser struct {
	id, username, role string
	disabled, verified bool
}

// googleAccount maps verified Google claims to a MeshBridge account.
//
//  1. A linked identity always wins and is the only way back into an account.
//  2. Otherwise a verified Google address may claim a same-address account
//     exactly once, and only an ordinary account whose own address was verified
//     (mail code at registration). Administrator accounts and unverified
//     addresses are never absorbed by e-mail: the owner signs in with the
//     password and links Google from Settings instead. A second Google subject
//     presenting an address that is already linked is refused, so a reassigned
//     mailbox cannot inherit an account.
//  3. Otherwise a new ordinary account is created when registration is open.
func (s *Server) googleAccount(ctx context.Context, c *kitauth.GoogleClaims) (id, username string, refusal *googleRefusal) {
	u, err := s.googleUserByIdentity(ctx, c.Sub)
	switch {
	case err == nil:
		if u.disabled {
			return "", "", errAccountDisabled
		}
		return u.id, u.username, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", "", errUnavailable
	}

	u, err = s.googleUserByEmail(ctx, c.Email)
	switch {
	case err == nil:
		if u.disabled {
			return "", "", errAccountDisabled
		}
		if u.role == "admin" || !u.verified {
			return "", "", errGoogleLinkRequired
		}
		switch err := s.linkGoogleIdentity(ctx, u.id, c.Sub); {
		case err == nil:
		case errors.Is(err, errGoogleIdentityTaken):
			return "", "", errGoogleLinked
		default:
			return "", "", errUnavailable
		}
		_ = audit.Log(ctx, s.DB, u.username, "google linked", "", "", "", c.Email)
		return u.id, u.username, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", "", errUnavailable
	}

	if settings.GetDefault(s.DB, "allow_registration", "1") != "1" {
		return "", "", errRegistrationClosed
	}
	id, username, err = s.createGoogleUser(ctx, c.Email, c.Name, c.Sub)
	if err != nil {
		// A concurrent first sign-in with the same subject wins the race;
		// follow its committed identity rather than reporting a conflict.
		if u, ierr := s.googleUserByIdentity(ctx, c.Sub); ierr == nil && !u.disabled {
			return u.id, u.username, nil
		}
		return "", "", &googleRefusal{http.StatusConflict, "conflict", "could not create account"}
	}
	_ = audit.Log(ctx, s.DB, username, "user registered", "", "", "", "google")
	return id, username, nil
}

func (s *Server) googleUserByIdentity(ctx context.Context, sub string) (googleUser, error) {
	var u googleUser
	var off int64
	err := s.DB.QueryRowContext(ctx, `SELECT u.id,u.username,u.role,u.disabled
		FROM user_identities i JOIN users u ON u.id=i.user_id
		WHERE i.provider='google' AND i.provider_sub=?`, sub).Scan(&u.id, &u.username, &u.role, &off)
	u.disabled = off != 0
	return u, err
}

func (s *Server) googleUserByEmail(ctx context.Context, email string) (googleUser, error) {
	var u googleUser
	var off, verified int64
	err := s.DB.QueryRowContext(ctx, `SELECT id,username,role,disabled,email_verified FROM users WHERE email=?`, email).Scan(&u.id, &u.username, &u.role, &off, &verified)
	u.disabled, u.verified = off != 0, verified == 1
	return u, err
}

var errGoogleIdentityTaken = errors.New("google identity already linked")

// linkGoogleIdentity binds a Google subject to a user in one transaction. A
// user holds at most one Google identity and a subject belongs to at most one
// user; either violation reports errGoogleIdentityTaken. A subject that is
// already bound to this very user is success.
func (s *Server) linkGoogleIdentity(ctx context.Context, userID, sub string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner, existing string
	switch err := tx.QueryRowContext(ctx, `SELECT user_id FROM user_identities WHERE provider='google' AND provider_sub=?`, sub).Scan(&owner); {
	case err == nil:
		if owner != userID {
			return errGoogleIdentityTaken
		}
		return tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	switch err := tx.QueryRowContext(ctx, `SELECT provider_sub FROM user_identities WHERE provider='google' AND user_id=?`, userID).Scan(&existing); {
	case err == nil:
		return errGoogleIdentityTaken
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_identities(user_id,provider,provider_sub,created_at) VALUES(?,'google',?,?)`, userID, sub, time.Now().Unix()); err != nil {
		// The unique indexes are the final arbiter between concurrent links.
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return errGoogleIdentityTaken
		}
		return err
	}
	return tx.Commit()
}

func (s *Server) createGoogleUser(ctx context.Context, email, displayName, sub string) (string, string, error) {
	username := sanitizeUsername(s.DB, email, displayName)
	id := auth.HashToken("google:" + sub + ":" + time.Now().String())[:16]
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	// The empty password hash cannot verify: this account signs in with Google,
	// or sets a password through the e-mail reset flow.
	if _, err := tx.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,email,email_verified,created_at)
		VALUES(?,?,?,'user',?,1,?)`, id, username, "", email, time.Now().Unix()); err != nil {
		return "", "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_identities(user_id,provider,provider_sub,created_at)
		VALUES(?,'google',?,?)`, id, sub, time.Now().Unix()); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return id, username, nil
}

// handleGoogleSettings is the administrator view of the Google configuration.
// It reports the effective value, where it comes from and which browser
// origins must be authorized in Google Cloud, so a misconfiguration can be
// diagnosed from the page instead of from the logs.
func (s *Server) handleGoogleSettings(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminToken(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		id, source := s.googleConfig()
		origins := []string{}
		for _, o := range []string{s.BaseURL, s.ProjectURL} {
			if o != "" && !contains(origins, o) {
				origins = append(origins, o)
			}
		}
		writeJSON(w, map[string]any{
			"client_id":  id,
			"configured": id != "",
			"source":     source, // settings | environment | none
			"env_set":    strings.TrimSpace(s.GoogleClientID) != "",
			"origins":    origins,
		})
	case http.MethodPut:
		var in struct {
			ClientID string `json:"client_id"`
		}
		if err := decodeAuthJSON(w, r, &in); err != nil {
			return
		}
		in.ClientID = strings.TrimSpace(in.ClientID)
		if in.ClientID != "" && !googleClientIDRe.MatchString(in.ClientID) {
			writeErr(w, http.StatusBadRequest, "bad_request", "google client id looks wrong")
			return
		}
		if err := settings.Set(s.DB, "google_client_id", in.ClientID); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "unavailable", "could not save Google sign-in settings")
			return
		}
		_ = audit.Log(r.Context(), s.DB, "api", "google sign-in changed", "", "", "", map[bool]string{true: "on", false: "off"}[in.ClientID != ""])
		writeJSON(w, map[string]any{"ok": true, "client_id": in.ClientID})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method", "GET/PUT only")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// handleMeGoogle lets a signed-in user link, inspect or unlink their own
// Google identity. This is the only route by which an administrator account
// gains Google sign-in: it needs the account's own session, never an e-mail
// coincidence.
func (s *Server) handleMeGoogle(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	switch r.Method {
	case http.MethodGet:
		var sub string
		err := s.DB.QueryRowContext(r.Context(), `SELECT provider_sub FROM user_identities WHERE provider='google' AND user_id=?`, u.ID).Scan(&sub)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			errUnavailable.write(w)
			return
		}
		writeJSON(w, map[string]any{"linked": err == nil, "configured": s.googleClientID() != ""})
	case http.MethodPut:
		clientID := s.googleClientID()
		if clientID == "" {
			errGoogleNotConfigured.write(w)
			return
		}
		key := "google-link:" + u.ID
		if s.loginFailures.blocked(key, time.Now()) {
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; retry later")
			return
		}
		var in struct {
			Credential string `json:"credential"`
		}
		if err := decodeAuthJSON(w, r, &in); err != nil {
			return
		}
		claims, refusal := s.verifyGoogle(r.Context(), clientID, in.Credential, key)
		if refusal != nil {
			refusal.write(w)
			return
		}
		switch err := s.linkGoogleIdentity(r.Context(), u.ID, claims.Sub); {
		case err == nil:
		case errors.Is(err, errGoogleIdentityTaken):
			errGoogleLinked.write(w)
			return
		default:
			errUnavailable.write(w)
			return
		}
		var username string
		_ = s.DB.QueryRowContext(r.Context(), `SELECT username FROM users WHERE id=?`, u.ID).Scan(&username)
		_ = audit.Log(r.Context(), s.DB, username, "google linked", "", "", "", "settings")
		writeJSON(w, map[string]any{"ok": true, "linked": true})
	case http.MethodDelete:
		// An account without a password would be locked out of itself.
		var hash string
		if err := s.DB.QueryRowContext(r.Context(), `SELECT password_hash FROM users WHERE id=?`, u.ID).Scan(&hash); err != nil {
			errUnavailable.write(w)
			return
		}
		if hash == "" {
			writeErr(w, http.StatusConflict, "google_last_login", "set a password before unlinking Google")
			return
		}
		res, err := s.DB.ExecContext(r.Context(), `DELETE FROM user_identities WHERE provider='google' AND user_id=?`, u.ID)
		if err != nil {
			errUnavailable.write(w)
			return
		}
		if n, _ := res.RowsAffected(); n > 0 {
			var username string
			_ = s.DB.QueryRowContext(r.Context(), `SELECT username FROM users WHERE id=?`, u.ID).Scan(&username)
			_ = audit.Log(r.Context(), s.DB, username, "google unlinked", "", "", "", "settings")
		}
		writeJSON(w, map[string]any{"ok": true, "linked": false})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method", "GET/PUT/DELETE only")
	}
}
