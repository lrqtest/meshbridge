// gateway.go — the visitor-facing side of the tunnel feature. Listens on
// loopback only, behind Caddy. One HTTP request from a visitor becomes one
// yamux stream on the agent's live session.
package tunnel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/meshbridge/meshbridge/internal/audit"
)

// GatewayConfig is wired in cmd/meshbridge-server from env + master key.
type GatewayConfig struct {
	DB         *sql.DB
	SSOEnabled bool   // force opaque-origin isolation on every path tunnel
	Secret     []byte // gate-cookie HMAC key (derive from master key)
	BaseURL    string // e.g. https://mineai.top — used for display URLs
	BaseDomain string // e.g. mineai.top — enables subdomain mode ("" = off)
	// HeaderTimeout bounds waiting for upstream response headers AFTER the
	// request body was written (0 → 60s default). Tests shorten it.
	HeaderTimeout time.Duration
}

const (
	maxConcurrentPerTunnel = 16
	maxConcurrentGlobal    = 128
	defaultRatePerMin      = 240
	// Bodies over this are refused even when the per-tunnel cap is higher.
	hardBodyCap = 1 << 30
	// ClientSupplied XFF is trusted only from loopback (Caddy); see ClientIP.
	auditFlapWindow = time.Minute
)

type Gateway struct {
	cfg GatewayConfig
	db  *sql.DB

	headerTimeout time.Duration // resolved from cfg (default 60s)

	mu     sync.RWMutex
	sess   map[string]*yamux.Session
	online map[string]bool // last announced state (audit dedup)
	lastEv map[string]time.Time

	gsem        chan struct{} // global concurrent visitor-request bound
	admissionMu sync.Mutex
	admission   map[string]chan struct{} // only tunnels with active requests
	jobs        map[string]map[*requestMeter]context.CancelFunc
	removing    map[string]int

	keys  *attemptLimiter
	rate  *rateLimiter
	proxy sync.Map // tunnelID -> *tunProxy

	setMu        sync.Mutex
	sets         map[string]setEntry
	setVersion   uint64
	meter        *usageMeter
	meterStart   sync.Once
	meterDone    chan struct{}
	meterCancel  context.CancelFunc
	openMu       sync.Mutex
	pendingOpens map[*yamux.Session]int
	retained     map[*yamux.Session]struct{}
	agentSlots   chan struct{}
	closing      bool
	sessionWG    sync.WaitGroup
	shutdownOnce sync.Once
	shutdownDone chan struct{}
}

type tunProxy struct {
	rp *httputil.ReverseProxy
}

type setEntry struct {
	val string
	exp time.Time
}

// NewGateway never fails; a missing DB shows up as 503s.
func NewGateway(cfg GatewayConfig) *Gateway {
	ht := cfg.HeaderTimeout
	if ht <= 0 {
		ht = responseHeaderTimeout
	}
	g := &Gateway{
		cfg:           cfg,
		headerTimeout: ht,
		db:            cfg.DB,
		sess:          make(map[string]*yamux.Session),
		online:        make(map[string]bool),
		lastEv:        make(map[string]time.Time),
		gsem:          make(chan struct{}, maxConcurrentGlobal),
		admission:     make(map[string]chan struct{}),
		jobs:          make(map[string]map[*requestMeter]context.CancelFunc),
		removing:      make(map[string]int),
		keys:          newAttemptLimiter(KeyAttemptLimit, KeyAttemptWindow),
		rate:          newRateLimiter(),
		sets:          make(map[string]setEntry),
		meter:         newUsageMeter(cfg.DB),
		pendingOpens:  make(map[*yamux.Session]int),
		retained:      make(map[*yamux.Session]struct{}),
		agentSlots:    make(chan struct{}, 32),
		shutdownDone:  make(chan struct{}),
	}
	g.meter.onResult = g.meterResult
	return g
}

// ---- settings (30s cache; reads would otherwise hit SQLite per request) ----

func (g *Gateway) setting(key, def string) string {
	for {
		g.setMu.Lock()
		if e, ok := g.sets[key]; ok && time.Now().Before(e.exp) {
			g.setMu.Unlock()
			return e.val
		}
		version := g.setVersion
		g.setMu.Unlock()
		val := def
		if g.db != nil {
			if v, err := g.getSettingDB(key); err == nil && v != "" {
				val = v
			} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
				g.meter.mu.Lock()
				g.meter.failure = err
				g.meter.mu.Unlock()
			}
		}
		g.setMu.Lock()
		if version != g.setVersion {
			g.setMu.Unlock()
			continue
		}
		g.sets[key] = setEntry{val, time.Now().Add(30 * time.Second)}
		g.setMu.Unlock()
		return val
	}
}

func (g *Gateway) getSettingDB(key string) (string, error) {
	var v string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := g.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	return v, err
}

func (g *Gateway) Enabled() bool { return g.setting("tunnels_enabled", "1") == "1" }

func (g *Gateway) BaseDomain() string { return g.cfg.BaseDomain }

// ---- live agent sessions ----

// Attach registers a fresh agent session, replacing any previous one (an
// agent reconnect races its own dead connection).
func (g *Gateway) Attach(tunnelID string, sess *yamux.Session) {
	// A handshake can complete after PATCH/delete. Serialize its final row
	// validation and registration with the removal guard, so it either gets
	// closed by the drain or is rejected after the row has gone away.
	g.admissionMu.Lock()
	if g.removing[tunnelID] > 0 {
		g.admissionMu.Unlock()
		_ = sess.Close()
		return
	}
	if g.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var active int
		err := g.db.QueryRowContext(ctx, `SELECT 1 FROM tunnels WHERE id=? AND status='active'`, tunnelID).Scan(&active)
		cancel()
		if err != nil {
			g.admissionMu.Unlock()
			_ = sess.Close()
			return
		}
	}
	g.mu.Lock()
	if g.closing || !g.MeterReady() {
		g.mu.Unlock()
		g.admissionMu.Unlock()
		_ = sess.Close()
		return
	}
	if old, ok := g.sess[tunnelID]; ok && old != sess {
		go old.Close()
	}
	g.sess[tunnelID] = sess
	wasOnline := g.online[tunnelID]
	g.online[tunnelID] = true
	last := g.lastEv[tunnelID]
	g.sessionWG.Add(2)
	g.mu.Unlock()
	g.admissionMu.Unlock()
	if !wasOnline || time.Since(last) > auditFlapWindow {
		g.logOnline(tunnelID, true)
	}
	go func() {
		defer g.sessionWG.Done()
		<-sess.CloseChan()
		g.mu.Lock()
		if g.sess[tunnelID] == sess {
			delete(g.sess, tunnelID)
			g.online[tunnelID] = false
		}
		g.mu.Unlock()
		g.logOnline(tunnelID, false)
	}()
	go func() {
		defer g.sessionWG.Done()
		// Agents only accept streams. A peer opening an inbound stream is
		// outside the protocol and cannot retain a backlog on the controller.
		if stream, err := sess.AcceptStream(); err == nil {
			_ = stream.Close()
			_ = sess.Close()
		}
	}()
}

// AcquireAgent counts pending handshakes as well as live/replaced sessions.
func (g *Gateway) AcquireAgent() (func(), bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closing || !g.MeterReady() {
		return nil, false
	}
	select {
	case g.agentSlots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-g.agentSlots }) }, true
	default:
		return nil, false
	}
}

// Open reservations include pending opens and FIN-waiting yamux streams.
// A hostile peer can temporarily saturate capacity until the 30s close timer
// removes its streams; retries cannot allocate another unbounded stream set.
func (g *Gateway) openStream(ctx context.Context, sess *yamux.Session) (*yamux.Stream, error) {
	g.openMu.Lock()
	if sess.IsClosed() {
		g.openMu.Unlock()
		return nil, ErrAgentOffline
	}
	g.retained[sess] = struct{}{}
	total := 0
	for s := range g.retained {
		n := s.NumStreams() + g.pendingOpens[s]
		if s.IsClosed() && g.pendingOpens[s] == 0 {
			delete(g.retained, s)
			continue
		}
		total += n
	}
	if sess.NumStreams()+g.pendingOpens[sess] >= 32 || total >= 128 {
		g.openMu.Unlock()
		return nil, ErrTunnelBusy
	}
	g.pendingOpens[sess]++
	g.openMu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	s, err := sess.OpenStream()
	stop()
	g.openMu.Lock()
	g.pendingOpens[sess]--
	if g.pendingOpens[sess] == 0 {
		delete(g.pendingOpens, sess)
	}
	g.openMu.Unlock()
	if ctx.Err() != nil {
		if s != nil {
			_ = s.Close()
		}
		return nil, ctx.Err()
	}
	return s, err
}

func (g *Gateway) logOnline(tunnelID string, up bool) {
	g.mu.Lock()
	last := g.lastEv[tunnelID]
	if time.Since(last) < auditFlapWindow {
		g.mu.Unlock()
		return // flapping agent: don't flood the audit log
	}
	g.lastEv[tunnelID] = time.Now()
	g.mu.Unlock()
	ev := "tunnel agent offline"
	if up {
		ev = "tunnel agent online"
	}
	detail := "live"
	if !up {
		detail = "disconnected"
	}
	_ = audit.Log(context.Background(), g.db, "agent", ev, "", tunnelID, "", detail)
}

// Kill force-closes the agent session (used on disable/delete).
func (g *Gateway) Kill(tunnelID string) {
	g.cancelJobs(tunnelID)
	g.mu.Lock()
	sess := g.sess[tunnelID]
	delete(g.sess, tunnelID)
	g.online[tunnelID] = false
	g.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
}

func (g *Gateway) session(tunnelID string) *yamux.Session {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.sess[tunnelID]
}

func (g *Gateway) Online(tunnelID string) bool { return g.session(tunnelID) != nil }

func (g *Gateway) OnlineCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.sess)
}

// ---- routing ----

// Handler builds the visitor-facing mux (mounted on a loopback listener).
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/__mb/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ready := g.MeterReady()
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte(`{"ok":` + strconv.FormatBool(ready) + `,"meter_degraded":` + strconv.FormatBool(!ready) + `,"live":` + strconv.Itoa(g.OnlineCount()) + `}`))
	})
	mux.HandleFunc("/t/", g.servePathMode)
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	mux.HandleFunc("/", g.serveHostMode)
	return mux
}

// servePathMode handles /t/<slug>[/<app path...>].
func (g *Gateway) servePathMode(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/t/")
	slug, _, _ := strings.Cut(rest, "/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	t := g.loadBySlug(slug)
	if t == nil {
		g.errorPage(w, r, http.StatusNotFound, "not_found")
		return
	}
	if !t.StripPrefix {
		// App opted to see the full /t/<slug>/... prefix.
		r = r.WithContext(context.WithValue(r.Context(), ctxPathMode{}, true))
		g.serveVisitor(w, r, t, false)
		return
	}
	prefix := PathPrefix(t.Slug)
	if r.URL.Path == prefix {
		// Canonicalize with a trailing slash so relative links resolve inside
		// the tunnel subtree.
		u := *r.URL
		u.Path += "/"
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
		return
	}
	orig := r.URL
	public := orig.RequestURI()
	stripped := *r.URL
	trimPathPrefix(&stripped, prefix)
	r.URL = &stripped
	// Remember the public URI: gate redirects and the form action must point
	// at the visitor-visible path, not the stripped one. Path mode also
	// marks the request for same-origin sandboxing (see proxyFor).
	r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxPublicURI{}, public), ctxPathMode{}, true))
	g.serveVisitor(w, r, t, true)
	r.URL = orig
}

// serveHostMode handles t-<slug12>.<base-domain> (subdomain mode).
func (g *Gateway) serveHostMode(w http.ResponseWriter, r *http.Request) {
	prefix := ParseSubdomainSlug(r.Host, g.cfg.BaseDomain)
	if prefix == "" {
		http.NotFound(w, r)
		return
	}
	t := g.loadBySlugPrefix(prefix)
	if t == nil {
		g.errorPage(w, r, http.StatusNotFound, "not_found")
		return
	}
	g.serveVisitor(w, r, t, false)
}

// trimPathPrefix rewrites u (in place) to the sub-path after prefix, keeping
// escaping intact (%2F etc. must not be re-interpreted).
func trimPathPrefix(u *url.URL, prefix string) {
	ep := u.EscapedPath()
	rest := strings.TrimPrefix(ep, prefix)
	if rest == "" || !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	if p, err := url.PathUnescape(rest); err == nil {
		u.Path = p
		if p != rest {
			u.RawPath = rest
		} else {
			u.RawPath = ""
		}
	} else {
		u.Path, u.RawPath = rest, ""
	}
}

// loadBySlug loads an active-path tunnel row by its full slug.
func (g *Gateway) loadBySlug(slug string) *Tunnel {
	if len(slug) != 32 {
		return nil // cheap pre-filter
	}
	return g.loadTunnel(`SELECT id FROM tunnels WHERE slug=?`, slug)
}

// loadBySlugPrefix resolves the (unique by construction) slug prefix used in
// subdomain mode; ambiguity resolves to nothing.
func (g *Gateway) loadBySlugPrefix(prefix string) *Tunnel {
	return g.loadTunnel(`SELECT id FROM tunnels WHERE slug LIKE ?||'%' AND length(slug)=32`, prefix)
}

func (g *Gateway) loadTunnel(idQuery string, args ...any) *Tunnel {
	if g.db == nil {
		return nil
	}
	var id string
	if err := g.db.QueryRow(idQuery, args...).Scan(&id); err != nil {
		return nil
	}
	return g.loadByID(id)
}

func (g *Gateway) loadByID(id string) *Tunnel {
	var t Tunnel
	var keyReq, strip, sandbox int
	err := g.db.QueryRow(`SELECT id,device_id,name,slug,target_scheme,target_host,target_port,
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

// ---- visitor flow ----

func (g *Gateway) serveVisitor(w http.ResponseWriter, r *http.Request, t *Tunnel, stripped bool) {
	ip := ClientIP(r)
	if !g.rate.allow(ip, g.ratePerMin()) {
		g.errorPage(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if !g.Enabled() {
		g.errorPage(w, r, http.StatusServiceUnavailable, "paused")
		return
	}
	switch t.Status {
	case "disabled":
		g.errorPage(w, r, http.StatusServiceUnavailable, "disabled")
		return
	case "quota_exceeded":
		g.errorPage(w, r, http.StatusServiceUnavailable, "quota")
		return
	}
	if g.globalOverBudget() {
		g.errorPage(w, r, http.StatusServiceUnavailable, "global_quota")
		return
	}
	if !g.gate(w, r, t, ip, stripped) {
		return // gate handled the response
	}
	g.proxyRequest(w, r, t, stripped)
}

func (g *Gateway) ratePerMin() int {
	n, err := strconv.Atoi(g.setting("tunnels_rate_per_min", strconv.Itoa(defaultRatePerMin)))
	if err != nil || n < 10 {
		return defaultRatePerMin
	}
	return n
}

// gate enforces the visitor key. Returns true when the request may proceed.
func (g *Gateway) gate(w http.ResponseWriter, r *http.Request, t *Tunnel, ip string, subdomainMode bool) bool {
	if !t.KeyRequired {
		return true
	}
	if c, err := r.Cookie(GateCookieName); err == nil && VerifyGate(g.cfg.Secret, t.Slug, c.Value, time.Now()) {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		key := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		return g.tryKey(w, r, t, ip, key, false)
	}
	// Form submission of the key (the gate page posts back to itself).
	if r.Method == http.MethodPost {
		ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
		if strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded") {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			key := r.PostFormValue("mb_tunnel_key")
			if key != "" {
				return g.tryKey(w, r, t, ip, key, true)
			}
		}
	}
	g.gatePage(w, r, t, "")
	return false
}

// publicURI returns the visitor-visible URL of the current request: in
// stripped path mode r.URL has already lost its /t/<slug> prefix, so the
// prefix is re-added for redirects and the gate form action.
func publicURI(r *http.Request) string {
	if p, ok := r.Context().Value(ctxPublicURI{}).(string); ok && p != "" {
		return p
	}
	return r.URL.RequestURI()
}

// tryKey checks one candidate key. On success (form mode) it sets the cookie
// and redirects (POST-redirect-GET); Bearer mode is authorized per request.
func (g *Gateway) tryKey(w http.ResponseWriter, r *http.Request, t *Tunnel, ip, key string, formMode bool) bool {
	lk := t.Slug[:8] + "|" + ip
	if g.keys.blocked(lk, time.Now()) {
		g.errorPage(w, r, http.StatusTooManyRequests, "key_limited")
		return false
	}
	if !CheckKey(t.AccessKeyHash, key) {
		g.keys.record(lk)
		if formMode {
			g.gatePage(w, r, t, "wrong")
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="meshbridge-tunnel"`)
			g.errorPage(w, r, http.StatusUnauthorized, "unauthorized")
		}
		return false
	}
	g.keys.reset(lk)
	if !formMode {
		return true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     GateCookieName,
		Value:    SignGate(g.cfg.Secret, t.Slug, time.Now().Add(GateTTL)),
		Path:     g.cookiePath(r, t),
		MaxAge:   int(GateTTL.Seconds()),
		Secure:   forwardedProto(r) == "https" || r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, publicURI(r), http.StatusSeeOther)
	return false
}

// cookiePath scopes the gate cookie to the tunnel subtree in path mode so
// sibling tunnels cannot observe each other's authorization.
func (g *Gateway) cookiePath(r *http.Request, t *Tunnel) string {
	if ParseSubdomainSlug(r.Host, g.cfg.BaseDomain) != "" {
		return "/"
	}
	return PathPrefix(t.Slug)
}

// ---- proxy ----

func (g *Gateway) proxyRequest(w http.ResponseWriter, r *http.Request, t *Tunnel, stripped bool) {
	if g.session(t.ID) == nil {
		g.errorPage(w, r, http.StatusServiceUnavailable, "offline")
		return
	}
	release, ok := g.admitTunnel(t.ID)
	if !ok {
		g.errorPage(w, r, http.StatusServiceUnavailable, "busy")
		return
	}
	defer release()
	// Global bound protects the control VPS from many-tunnel fan-out.
	select {
	case g.gsem <- struct{}{}:
		defer func() { <-g.gsem }()
	default:
		g.errorPage(w, r, http.StatusServiceUnavailable, "busy")
		return
	}

	meter := g.meter.begin(t)
	defer func() { stopped, err := meter.close(); g.meterResult(stopped, err) }()
	requestCtx, cancel := context.WithCancel(r.Context())
	stopReadDeadline := context.AfterFunc(requestCtx, func() {
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
	})
	defer func() { stopReadDeadline(); cancel() }()
	r = r.WithContext(requestCtx)
	g.admissionMu.Lock()
	if g.jobs[t.ID] == nil {
		g.jobs[t.ID] = make(map[*requestMeter]context.CancelFunc)
	}
	g.jobs[t.ID][meter] = cancel
	g.admissionMu.Unlock()
	defer func() {
		g.admissionMu.Lock()
		delete(g.jobs[t.ID], meter)
		if len(g.jobs[t.ID]) == 0 {
			delete(g.jobs, t.ID)
		}
		g.admissionMu.Unlock()
	}()
	limit := t.MaxRequestBytes
	if limit <= 0 || limit > hardBodyCap {
		limit = hardBodyCap
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, &countReader{r: r.Body, meter: meter, ctx: r.Context(), g: g}, limit)
	}
	cw := &countWriter{ResponseWriter: w, meter: meter, ctx: r.Context(), g: g}

	proxy := g.proxyFor(t)
	ctx := context.WithValue(r.Context(), ctxTunnel{}, t)
	ctx = context.WithValue(ctx, ctxStripped{}, stripped)
	if v, ok := r.Context().Value(ctxPathMode{}).(bool); ok {
		ctx = context.WithValue(ctx, ctxPathMode{}, v)
	}
	proxy.ServeHTTP(cw, r.WithContext(ctx))

}

// Admission is held until ReverseProxy finishes the body or bidirectional
// upgrade copy, not merely until response headers arrive. It is independent
// of proxy configuration caches, so PATCH/reset cannot create a second budget.
func (g *Gateway) admitTunnel(id string) (func(), bool) {
	g.admissionMu.Lock()
	if g.removing[id] > 0 {
		g.admissionMu.Unlock()
		return nil, false
	}
	sem := g.admission[id]
	if sem == nil {
		sem = make(chan struct{}, maxConcurrentPerTunnel)
		g.admission[id] = sem
	}
	select {
	case sem <- struct{}{}:
		g.admissionMu.Unlock()
		var once sync.Once
		return func() {
			once.Do(func() {
				g.admissionMu.Lock()
				<-sem
				if len(sem) == 0 {
					delete(g.admission, id)
				}
				g.admissionMu.Unlock()
			})
		}, true
	default:
		g.admissionMu.Unlock()
		return nil, false
	}
}

// Forget drops all runtime state for a tunnel (on delete or disable).
func (g *Gateway) Forget(tunnelID string) {
	g.Kill(tunnelID)
	g.proxy.Delete(tunnelID)
}

// ResetProxy drops the cached proxy bundle so the next request rebuilds it
// from fresh DB state (after config PATCHes; keeps the live agent link).
func (g *Gateway) ResetProxy(tunnelID string) { g.proxy.Delete(tunnelID) }

func (g *Gateway) UpdateQuota(tunnelID string, quota int64) {
	g.meter.mu.Lock()
	if g.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := g.db.QueryRowContext(ctx, `SELECT monthly_quota_bytes FROM tunnels WHERE id=?`, tunnelID).Scan(&quota)
		cancel()
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				g.meter.failure = err
			}
			g.meter.mu.Unlock()
			if !errors.Is(err, sql.ErrNoRows) {
				g.meterResult(nil, ErrMeterUnavailable)
			}
			return
		}
	}
	// PATCH callbacks can arrive in a different order from SQLite commits.
	// Reading under the meter lock makes every callback use the current row.
	for k, e := range g.meter.entries {
		if k.id == tunnelID {
			e.quota = quota
		}
	}
	g.meter.mu.Unlock()
}

// Stop admissions and drain final meter writes before the existing cascading
// delete. Otherwise a late body write would violate the usage foreign key and
// degrade every tunnel after a legitimate owner delete.
func (g *Gateway) PrepareDelete(ctx context.Context, id string) (func(), error) {
	g.admissionMu.Lock()
	g.removing[id]++
	g.admissionMu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			g.admissionMu.Lock()
			g.removing[id]--
			if g.removing[id] == 0 {
				delete(g.removing, id)
			}
			g.admissionMu.Unlock()
		})
	}
	g.Forget(id)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		g.admissionMu.Lock()
		drained := len(g.admission[id]) == 0
		g.admissionMu.Unlock()
		if drained {
			stopped, err := g.meter.flush(ctx)
			g.meterResult(stopped, err)
			if err != nil {
				release()
				return nil, err
			}
			return release, nil
		}
		select {
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

type (
	ctxTunnel    struct{}
	ctxStripped  struct{}
	ctxPublicURI struct{}
	ctxPathMode  struct{} // set when the tunnel is served on the console origin
)

func (g *Gateway) proxyFor(t *Tunnel) *httputil.ReverseProxy {
	if v, ok := g.proxy.Load(t.ID); ok {
		return v.(*tunProxy).rp
	}
	trip := &yamuxTripper{g: g, tun: t}
	rp := &httputil.ReverseProxy{
		Transport:     trip,
		FlushInterval: -1, // SSE / streamed responses flush immediately
		Rewrite:       g.rewrite,
		ModifyResponse: func(resp *http.Response) error {
			rctx := resp.Request.Context()
			current, _ := rctx.Value(ctxTunnel{}).(*Tunnel)
			if pathMode, _ := rctx.Value(ctxPathMode{}).(bool); pathMode && (g.cfg.SSOEnabled || current != nil && current.Sandbox) {
				// Path mode shares the browser origin with the console SPA:
				// any tunneled page could otherwise read the console's
				// localStorage (its API token) and call /api/v1 directly.
				// `CSP: sandbox` (without allow-same-origin) makes the page
				// an opaque origin: no localStorage, no credentialed API
				// calls. Add() keeps the app's own CSP (both then apply).
				resp.Header.Add("Content-Security-Policy",
					"sandbox allow-scripts allow-forms allow-modals allow-popups allow-downloads")
			}
			stripped, _ := rctx.Value(ctxStripped{}).(bool)
			if !stripped {
				return nil
			}
			loc := resp.Header.Get("Location")
			if loc != "" && strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") {
				resp.Header.Set("Location", PathPrefix(t.Slug)+loc)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var maxErr *http.MaxBytesError
			switch {
			case errors.Is(err, ErrAgentOffline):
				g.errorPage(w, r, http.StatusServiceUnavailable, "offline")
			case errors.Is(err, ErrTunnelBusy):
				g.errorPage(w, r, http.StatusServiceUnavailable, "busy")
			case errors.As(err, &maxErr):
				g.errorPage(w, r, http.StatusRequestEntityTooLarge, "too_large")
			default:
				if r.Context().Err() == nil {
					log.Printf("tunnel %s proxy error: %v", t.ID, err)
				}
				g.errorPage(w, r, http.StatusBadGateway, "bad_gateway")
			}
		},
	}
	bundle := &tunProxy{rp: rp}
	actual, _ := g.proxy.LoadOrStore(t.ID, bundle)
	return actual.(*tunProxy).rp
}

// rewrite targets the intranet service and applies header hygiene: inbound
// X-Forwarded-* is dropped and rebuilt from the trusted client IP.
func (g *Gateway) rewrite(pr *httputil.ProxyRequest) {
	t, _ := pr.In.Context().Value(ctxTunnel{}).(*Tunnel)
	if t == nil {
		return
	}
	out := pr.Out
	out.URL.Scheme = t.TargetScheme
	host := t.TargetHost
	if !(t.TargetScheme == "http" && t.TargetPort == 80) && !(t.TargetScheme == "https" && t.TargetPort == 443) {
		host = net.JoinHostPort(t.TargetHost, strconv.Itoa(t.TargetPort))
	}
	out.URL.Host = host
	out.Host = host
	out.Header.Del("X-Forwarded-For")
	out.Header.Del("X-Forwarded-Host")
	out.Header.Del("X-Forwarded-Proto")
	out.Header.Set("X-Forwarded-For", ClientIP(pr.In))
	out.Header.Set("X-Forwarded-Host", pr.In.Host)
	out.Header.Set("X-Forwarded-Proto", forwardedProto(pr.In))
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	ip := net.ParseIP(ClientIP(r))
	if ip != nil && ip.IsLoopback() {
		if p := r.Header.Get("X-Forwarded-Proto"); p == "https" || p == "http" {
			return p
		}
	}
	return "http"
}

// ---- usage accounting + quotas ----

func (g *Gateway) globalBudget() int64 {
	limit, err := strconv.ParseInt(g.setting("tunnels_global_monthly_bytes", "21474836480"), 10, 64)
	if err != nil || limit <= 0 {
		return 0
	}
	return limit
}

func (g *Gateway) globalOverBudget() bool {
	if g.db == nil {
		return false
	}
	limit := g.globalBudget()
	m := g.meter
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failure != nil {
		return true
	}
	month := MonthKey(m.now())
	b := m.months[month]
	if b == nil {
		b = &monthBalance{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes_in+bytes_out),0) FROM tunnel_usage WHERE month=?`, month).Scan(&b.total); err != nil {
			m.failure = err
			return true
		}
		m.months[month] = b
	}
	return limit > 0 && b.total >= limit
}

func (g *Gateway) MeterReady() bool { return g.meter.ready() }

func (g *Gateway) meterResult(stopped []string, err error) {
	if errors.Is(err, ErrMeterUnavailable) || errors.Is(err, ErrGlobalQuota) {
		g.CloseSessions()
		return
	}
	for _, id := range stopped {
		g.proxy.Delete(id)
		g.Kill(id)
	}
}

// StartMeter is owned by the server lifetime. Tests without a background
// lifecycle still flush on threshold/final Close, without leaking goroutines.
func (g *Gateway) StartMeter(ctx context.Context) {
	g.meterStart.Do(func() {
		workerCtx, cancel := context.WithCancel(ctx)
		g.meterCancel = cancel
		g.meterDone = make(chan struct{})
		go func() {
			defer close(g.meterDone)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-workerCtx.Done():
					return
				case <-ticker.C:
					stopped, err := g.meter.flush(workerCtx)
					g.meterResult(stopped, err)
				}
			}
		}()
	})
}

func (g *Gateway) CloseSessions() {
	g.cancelJobs("")
	g.mu.Lock()
	sessions := make([]*yamux.Session, 0, len(g.sess))
	for id, s := range g.sess {
		sessions = append(sessions, s)
		delete(g.sess, id)
		g.online[id] = false
	}
	g.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}

func (g *Gateway) cancelJobs(id string) {
	g.admissionMu.Lock()
	var cancels []context.CancelFunc
	for tunnel, jobs := range g.jobs {
		if id == "" || id == tunnel {
			for _, cancel := range jobs {
				cancels = append(cancels, cancel)
			}
		}
	}
	g.admissionMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (g *Gateway) ShutdownSessions(ctx context.Context) error {
	g.shutdownOnce.Do(func() {
		go func() {
			g.mu.Lock()
			g.closing = true
			g.mu.Unlock()
			g.CloseSessions()
			g.sessionWG.Wait()
			close(g.shutdownDone)
		}()
	})
	select {
	case <-g.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *Gateway) StopMeter(ctx context.Context) error {
	if g.meterCancel != nil {
		g.meterCancel()
		select {
		case <-g.meterDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	stopped, err := g.meter.flush(ctx)
	g.meterResult(stopped, err)
	return err
}

func (g *Gateway) ResetSettings() {
	g.setMu.Lock()
	g.setVersion++
	g.sets = make(map[string]setEntry)
	g.setMu.Unlock()
}

// ---- limiters ----

// attemptLimiter mirrors auth login throttling: N failures inside the window
// block the key until the window passes.
type attemptLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	seen   map[string]*attemptState
}

type attemptState struct {
	count int
	until time.Time
}

func newAttemptLimiter(max int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{max: max, window: window, seen: make(map[string]*attemptState)}
}

func (l *attemptLimiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.seen[key]
	if !ok {
		return false
	}
	return now.Before(s.until)
}

func (l *attemptLimiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 10000 {
		l.seen = make(map[string]*attemptState)
	}
	s := l.seen[key]
	if s == nil {
		s = &attemptState{}
		l.seen[key] = s
	}
	s.count++
	if s.count >= l.max {
		s.until = time.Now().Add(l.window)
		s.count = 0
	}
}

func (l *attemptLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.seen, key)
}

// rateLimiter is a per-IP fixed window (requests per minute).
type rateLimiter struct {
	mu   sync.Mutex
	seen map[string]*rateState
}

type rateState struct {
	min int64 // unix minute
	n   int
}

func newRateLimiter() *rateLimiter { return &rateLimiter{seen: make(map[string]*rateState)} }

func (l *rateLimiter) allow(ip string, perMin int) bool {
	min := time.Now().Unix() / 60
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 20000 { // bound memory under IP spray
		l.seen = make(map[string]*rateState)
	}
	s := l.seen[ip]
	if s == nil || s.min != min {
		s = &rateState{min: min}
		l.seen[ip] = s
	}
	s.n++
	return s.n <= perMin
}

// ---- visitor pages (CSP-safe: no inline style/script; CSS is an asset) ----

var gateTmpl = template.Must(template.New("gate").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">:root{color-scheme:light dark}
*{box-sizing:border-box;margin:0}
body{font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;display:grid;place-items:center;background:#f3f0e8;color:#23281f;padding:24px}
@media(prefers-color-scheme:dark){body{background:#121410;color:#e9e5da}}
.card{max-width:24rem;width:100%;text-align:center}
.mark{font-size:1.6rem;color:#5a6b4f;margin-bottom:.75rem}
h1{font-size:1.35rem;font-weight:600;letter-spacing:-.01em;margin-bottom:.5rem}
.lede{color:inherit;opacity:.75;margin-bottom:1.25rem}
form{display:flex;gap:.5rem;justify-content:center}
.key{flex:1;padding:.65rem .8rem;border:1px solid rgba(35,40,31,.25);border-radius:.6rem;background:rgba(255,255,255,.6);font:inherit}
@media(prefers-color-scheme:dark){.key{background:rgba(255,255,255,.06);border-color:rgba(233,229,218,.2)}}
.key:focus{outline:2px solid #5a6b4f;outline-offset:1px}
button{padding:.65rem 1.1rem;border:0;border-radius:.6rem;background:#4d6142;color:#f6f4ec;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#3f5136}
.wrong{color:#a34d3f;margin-top:.9rem;font-weight:600}
.fine{margin-top:1.5rem;font-size:.8rem;opacity:.55}</style>
</head>
<body>
<main class="card">
<div class="mark" aria-hidden="true">{{.Glyph}}</div>
<h1>{{.Heading}}</h1>
<p class="lede">{{.Lede}}</p>
{{if .ShowForm}}
<form method="post" action="{{.Action}}">
<input class="key" type="password" name="mb_tunnel_key" inputmode="text" autocomplete="off" autofocus aria-label="access key" required>
<button type="submit">Enter</button>
</form>
{{end}}
{{if .Wrong}}<p class="wrong" role="alert">Wrong key, try again.</p>{{end}}
<p class="fine">{{.Fine}}</p>
</main>
</body>
</html>
`))

type gatePageData struct {
	Title, Heading, Lede, Fine, Action string
	ShowForm, Wrong                    bool
	Glyph, Nonce                       string
}

func (g *Gateway) writePage(w http.ResponseWriter, status int, d gatePageData) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("X-Content-Type-Options", "nosniff")
	// Self-contained page: the stylesheet is inlined with a per-response
	// nonce, so the gate renders correctly behind ANY reverse-proxy split
	// (in path mode /t/* reaches the gateway but other paths do not).
	nonceB := make([]byte, 16)
	_, _ = rand.Read(nonceB)
	d.Nonce = base64.RawStdEncoding.EncodeToString(nonceB)
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+d.Nonce+"'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = gateTmpl.Execute(w, d)
}

// pageCopy centralizes visitor-facing copy (EN; the gate is language-neutral).
func pageCopy(kind string) (heading, lede, fine string) {
	switch kind {
	case "wrong":
		return "Protected link", "This link is protected. Enter the access key you were given.", ""
	case "paused":
		return "Tunnels paused", "The administrator has paused public tunnels on this server.", "Please come back later."
	case "disabled":
		return "Tunnel closed", "This tunnel has been disabled by its owner.", ""
	case "quota":
		return "Monthly limit reached", "This tunnel reached its monthly traffic limit.", "The owner can raise the quota or manually re-enable it in a new month."
	case "global_quota":
		return "Server limit reached", "All tunnels on this server reached the shared monthly traffic limit.", "Please come back later."
	case "offline":
		return "Device offline", "The device sharing this link is not connected right now.", "Try again in a moment."
	case "busy":
		return "Too many requests", "This tunnel is serving too many requests at once.", ""
	case "too_large":
		return "Request too large", "The request body exceeds this tunnel's size limit.", ""
	case "rate_limited":
		return "Slow down", "Too many requests from your address.", "Try again in a minute."
	case "key_limited":
		return "Too many attempts", "Too many wrong keys. This address is paused for a while.", ""
	case "unauthorized":
		return "Unauthorized", "A valid access key is required.", ""
	default: // not_found, bad_gateway
		return "Not available", "There is nothing here.", ""
	}
}

func (g *Gateway) errorPage(w http.ResponseWriter, r *http.Request, status int, kind string) {
	h, l, f := pageCopy(kind)
	g.writePage(w, status, gatePageData{
		Title: "MeshBridge — " + h, Heading: h, Lede: l, Fine: f, Glyph: "⌁",
	})
}

func (g *Gateway) gatePage(w http.ResponseWriter, r *http.Request, t *Tunnel, state string) {
	heading, lede, _ := pageCopy("wrong")
	status := http.StatusOK
	if state == "wrong" {
		status = http.StatusUnauthorized
	}
	g.writePage(w, status, gatePageData{
		Title: "MeshBridge — Protected link", Heading: heading, Lede: lede,
		Fine:     "Only people holding the key can open this link. 需要访问密钥。",
		Action:   publicURI(r),
		ShowForm: true,
		Wrong:    state == "wrong",
		Glyph:    "⌁",
	})
}
