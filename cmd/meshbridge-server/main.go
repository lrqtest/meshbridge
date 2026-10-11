// Command meshbridge-server: Control Plane (Caddy → 127.0.0.1:8081).
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/meshbridge/meshbridge/internal/api"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/config"
	"github.com/meshbridge/meshbridge/internal/db"
	"github.com/meshbridge/meshbridge/internal/headscale"
	"github.com/meshbridge/meshbridge/internal/mailer"
	"github.com/meshbridge/meshbridge/internal/secret"
	"github.com/meshbridge/meshbridge/internal/serverlimits"
	"github.com/meshbridge/meshbridge/internal/settings"
	"github.com/meshbridge/meshbridge/internal/tunnel"
	"github.com/mineai/kit/httpx"
	"golang.org/x/term"
)

func main() {
	var (
		dataDir     = flag.String("data-dir", "", "override data dir (sqlite lives here)")
		schema      = flag.String("schema", "migrations/001_init.sql", "schema file (single-file fallback)")
		migrations  = flag.String("migrations", "migrations", "migrations directory (all .sql, lexical order)")
		listen      = flag.String("listen", "", "override listen addr")
		derpWarn    = flag.Bool("derp-check", true, "warn if embedded DERP appears enabled")
		createAdmin = flag.String("create-admin", "", "create admin user (name), password via stdin; then exit")
	)
	flag.Parse()

	cfg := config.FromEnv()
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	// CONTROL != DATA guard: refuse embedded DERP for production.
	if *derpWarn {
		for _, p := range []string{"/etc/headscale/config.yaml", "deploy/headscale/config.yaml.example"} {
			if raw, err := os.ReadFile(p); err == nil {
				if containsEnabledDERP(string(raw)) {
					log.Printf("WARN: CONTROL VPS DERP ENABLED detected in %s — disable embedded DERP for production (see docs/ARCHITECTURE.md)", p)
				}
			}
		}
	}
	dbPath := filepath.Join(cfg.DataDir, "meshbridge.sqlite")
	database, err := db.Open(dbPath, "")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()
	// Migrations: prefer the directory (001+002+…); fall back to a single
	// schema file when the dir is missing (e.g. stripped installs).
	if _, err := os.Stat(*migrations); err == nil {
		if err := db.RunMigrations(database, *migrations); err != nil {
			log.Fatalf("migrations: %v", err)
		}
	} else {
		raw, rerr := os.ReadFile(*schema)
		if rerr != nil {
			log.Fatalf("read schema: %v", rerr)
		}
		if _, err := database.Exec(string(raw)); err != nil {
			log.Fatalf("schema: %v", err)
		}
	}

	if *createAdmin != "" {
		if err := runCreateAdmin(database, *createAdmin); err != nil {
			log.Fatalf("create-admin: %v", err)
		}
		return
	}

	srv := api.New(database)
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	srv.Lifetime = lifetime
	srv.BaseURL = cfg.BaseURL
	srv.ProjectURL = cfg.ProjectURL
	srv.GoogleClientID = cfg.GoogleClientID
	if cfg.SSOEnabled {
		// The six account applications are declared; the MeshBridge project is a
		// seventh client derived from its own origin, never from request input.
		clients := make(map[string]string, len(cfg.SSOClients)+1)
		for id, callback := range cfg.SSOClients {
			clients[id] = callback
		}
		if cfg.ProjectSSOEnabled() {
			clients[config.ProjectSSOClientID] = cfg.ProjectCallback()
		}
		if err := srv.EnableSSO(cfg.SSOIssuer, clients, cfg.SSODev); err != nil {
			log.Fatalf("platform SSO: %v", err)
		}
		if cfg.ProjectSSOEnabled() {
			if err := srv.EnableProjectSSO(cfg.SSODev); err != nil {
				log.Fatalf("project SSO: %v", err)
			}
		}
	}
	if cfg.ProjectURL != "" {
		log.Printf("surfaces: platform=%s project=%s project-sso=%v", cfg.BaseURL, cfg.ProjectURL, cfg.ProjectSSOEnabled())
	}
	// Master key unlocks secret encryption (SMTP passwords, …). Without it the
	// web onboarding mail features stay disabled (log once, keep serving API).
	var masterKey []byte
	if mk, err := secret.LoadKey(cfg.MasterKeyPath); err == nil {
		masterKey = mk
		srv.MasterKey = mk
		srv.Mailer = &mailer.Service{
			DB: database,
			Config: func() mailer.Config {
				host, _ := settings.Get(database, "smtp_host")
				portS, _ := settings.Get(database, "smtp_port")
				user, _ := settings.Get(database, "smtp_username")
				from, _ := settings.Get(database, "smtp_from")
				enc, _ := settings.Get(database, "smtp_password_enc")
				pw, _ := secret.Decrypt(mk, enc)
				port, _ := strconv.Atoi(portS)
				return mailer.Config{Host: host, Port: port, Username: user, Password: pw, From: from}
			},
			Secret: func() string { return hex.EncodeToString(mk) },
			Limits: func() mailer.Limits {
				return mailer.Limits{
					CooldownSeconds: atoiOr(settings.GetDefault(database, "mail_code_cooldown_seconds", "60"), 60),
					ExpireMinutes:   atoiOr(settings.GetDefault(database, "mail_code_expire_minutes", "15"), 15),
					MinuteLimit:     atoiOr(settings.GetDefault(database, "mail_code_minute_limit", "5"), 5),
					DailyLimit:      atoiOr(settings.GetDefault(database, "mail_code_daily_limit", "100"), 100),
				}
			},
		}
	} else {
		log.Printf("WARN: master key unavailable (%v) — SMTP/web onboarding disabled", err)
	}

	// Tunnel gateway (visitor-facing reverse tunnel endpoint, loopback only).
	// Its gate-cookie secret derives from the master key; without one we use
	// an ephemeral key (visitors re-enter keys after every restart).
	gateSecret := sha256.Sum256(append(append([]byte("meshbridge-tunnel-gate:"), masterKey...), []byte(os.Getenv("MESH_TUNNEL_GATE_SECRET"))...))
	if len(masterKey) == 0 {
		log.Printf("WARN: ephemeral tunnel gate secret — gate cookies do not survive restarts")
		eph := make([]byte, 32)
		_, _ = rand.Read(eph)
		gateSecret = sha256.Sum256(eph)
	}
	baseDomain := cfg.TunnelBaseDomain
	if baseDomain == "" {
		if u, err := url.Parse(srv.BaseURL); err == nil && u.Hostname() != "" {
			baseDomain = u.Hostname()
		}
	}
	gw := tunnel.NewGateway(tunnel.GatewayConfig{
		DB:         database,
		SSOEnabled: cfg.SSOEnabled,
		Secret:     gateSecret[:],
		BaseURL:    srv.BaseURL,
		BaseDomain: baseDomain,
	})
	srv.Gateway = gw
	gw.StartMeter(lifetime)
	// Health reflects real Headscale reachability when an API key is present.
	if cfg.HeadscaleURL != "" {
		hs := headscale.New(cfg.HeadscaleURL, cfg.HeadscaleAPIKey)
		srv.HS = hs
		srv.HSProbe = func(ctx context.Context) bool { return hs.Health(ctx) == nil }
	}
	// Web UI from the embedded filesystem, SPA fallback to index.html.
	// /dl/ is NOT part of the SPA: the install script curls origin/dl/* with
	// `curl -f`, and the SPA fallback's 200 + index.html made it install HTML
	// as the agent binary. Fail loudly until an agent download path exists.
	srv.Mux.Handle("/dl/", http.NotFoundHandler())
	srv.Mux.Handle("/", webHandler())
	apiHandlers := serverlimits.Handler(srv.Mux, serverlimits.API)
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpx.Secure(apiHandlers),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return lifetime },
	}
	apiLN, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("API listen: %v", err)
	}
	apiLN = serverlimits.Listener(apiLN, serverlimits.API)
	servers := []*http.Server{httpSrv}
	listeners := []net.Listener{apiLN}
	handlers := []*serverlimits.Requests{apiHandlers}
	// Visitor-facing tunnel gateway on its own loopback listener so proxy
	// traffic never competes with API connection limits (Caddy routes /t/*
	// and t-*.domain here). No WriteTimeout: proxied bodies may be slow.
	if cfg.GatewayListenAddr != "" {
		gwHandlers := serverlimits.Handler(gw.Handler(), serverlimits.Gateway)
		gwSrv := &http.Server{
			Addr:              cfg.GatewayListenAddr,
			Handler:           gwHandlers,
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       120 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return lifetime },
		}
		ln, err := net.Listen("tcp", cfg.GatewayListenAddr)
		if err != nil {
			_ = apiLN.Close()
			log.Fatalf("tunnel gateway listen: %v", err)
		}
		ln = serverlimits.Listener(ln, serverlimits.Gateway)
		servers = append(servers, gwSrv)
		listeners = append(listeners, ln)
		handlers = append(handlers, gwHandlers)
		log.Printf("tunnel gateway listening on %s (base domain %q)", cfg.GatewayListenAddr, baseDomain)
	}
	log.Printf("meshbridge-server listening on %s (data=%s)", cfg.ListenAddr, cfg.DataDir)
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	serveErr := make(chan error, len(servers))
	for i, s := range servers {
		ln := listeners[i]
		go func() { serveErr <- s.Serve(ln) }()
	}
	select {
	case <-signalCtx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("HTTP serve: %v", err)
		}
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	owner := newShutdownOwner(cancelLifetime, servers, listeners, handlers, gw)
	if err := owner.shutdown(shutdownCtx); err != nil {
		// A timed-out owner may still touch SQLite. Preserve it until process
		// exit instead of closing it underneath a handler or pending flush.
		log.Printf("shutdown: %v", err)
		os.Exit(1)
	}
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

// runCreateAdmin reads the password from a TTY (twice, no echo) or stdin pipe
// (single line) and writes the Argon2id hash. Never logs the password.
func runCreateAdmin(database *sql.DB, username string) error {
	if username == "" || len(username) > 64 {
		return fmt.Errorf("username must be 1..64 chars")
	}
	var password string
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Printf("password for %q (>=12 chars): ", username)
		b1, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return err
		}
		fmt.Print("confirm: ")
		b2, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return err
		}
		if string(b1) != string(b2) {
			return fmt.Errorf("passwords differ")
		}
		password = string(b1)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && (err != io.EOF || strings.TrimSpace(line) == "") {
			return err
		}
		password = strings.TrimSpace(line)
	}
	if len(password) < 12 {
		return fmt.Errorf("password too short (need >=12)")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	id := auth.HashToken(username + time.Now().String())[:16]
	res, err := database.Exec(`INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,'admin',?)`,
		id, username, hash, time.Now().Unix())
	if err != nil {
		// idempotent-ish: refresh hash for existing admin
		if _, uerr := database.Exec(`UPDATE users SET password_hash=? WHERE username=?`, hash, username); uerr == nil {
			log.Printf("admin %q password updated", username)
			return nil
		}
		return err
	}
	_ = res
	log.Printf("admin %q created", username)
	return nil
}

func containsEnabledDERP(yaml string) bool {
	for i := 0; i+4 < len(yaml); i++ {
		if yaml[i:i+4] == "derp" || yaml[i:i+4] == "DERP" {
			window := yaml[i:]
			if len(window) > 500 {
				window = window[:500]
			}
			if strings.Contains(window, "enabled: true") || strings.Contains(window, "enabled:true") {
				return true
			}
		}
	}
	return false
}
