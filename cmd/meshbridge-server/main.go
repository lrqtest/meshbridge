// Command meshbridge-server: Control Plane (Caddy → 127.0.0.1:8081).
package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/meshbridge/meshbridge/internal/api"
	"github.com/meshbridge/meshbridge/internal/auth"
	"github.com/meshbridge/meshbridge/internal/config"
	"github.com/meshbridge/meshbridge/internal/db"
	"github.com/meshbridge/meshbridge/internal/headscale"
	"golang.org/x/term"
)

func main() {
	var (
		dataDir     = flag.String("data-dir", "", "override data dir (sqlite lives here)")
		schema      = flag.String("schema", "migrations/001_init.sql", "schema file")
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
	database, err := db.Open(dbPath, *schema)
	if err != nil {
		// try relative to repo root
		alt := filepath.Join("..", "..", *schema)
		database, err = db.Open(dbPath, alt)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
	}
	defer database.Close()

	if *createAdmin != "" {
		if err := runCreateAdmin(database, *createAdmin); err != nil {
			log.Fatalf("create-admin: %v", err)
		}
		return
	}

	srv := api.New(database)
	// Health reflects real Headscale reachability when an API key is present.
	if cfg.HeadscaleURL != "" {
		hs := headscale.New(cfg.HeadscaleURL, cfg.HeadscaleAPIKey)
		srv.HSOK = func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return hs.Health(ctx) == nil
		}
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("meshbridge-server listening on %s (data=%s)", cfg.ListenAddr, cfg.DataDir)
	log.Fatal(httpSrv.ListenAndServe())
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
		if err != nil {
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
