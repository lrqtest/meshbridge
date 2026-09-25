// Command meshbridge-server: Control Plane (Caddy → 127.0.0.1:8081).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/meshbridge/meshbridge/internal/api"
	"github.com/meshbridge/meshbridge/internal/config"
	"github.com/meshbridge/meshbridge/internal/db"
)

func main() {
	var (
		dataDir  = flag.String("data-dir", "", "override data dir (sqlite lives here)")
		schema   = flag.String("schema", "migrations/001_init.sql", "schema file")
		listen   = flag.String("listen", "", "override listen addr")
		derpWarn = flag.Bool("derp-check", true, "warn if embedded DERP appears enabled")
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
				s := string(raw)
				if containsEnabledDERP(s) {
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
	srv := api.New(database)
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("meshbridge-server listening on %s (data=%s)", cfg.ListenAddr, cfg.DataDir)
	log.Fatal(httpSrv.ListenAndServe())
}

func containsEnabledDERP(yaml string) bool {
	// naive but effective guard: look for "enabled: true" near "derp".
	for i := 0; i+4 < len(yaml); i++ {
		if len(yaml[i:]) >= 4 && (yaml[i:i+4] == "derp" || yaml[i:i+4] == "DERP") {
			window := yaml[i:]
			if len(window) > 500 {
				window = window[:500]
			}
			if contains(window, "enabled: true") || contains(window, "enabled:true") {
				return true
			}
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
