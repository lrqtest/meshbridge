package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	kitweb "github.com/mineai/kit/web"
)

// web/ is canonical; `make sync-web` copies it here for embedding.
//
//go:embed all:web
var webFS embed.FS

// The UI ships no inline script or style. Google Identity Services is the
// only optional third-party login asset; data: covers the CSS paper grain.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' https://accounts.google.com; " +
	"style-src 'self' 'unsafe-inline' https://accounts.google.com; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self' https://accounts.google.com; " +
	"frame-src https://accounts.google.com; object-src 'none'; base-uri 'none'; " +
	"form-action 'self'; frame-ancestors 'none'"

func webHandler() http.Handler {
	// MESH_WEB_DIR serves the UI straight from disk for edit-and-reload work.
	if dir := os.Getenv("MESH_WEB_DIR"); dir != "" {
		return newWebHandler(os.DirFS(dir), ".", dir, os.Getenv("KIT_WEB_DIR"))
	}
	return newWebHandler(webFS, "web", "", os.Getenv("KIT_WEB_DIR"))
}

// Both platform and project shells use one combined app/kit version. HTML
// revalidates; current versioned assets are immutable. Disk development never
// versions assets. Mesh's CSP and non-SPA namespaces remain unchanged.
func newWebHandler(fsys fs.FS, dir, devDir, kitDevDir string) http.Handler {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}
	files := kitweb.HandlerPolicy(sub, func() string { return contentSecurityPolicy }, devDir, kitDevDir)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "assets" || p == "api" || p == "dl" || strings.HasPrefix(p, "dl/") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}
