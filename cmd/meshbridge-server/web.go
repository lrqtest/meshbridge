package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
)

// web/ is canonical; `make sync-web` copies it here for embedding.
//
//go:embed all:web
var webFS embed.FS

// The UI ships no inline script or style and no third-party assets (fonts
// are self-hosted), so the policy can stay strict. data: covers the CSS
// paper-grain texture.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func init() {
	// Not in Go's builtin table; don't depend on the host's /etc/mime.types.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}

func webHandler() http.Handler {
	// MESH_WEB_DIR serves the UI straight from disk for edit-and-reload work.
	if dir := os.Getenv("MESH_WEB_DIR"); dir != "" {
		return newWebHandler(os.DirFS(dir), ".", false)
	}
	return newWebHandler(webFS, "web", true)
}

// newWebHandler serves the UI with SPA fallback to index.html. Responses carry
// a content-hash ETag: the shell, scripts and dictionaries revalidate on every
// load (cheap 304s, deploys show up at once), while woff2 fonts are cached for
// a year — CJK subsets, the only fonts that change, have hashed names.
// ETags are memoized unless the files may change underneath (disk mode).
func newWebHandler(fsys fs.FS, dir string, memoize bool) http.Handler {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}
	files := http.FileServer(http.FS(sub))
	var etags sync.Map // file path -> quoted ETag
	etag := func(p string) string {
		if v, ok := etags.Load(p); ok {
			return v.(string)
		}
		raw, err := fs.ReadFile(sub, p)
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(raw)
		tag := `"` + hex.EncodeToString(sum[:8]) + `"`
		if memoize {
			etags.Store(p, tag)
		}
		return tag
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if st, err := fs.Stat(sub, p); p == "" || err != nil || st.IsDir() {
			// SPA route (or a directory: never list embedded files) → shell.
			p = "index.html"
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = "/"
			r = r2
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		if tag := etag(p); tag != "" {
			h.Set("ETag", tag)
		}
		switch {
		case p == "index.html":
			h.Set("Content-Security-Policy", contentSecurityPolicy)
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Cache-Control", "no-cache")
		case strings.HasPrefix(p, "assets/fonts/") && strings.HasSuffix(p, ".woff2"):
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			h.Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
