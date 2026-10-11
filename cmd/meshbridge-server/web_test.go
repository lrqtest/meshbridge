package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestMeshWebWithSharedAssets(t *testing.T) {
	app := fstest.MapFS{
		"index.html":               {Data: []byte(`<html data-app="mb"><head><script src="/assets/kit/core.js" defer></script><script src="/assets/app.js" defer></script></head></html>`)},
		"assets/app.js":            {Data: []byte("mesh adapter")},
		"assets/fonts/local.woff2": {Data: []byte("local font")},
	}
	mux := http.NewServeMux()
	mux.Handle("/", newWebHandler(app, ".", "", ""))
	get := func(p, inm string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, p := range []string{"/", "/login", "/app/overview"} {
		w := get(p, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-app="mb"`) || w.Header().Get("Content-Security-Policy") != contentSecurityPolicy {
			t.Fatalf("Mesh SPA/CSP lost at %s: %d %s", p, w.Code, w.Body.String())
		}
	}
	for _, p := range []string{"/assets/kit/core.js", "/assets/kit/chrome.js", "/assets/kit/boot.js", "/assets/kit/i18n/zh-CN.json", "/assets/app.js"} {
		w := get(p, "")
		if w.Code != http.StatusOK || w.Header().Get("ETag") == "" || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("asset %s: %d %q", p, w.Code, w.Header().Get("Cache-Control"))
		}
		if next := get(p, w.Header().Get("ETag")); next.Code != http.StatusNotModified {
			t.Fatalf("%s does not revalidate: %d", p, next.Code)
		}
	}
	for _, p := range []string{"/assets/kit/missing.js", "/assets/missing.js", "/assets/kit/i18n/", "/dl/missing-agent", "/api/missing"} {
		if w := get(p, ""); w.Code != http.StatusNotFound {
			t.Fatalf("missing asset/API/download %s returned %d", p, w.Code)
		}
	}
	if w := get("/assets/fonts/local.woff2", ""); w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatal("Mesh font caching changed")
	}
	body := get("/", "").Body.String()
	refs := regexp.MustCompile(`(?:src|href)="(/assets/[^"?]+\?v=[0-9a-f]{16})"`).FindAllStringSubmatch(body, -1)
	all := regexp.MustCompile(`<meta name="asset-v" content="([0-9a-f]{16})">`).FindStringSubmatch(body)
	if len(refs) != 2 || all == nil {
		t.Fatalf("Mesh shell was not versioned: %s", body)
	}
	for _, url := range []string{refs[0][1], refs[1][1], "/assets/kit/i18n/en.json?v=" + all[1]} {
		if w := get(url, ""); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("current asset %s: %d %q", url, w.Code, w.Header().Get("Cache-Control"))
		}
	}
	if w := get("/assets/app.js?v=old", ""); w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("stale assets must revalidate")
	}
	if w := get("/", get("/", "").Header().Get("ETag")); w.Code != http.StatusNotModified {
		t.Fatal("versioned shell must still revalidate")
	}
}

func TestMeshDevAssetsAndVersionChanges(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	shell := []byte(`<html><head><script src="/assets/app.js"></script></head></html>`)
	for p, data := range map[string][]byte{"index.html": shell, "assets/app.js": []byte("first")} {
		if err := os.WriteFile(filepath.Join(dir, p), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newWebHandler(os.DirFS(dir), ".", dir, "")
	request := func(handler http.Handler, url string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		return w
	}
	if body := request(h, "/").Body.String(); strings.Contains(body, "?v=") || strings.Contains(body, "asset-v") {
		t.Fatal("development shell must not be versioned")
	}
	first := request(h, "/assets/app.js?v=anything")
	if first.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("development assets must revalidate")
	}
	if err := os.WriteFile(filepath.Join(dir, "assets/app.js"), []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	if next := request(h, "/assets/app.js"); next.Body.String() != "second" || next.Header().Get("ETag") == first.Header().Get("ETag") {
		t.Fatal("development edit was hidden by the cache")
	}
	a := fstest.MapFS{"index.html": {Data: shell}, "assets/app.js": {Data: []byte("first")}}
	b := fstest.MapFS{"index.html": {Data: shell}, "assets/app.js": {Data: []byte("second")}}
	old, next := request(newWebHandler(a, ".", "", ""), "/"), request(newWebHandler(b, ".", "", ""), "/")
	if old.Header().Get("ETag") == next.Header().Get("ETag") || old.Body.String() == next.Body.String() {
		t.Fatal("asset changes must change the shell version and ETag")
	}
}
