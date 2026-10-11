package api

import (
	"net/http"

	"github.com/meshbridge/meshbridge/internal/config"
)

// Surface names which product a request is addressed to. One process serves
// both the MineAI platform origin and the MeshBridge project origin, so the
// browser asks which one it is on instead of guessing from a hard-coded host.
// Kind is only a presentation choice: every API enforces the same
// authentication on both origins, and sessions never cross an origin.
const (
	SurfacePlatform = "platform"
	SurfaceProject  = "project"
)

type surfaceInfo struct {
	Kind        string `json:"kind"`
	Split       bool   `json:"split"`        // platform and project live on separate origins
	PlatformURL string `json:"platform_url"` // empty on a standalone installation
	ProjectURL  string `json:"project_url"`  // empty on a standalone installation
	// BaseURL is where the control plane publishes its public services:
	// Headscale (tailscale --login-server), agent downloads and tunnel URLs.
	// Those are routed on the platform origin only, so the console must not
	// derive them from the project origin it happens to be served from.
	BaseURL string `json:"base_url"`
	SSO     bool   `json:"sso"` // the project can continue with the platform account
}

// surfaceOf resolves the Host of a request. Without a configured project
// origin there is a single surface and it is the project itself; an unknown
// host (a direct IP, an old alias) also gets the project, so the platform
// landing page can only ever appear on the configured platform host.
func (s *Server) surfaceOf(r *http.Request) surfaceInfo {
	if s.ProjectURL == "" {
		return surfaceInfo{Kind: SurfaceProject, BaseURL: s.BaseURL}
	}
	info := surfaceInfo{Kind: SurfaceProject, Split: true, PlatformURL: s.BaseURL, ProjectURL: s.ProjectURL, BaseURL: s.BaseURL, SSO: s.ProjectSSO != nil}
	if s.BaseURL != "" && config.HostKey(r.Host) == config.HostKey(s.BaseURL) {
		info.Kind = SurfacePlatform
		// The platform never offers "continue with the platform" to itself.
		info.SSO = false
	}
	return info
}

func (s *Server) handleSurface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "method", "GET only")
		return
	}
	// The answer depends on the Host header, so no cache may reuse it.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Host")
	writeJSON(w, s.surfaceOf(r))
}
