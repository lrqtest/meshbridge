package tunnel

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestSSOForcesOpaqueSandboxForAllPathTunnels(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, pathMode := range []bool{false, true} {
			for _, recordSandbox := range []bool{false, true} {
				g := NewGateway(GatewayConfig{SSOEnabled: enabled})
				tunnel := &Tunnel{ID: "test", Sandbox: recordSandbox}
				ctx := context.WithValue(context.Background(), ctxTunnel{}, tunnel)
				ctx = context.WithValue(ctx, ctxPathMode{}, pathMode)
				r, _ := http.NewRequestWithContext(ctx, "GET", "http://mesh.example/t/test", nil)
				response := &http.Response{Request: r, Header: http.Header{"Content-Security-Policy": []string{"default-src 'self'"}}}
				if err := g.proxyFor(tunnel).ModifyResponse(response); err != nil {
					t.Fatal(err)
				}
				policies := strings.Join(response.Header.Values("Content-Security-Policy"), ";")
				sandbox := strings.Contains(policies, "sandbox ")
				if sandbox != (pathMode && (enabled || recordSandbox)) {
					t.Fatalf("enabled=%v path=%v record=%v CSP=%s", enabled, pathMode, recordSandbox, policies)
				}
				if sandbox && strings.Contains(policies, "allow-same-origin") {
					t.Fatal("opaque origin lost")
				}
				if !strings.Contains(policies, "default-src 'self'") {
					t.Fatal("upstream CSP lost")
				}
			}
		}
	}
}
