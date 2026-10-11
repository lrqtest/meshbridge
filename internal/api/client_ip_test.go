package api

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPUsesTrustedProxyAppendedAddress(t *testing.T) {
	for _, tc := range []struct{ name, peer, forwarded, want string }{
		{"caddy replacement", "127.0.0.1:8000", "198.51.100.7", "198.51.100.7"},
		{"spoofed first address", "127.0.0.1:8000", "192.0.2.99, 198.51.100.7", "198.51.100.7"},
		{"ipv6 proxy", "[::1]:8000", "192.0.2.99, 2001:db8::7", "2001:db8::7"},
		{"invalid appended address", "127.0.0.1:8000", "198.51.100.7, untrusted", "127.0.0.1"},
		{"direct remote", "203.0.113.5:8000", "192.0.2.99, 198.51.100.7", "203.0.113.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP=%q, want %q", got, tc.want)
			}
		})
	}
}
