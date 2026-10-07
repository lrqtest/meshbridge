// Package tunnel implements the public web-tunnel feature: an agent behind
// NAT opens one outbound WebSocket to the control plane and multiplexes
// visitor HTTP requests over it (yamux streams inside binary WS messages).
// The gateway terminates visitors on a loopback listener behind Caddy.
//
// Security model (see docs/TUNNEL.md):
//   - agent connects OUT only; the intranet machine never listens publicly
//   - HTTP(S) upstreams only, no raw TCP relay
//   - visitors pass a per-tunnel key gate (HMAC cookie / Bearer / form),
//     keys stored hashed, verified constant-time, brute-force limited
//   - per-tunnel and global monthly byte quotas; agent-side dial allowlist
package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/meshbridge/meshbridge/internal/auth"
)

// Tunnel is the persisted configuration of one public tunnel.
type Tunnel struct {
	ID            string
	DeviceID      string
	Name          string
	Slug          string
	TargetScheme  string
	TargetHost    string
	TargetPort    int
	KeyRequired   bool
	AccessKeyHash string
	Status        string // active | disabled | quota_exceeded
	StripPrefix   bool
	// Sandbox: path mode serves the tunnel on the console origin, so by
	// default responses carry `CSP: sandbox` (opaque origin — the page
	// cannot read the console's localStorage/API token). Turn off only for
	// content you fully control and that needs browser storage.
	Sandbox          bool
	MonthlyQuotaByte int64
	MaxRequestBytes  int64
	CreatedBy        string
	CreatedAt        int64
	UpdatedAt        int64
}

// AgentConfig is the per-tunnel payload sent to the agent inside the
// heartbeat response. Only non-sensitive fields.
type AgentConfig struct {
	ID     string `json:"id"`
	Scheme string `json:"target_scheme"`
	Host   string `json:"target_host"`
	Port   int    `json:"target_port"`
}

// NewSlug returns a 32-hex-char unguessable slug (16 bytes entropy).
func NewSlug() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("tunnel: rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// NewAccessKey returns (raw, hash). raw is shown once; hash is stored.
func NewAccessKey() (string, string) {
	raw, err := auth.RandomToken(24) // 192-bit entropy, base64url
	if err != nil {
		panic("tunnel: rand: " + err.Error())
	}
	return raw, auth.HashToken(raw)
}

// CheckKey verifies a candidate access key against the stored hash. Both are
// SHA-256 digests; the final compare is constant-time.
func CheckKey(storedHash, candidate string) bool {
	if storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(auth.HashToken(candidate)), []byte(storedHash)) == 1
}

// TargetOK validates the upstream target. Server and agent both enforce it:
// the server bounds what may be configured, the agent bounds what it will
// actually dial. Only IP literals in loopback / RFC1918 / CGNAT space are
// accepted — a tunnel must never point at an arbitrary public IP (open-proxy
// abuse) or at a hostname that external DNS could repoint.
func TargetOK(scheme, host string, port int) error {
	switch scheme {
	case "http", "https":
	default:
		return fmt.Errorf("scheme must be http or https")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("target host must be an IP literal")
	}
	if !ip.IsLoopback() && !ip.IsPrivate() && !isCGNAT(ip) {
		return fmt.Errorf("target host must be loopback or private")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range")
	}
	return nil
}

func isCGNAT(ip net.IP) bool {
	if b := ip.To4(); b != nil {
		return b[0] == 100 && b[1] >= 64 && b[1] <= 127
	}
	return false
}

// AllowedBy reports whether the target falls inside the agent dial policy
// (loopback always allowed; extra CIDRs come from --tunnel-allow).
func AllowedBy(host string, extra []*net.IPNet) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, n := range extra {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// MonthKey returns the UTC 'YYYY-MM' bucket for usage accounting.
func MonthKey(t time.Time) string { return t.UTC().Format("2006-01") }

// PathPrefix is the public URL prefix for a slug in path mode.
func PathPrefix(slug string) string { return "/t/" + slug }

// SubdomainLabel is the left-most DNS label for subdomain mode.
// 12 hex chars (48 bits) is unguessable and still short.
func SubdomainLabel(slug string) string {
	if len(slug) > 12 {
		slug = slug[:12]
	}
	return "t-" + slug
}

// PublicHost is the visitor-facing hostname in subdomain mode.
func PublicHost(label, baseDomain string) string { return label + "." + baseDomain }

// ParseSubdomainSlug extracts the slug prefix from a host like
// t-abcdef123456.mineai.top; empty when the host is not a tunnel host.
func ParseSubdomainSlug(host, baseDomain string) string {
	if baseDomain == "" {
		return ""
	}
	h := host
	if hn, _, err := net.SplitHostPort(host); err == nil {
		h = hn
	}
	suffix := "." + baseDomain
	if !strings.HasSuffix(h, suffix) || len(h) <= len(suffix)+2 {
		return ""
	}
	label := h[:len(h)-len(suffix)]
	if !strings.HasPrefix(label, "t-") {
		return ""
	}
	rest := label[2:]
	if rest == "" {
		return ""
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return rest
}

// GateCookieName is the fixed cookie name; the signed value binds the slug.
const GateCookieName = "mb_gate"

// GateTTL is how long a verified visitor stays authorized.
const GateTTL = 7 * 24 * time.Hour

func gateMAC(secret []byte, slug string, exp int64) []byte {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "mb-gate|%s|%d", slug, exp)
	return mac.Sum(nil)
}

// SignGate produces "<unix-exp>.<truncated-hmac>" binding slug to the secret.
func SignGate(secret []byte, slug string, exp time.Time) string {
	sig := gateMAC(secret, slug, exp.Unix())[:16]
	return strconv.FormatInt(exp.Unix(), 10) + "." + hex.EncodeToString(sig)
}

// VerifyGate checks a cookie value for slug at time now.
func VerifyGate(secret []byte, slug, value string, now time.Time) bool {
	expS, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expS, 10, 64)
	if err != nil || now.Unix() > exp || exp > now.Add(GateTTL+time.Hour).Unix() {
		return false
	}
	want := hex.EncodeToString(gateMAC(secret, slug, exp)[:16])
	return subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1
}

// Key-guessing bounds per visitor IP + slug.
const (
	KeyAttemptLimit  = 8
	KeyAttemptWindow = 15 * time.Minute
)

// ClientIP trusts X-Forwarded-For only from loopback (Caddy); otherwise
// RemoteAddr, so a direct attacker cannot spoof its IP through the header.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first, _, ok := strings.Cut(xff, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(xff)
		}
	}
	return host
}
