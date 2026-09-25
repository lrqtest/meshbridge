// Package auth implements password hashing (Argon2id), random tokens,
// at-rest hashes, and short-lived HMAC transfer tokens (JWT-like, no external dep).
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// OWASP-ish Argon2id params for interactive login.
	memKB   = 64 * 1024
	timeN   = 1
	threads = 4
	keyLen  = 32
	saltLen = 16
)

// HashPassword returns PHC-like string $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password too short")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, timeN, memKB, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memKB, timeN, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword parses our own format only (params read from the stored
// string so future parameter changes keep old hashes verifiable).
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported hash format")
	}
	m, t, p, err := parseArgon2Params(parts[3])
	if err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	// Hard cap decoded material to keep a tampered DB row from forcing huge work.
	if len(want) < 16 || len(want) > 128 || len(salt) < 8 || len(salt) > 64 || m > 4<<20 || t == 0 || t > 8 || p == 0 || p > 16 {
		return false, fmt.Errorf("implausible hash parameters")
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func parseArgon2Params(s string) (m uint32, t uint32, p uint8, err error) {
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, fmt.Errorf("bad params %q", s)
		}
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil {
			return 0, 0, 0, fmt.Errorf("bad param %q", kv)
		}
		switch k {
		case "m":
			m = uint32(n)
		case "t":
			t = uint32(n)
		case "p":
			if n > 255 {
				return 0, 0, 0, fmt.Errorf("bad p")
			}
			p = uint8(n)
		}
	}
	if m == 0 || t == 0 || p == 0 {
		return 0, 0, 0, fmt.Errorf("incomplete params %q", s)
	}
	return m, t, p, nil
}

// DummyHash is a real Argon2id digest of a throwaway password. Verifying
// against it when the username is unknown keeps login timing uniform so
// valid usernames cannot be enumerated by response time.
var dummyHash = func() string {
	h, err := HashPassword("meshbridge-dummy-verify-target")
	if err != nil {
		panic(err)
	}
	return h
}()

// DummyVerify burns the same Argon2 work as a real check. Always fails.
func DummyVerify(password string) {
	_, _ = VerifyPassword(dummyHash, password)
}

// RandomToken returns base64url random bytes (n bytes of entropy).
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns hex(sha256(token)) for DB storage (never store raw).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ---- Transfer tokens (Controller-signed, 10min, anti-replay) ----

type TransferClaims struct {
	JobID string `json:"job"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

// SignTransfer signs claims with HMAC-SHA256(controllerSecret).
// Format: base64url(payload) + "." + base64url(sig)
func SignTransfer(secret []byte, c TransferClaims) (string, error) {
	if len(secret) < 16 {
		return "", fmt.Errorf("controller secret too short")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return p + "." + sig, nil
}

// VerifyTransfer checks signature + expiry + expected job/src/dst.
func VerifyTransfer(secret []byte, token, jobID, src, dst string, now time.Time) (*TransferClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("bad token format")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("bad sig")
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, fmt.Errorf("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var c TransferClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.JobID != jobID || c.Src != src || c.Dst != dst {
		return nil, fmt.Errorf("claims mismatch")
	}
	if now.Unix() > c.Exp {
		return nil, fmt.Errorf("token expired")
	}
	if c.Nonce == "" {
		return nil, fmt.Errorf("missing nonce")
	}
	return &c, nil
}

// ReplayGuard remembers consumed nonces until their token expiry passes.
// VerifyTransfer alone cannot detect re-use: the receiver must consult this
// (or an equivalent persistent store) before acting on a token.
type ReplayGuard struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	lastGC time.Time
}

func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: make(map[string]time.Time)}
}

// CheckAndConsume returns false if nonce was already used. Nonces older than
// maxTTL are garbage-collected opportunistically.
func (g *ReplayGuard) CheckAndConsume(nonce string, exp time.Time, maxTTL time.Duration) bool {
	if nonce == "" {
		return false
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Sub(g.lastGC) > time.Minute {
		for k, t := range g.seen {
			if now.Sub(t) > maxTTL {
				delete(g.seen, k)
			}
		}
		g.lastGC = now
	}
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = exp
	return true
}
