// Package auth implements password hashing (Argon2id), random tokens,
// at-rest hashes, and short-lived HMAC transfer tokens (JWT-like, no external dep).
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mineai/kit/password"
	"github.com/mineai/kit/token"
)

// Mesh keeps its password policy and one 64 MiB job per process while the
// shared engine owns PHC parsing, constant-time verification and admission.
var passwordEngine = password.NewEngine(password.Config{
	MemoryKB: 64 * 1024, Time: 1, Threads: 4, KeyLen: 32, SaltLen: 16, Slots: 1,
})

func acquirePasswordWork(ctx context.Context) (func(), error) {
	return passwordEngine.Acquire(ctx)
}

// HashPassword returns PHC-like string $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>.
func HashPassword(password string) (string, error) {
	return HashPasswordContext(context.Background(), password)
}

// HashPasswordContext can cancel admission; admitted crypto work completes
// before releasing the shared engine's budget.
func HashPasswordContext(ctx context.Context, password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password too short")
	}
	return passwordEngine.Hash(ctx, password)
}

// VerifyPassword preserves existing Mesh Argon2id records. The shared parser
// requires v19 and rejects records requesting more than 64 MiB of memory.
func VerifyPassword(encoded, password string) (bool, error) {
	return VerifyPasswordContext(context.Background(), encoded, password)
}

func VerifyPasswordContext(ctx context.Context, encoded, password string) (bool, error) {
	ok, _, err := passwordEngine.Verify(ctx, encoded, password)
	return ok, err
}

// Precompute the throwaway digest at startup, as Mesh always has. Unknown
// users then consume one verification job with the same cancellation budget
// as real users, including the very first login request.
var dummyHash = func() string {
	h, err := HashPassword("meshbridge-dummy-verify-target")
	if err != nil {
		panic(err)
	}
	return h
}()

// DummyVerify burns the same Argon2 work as a real check. Always fails.
func DummyVerify(password string) {
	_ = DummyVerifyContext(context.Background(), password)
}

func DummyVerifyContext(ctx context.Context, password string) error {
	_, _, err := passwordEngine.Verify(ctx, dummyHash, password)
	return err
}

// RandomToken returns base64url random bytes (n bytes of entropy).
func RandomToken(n int) (string, error) {
	return token.Generate(n)
}

// HashToken returns hex(sha256(token)) for DB storage (never store raw).
func HashToken(raw string) string {
	return token.Hash(raw)
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
