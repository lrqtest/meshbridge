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
	"strings"
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

// VerifyPassword parses our own format only.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported hash format")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, timeN, memKB, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
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
