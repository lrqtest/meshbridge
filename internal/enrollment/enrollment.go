// Package enrollment creates single-use 256-bit enrollment tokens (hash-only at rest).
package enrollment

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

func NewToken() (raw, hash string, err error) {
	b := make([]byte, 32) // 256 bit
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

type Record struct {
	Hash      string
	ExpiresAt time.Time
	Used      bool
}

func (r Record) Valid(now time.Time) error {
	if r.Used {
		return errors.New("token already used")
	}
	if now.After(r.ExpiresAt) {
		return errors.New("token expired")
	}
	return nil
}
