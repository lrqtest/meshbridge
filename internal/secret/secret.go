// Package secret provides AES-256-GCM encryption of small secrets (SMTP
// passwords, S3 keys) under a master key file. Ciphertext layout:
// base64url(nonce || ciphertext). The master key is 32 bytes of hex.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadKey reads the 32-byte hex master key from path, creating one on first
// use (0600). The file must never be committed or logged.
func LoadKey(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("master key is not valid hex: %w", err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(k))
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func cipherGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext under key. Empty input encrypts to empty string.
func Encrypt(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	gcm, err := cipherGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Decrypt opens a value produced by Encrypt. Empty input returns empty string.
func Decrypt(key []byte, enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	gcm, err := cipherGCM(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// CodeHash salts and hashes a verification code for at-rest storage.
func CodeHash(serverSecret, email, code string) string {
	h := sha256.Sum256([]byte(serverSecret + ":" + email + ":" + code))
	return hex.EncodeToString(h[:])
}
