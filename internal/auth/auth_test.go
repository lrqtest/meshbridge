package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundtrip(t *testing.T) {
	h, err := HashPassword("correct-horse-123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Fatalf("Mesh hash strength changed: %s", h)
	}
	ok, err := VerifyPassword(h, "correct-horse-123")
	if err != nil || !ok {
		t.Fatalf("verify failed: %v %v", ok, err)
	}
	ok, _ = VerifyPassword(h, "wrong")
	if ok {
		t.Fatalf("wrong password accepted")
	}
}

func TestVerifyExistingMeshPasswordRecord(t *testing.T) {
	// Fixed PHC fixture from Mesh's original Argon2id implementation. A
	// shared-engine migration must validate it without rewriting the record.
	const record = "$argon2id$v=19$m=65536,t=1,p=4$MDEyMzQ1Njc4OWFiY2RlZg$3xo/ddAe2JLjXpAVM8Yw7hhS85eoekDHQ3uzV4EuwZo"
	if ok, err := VerifyPassword(record, "legacy-mesh-password"); err != nil || !ok {
		t.Fatalf("existing record rejected: %v %v", ok, err)
	}
}

func TestTransferToken(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	nonce, _ := RandomToken(12)
	c := TransferClaims{JobID: "j1", Src: "a", Dst: "b", Exp: time.Now().Add(10 * time.Minute).Unix(), Nonce: nonce}
	tok, err := SignTransfer(secret, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTransfer(secret, tok, "j1", "a", "b", time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyTransfer(secret, tok, "j1", "a", "EVIL", time.Now()); err == nil {
		t.Fatalf("dst mismatch must fail")
	}
	expired := c
	expired.Exp = time.Now().Add(-time.Minute).Unix()
	tok2, _ := SignTransfer(secret, expired)
	if _, err := VerifyTransfer(secret, tok2, "j1", "a", "b", time.Now()); err == nil {
		t.Fatalf("expired must fail")
	}
	if HashToken("abc") == "abc" {
		t.Fatalf("hash must differ")
	}
}

func TestReplayGuard(t *testing.T) {
	g := NewReplayGuard()
	exp := time.Now().Add(10 * time.Minute)
	if !g.CheckAndConsume("n1", exp, time.Hour) {
		t.Fatal("first use must pass")
	}
	if g.CheckAndConsume("n1", exp, time.Hour) {
		t.Fatal("replay must be rejected")
	}
	if g.CheckAndConsume("", exp, time.Hour) {
		t.Fatal("empty nonce must be rejected")
	}
}

func TestVerifyPasswordRejectsImplausibleParams(t *testing.T) {
	// tampered / malformed hashes must error, not panic or accept
	for _, bad := range []string{
		"$argon2id$v=19$m=1,t=0,p=0$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=999999999,t=99,p=99$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=65537,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=16$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$bcrypt$v=1$x$y",
	} {
		if _, err := VerifyPassword(bad, "x"); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	DummyVerify("x") // must not panic
}
