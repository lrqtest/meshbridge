package auth

import (
	"testing"
	"time"
)

func TestPasswordRoundtrip(t *testing.T) {
	h, err := HashPassword("correct-horse-123")
	if err != nil {
		t.Fatal(err)
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
		"$bcrypt$v=1$x$y",
	} {
		if _, err := VerifyPassword(bad, "x"); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	DummyVerify("x") // must not panic
}
