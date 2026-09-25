package config

import "testing"

func TestValidate(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default should validate: %v", err)
	}
	c.ListenAddr = "0.0.0.0:8081"
	if err := c.Validate(); err == nil {
		t.Fatalf("production 0.0.0.0 must be refused")
	}
	c = Default()
	c.Env = "dev"
	c.ListenAddr = "0.0.0.0:8081"
	if err := c.Validate(); err != nil {
		t.Fatalf("dev may bind 0.0.0.0: %v", err)
	}
	c = Default()
	c.DefaultChunkBytes = 1 << 20
	if err := c.Validate(); err == nil {
		t.Fatalf("too small chunk must fail")
	}
}
