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

func TestProductionListenersRequireLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9999", ":8081", "[::]:8081", "192.168.1.1:8081", "example.com:8081", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", "malformed"} {
		for _, gateway := range []bool{false, true} {
			c := Default()
			if gateway {
				c.GatewayListenAddr = addr
			} else {
				c.ListenAddr = addr
			}
			if err := c.Validate(); err == nil {
				t.Errorf("accepted production %q, gateway=%v", addr, gateway)
			}
		}
	}
	for _, addr := range []string{"127.0.0.1:9999", "127.1.2.3:8081", "[::1]:8081", "[::ffff:127.0.0.1]:8081", "localhost:8081"} {
		c := Default()
		c.ListenAddr = addr
		c.GatewayListenAddr = addr
		if err := c.Validate(); err != nil {
			t.Errorf("rejected loopback %q: %v", addr, err)
		}
	}
}
