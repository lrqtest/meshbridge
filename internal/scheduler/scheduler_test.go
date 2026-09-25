package scheduler

import (
	"testing"

	"github.com/meshbridge/meshbridge/internal/probe"
)

func TestDecide(t *testing.T) {
	derpLimit := int64(100 << 20)
	relays := []Relay{{ID: "relay-jp-01", Healthy: true, BytesMonth: 10 << 30, QuotaBytes: 1 << 40}}
	if d := Decide(probe.ClassDirect, 200<<30, derpLimit, relays, true); d.Route != RouteDirect {
		t.Fatalf("direct: %v", d)
	}
	if d := Decide(probe.ClassPeerRelay, 200<<30, derpLimit, relays, true); d.Route != RoutePeer || d.RelayID != "relay-jp-01" {
		t.Fatalf("peer: %v", d)
	}
	// DERP small ok
	if d := Decide(probe.ClassDERP, 10<<20, derpLimit, relays, true); d.Route != RouteDERPSml {
		t.Fatalf("derp small: %v", d)
	}
	// DERP large must NOT transfer over DERP
	if d := Decide(probe.ClassDERP, 10<<30, derpLimit, relays, true); d.Route == RouteDERPSml || d.Route == "DERP" {
		t.Fatalf("derp large must be refused/redirected: %v", d)
	}
	if d := Decide(probe.ClassDERP, 10<<30, derpLimit, nil, false); d.Route != RouteRefused {
		t.Fatalf("derp large no relay/s3 => refused/wait: %v", d)
	}
	// relay quota critical => s3
	full := []Relay{{ID: "r1", Healthy: true, BytesMonth: 980, QuotaBytes: 1000}}
	if d := Decide(probe.ClassPeerRelay, 10<<30, derpLimit, full, true); d.Route != RouteS3 {
		t.Fatalf("quota critical => s3: %v", d)
	}
	// unreachable + s3
	if d := Decide(probe.ClassUnreach, 10<<30, derpLimit, nil, true); d.Route != RouteS3 {
		t.Fatalf("unreach => s3: %v", d)
	}
}
