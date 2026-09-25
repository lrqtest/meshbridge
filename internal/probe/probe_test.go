package probe

import "testing"

func TestClassifyStatusJSON(t *testing.T) {
	direct := []byte(`{"Peer":{"nodekey123":{"Relay":"","CurAddr":"1.2.3.4:41641","Addrs":["100.64.0.2"]}}}`)
	if got := ClassifyStatusJSON(direct, "nodekey123"); got.Class != ClassDirect {
		t.Fatalf("want DIRECT got %v", got)
	}
	derp := []byte(`{"Peer":{"nodekey123":{"Relay":"ord","CurAddr":"derp","Addrs":["100.64.0.2"]}}}`)
	if got := ClassifyStatusJSON(derp, "nodekey123"); got.Class != ClassDERP || got.RelayName != "ord" {
		t.Fatalf("want DERP got %v", got)
	}
	pr := []byte(`{"Peer":{"nodekey123":{"Relay":"peer-relay(relay-jp-01)","CurAddr":"5.6.7.8:40000","PeerRelay":"relay-jp-01"}}}`)
	if got := ClassifyStatusJSON(pr, "nodekey123"); got.Class != ClassPeerRelay {
		t.Fatalf("want PEER_RELAY got %v", got)
	}
	if got := ClassifyStatusJSON([]byte(`{bad`), "x"); got.Class != ClassUnknown {
		t.Fatalf("bad json must be UNKNOWN")
	}
}

func TestParsePingOutput(t *testing.T) {
	cases := map[string]ConnectionClass{
		"pong from us-pc (100.64.0.3) via 100.64.0.3:41641 in 42ms": ClassDirect,
		"pong from us-pc via peer-relay(relay-jp-01) in 60ms":        ClassPeerRelay,
		"pong from us-pc via DERP(ord) in 180ms":                     ClassDERP,
		"no response": ClassUnreach,
		"ping timed out": ClassUnreach,
		"garbage ???": ClassUnknown,
	}
	for in, want := range cases {
		if got := ParsePingOutput(in); got.Class != want {
			t.Fatalf("input %q: want %s got %s", in, want, got.Class)
		}
	}
}

func TestDebounce(t *testing.T) {
	if !DebounceRoute(ClassDirect, ClassDERP, 2, 10<<30, 100<<20) {
		t.Fatalf("should pause big file after 2x DERP")
	}
	if DebounceRoute(ClassDirect, ClassDERP, 1, 10<<30, 100<<20) {
		t.Fatalf("single sample must not pause (flap)")
	}
	if DebounceRoute(ClassDirect, ClassDERP, 5, 1<<20, 100<<20) {
		t.Fatalf("small tail may finish over DERP")
	}
}
