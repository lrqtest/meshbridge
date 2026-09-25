// Package probe classifies Tailscale paths as DIRECT / PEER_RELAY / DERP / ...
// Prefer stable JSON (`tailscale status --json`); text parsing isolated here with fixtures.
package probe

import (
	"encoding/json"
	"strings"
)

// ConnectionClass is the coarse route type used by the scheduler.
type ConnectionClass string

const (
	ClassDirect    ConnectionClass = "DIRECT"
	ClassPeerRelay ConnectionClass = "PEER_RELAY"
	ClassDERP      ConnectionClass = "DERP"
	ClassUnreach   ConnectionClass = "UNREACHABLE"
	ClassUnknown   ConnectionClass = "UNKNOWN"
)

// Observation is one classified probe result.
type Observation struct {
	Class     ConnectionClass `json:"class"`
	RTTMs     float64         `json:"rtt_ms"`
	Loss      float64         `json:"loss"`
	RelayName string          `json:"relay_name"`
	Endpoint  string          `json:"endpoint"`
}

// tailscaleStatusJSON is the subset we rely on (stable across 1.80+).
type tailscaleStatusJSON struct {
	Peer map[string]struct {
		Relay        string   `json:"Relay"`
		RxBytes      int64    `json:"RxBytes"`
		TxBytes      int64    `json:"TxBytes"`
		Addrs        []string `json:"Addrs"`
		CurAddr      string   `json:"CurAddr"`
		PeerRelay    string   `json:"PeerRelay"`
		LastHandshake string  `json:"LastHandshake"`
	} `json:"Peer"`
	Self struct {
		Relay string `json:"Relay"`
	} `json:"Self"`
}

// ClassifyStatusJSON inspects `tailscale status --json` for a given peer key/host.
func ClassifyStatusJSON(raw []byte, peerKeyOrHost string) Observation {
	var st tailscaleStatusJSON
	if err := json.Unmarshal(raw, &st); err != nil {
		return Observation{Class: ClassUnknown}
	}
	// peer map keys are node keys; tests may use hostname substring.
	for k, p := range st.Peer {
		if peerKeyOrHost != "" && !strings.Contains(k, peerKeyOrHost) && !containsAddr(p.Addrs, peerKeyOrHost) {
			continue
		}
		relay := p.Relay
		if p.PeerRelay != "" {
			return Observation{Class: ClassPeerRelay, RelayName: p.PeerRelay, Endpoint: p.CurAddr}
		}
		if relay == "" {
			return Observation{Class: ClassDirect, Endpoint: p.CurAddr}
		}
		if strings.HasPrefix(relay, "peer-relay") || strings.Contains(relay, "peer") {
			return Observation{Class: ClassPeerRelay, RelayName: relay, Endpoint: p.CurAddr}
		}
		return Observation{Class: ClassDERP, RelayName: relay, Endpoint: p.CurAddr}
	}
	return Observation{Class: ClassUnknown}
}

func containsAddr(addrs []string, want string) bool {
	for _, a := range addrs {
		if strings.Contains(a, want) {
			return true
		}
	}
	return false
}

// ParsePingOutput parses `tailscale ping` human output (fragile; keep isolated).
// Examples:
// "pong from HOST (100.x.y.z) via 100.x.y.z:41641 in 42ms"
// "pong from HOST via peer-relay(relay-jp-01) in 60ms"
// "pong from HOST via DERP(ord) in 180ms"
// "no response" / "ping timed out" => UNREACHABLE
func ParsePingOutput(out string) Observation {
	l := strings.ToLower(out)
	if strings.Contains(l, "no response") || strings.Contains(l, "timed out") || strings.Contains(l, "unreachable") {
		return Observation{Class: ClassUnreach}
	}
	if strings.Contains(l, "peer-relay") || strings.Contains(l, "peer relay") {
		return Observation{Class: ClassPeerRelay, RelayName: extractParen(out)}
	}
	if strings.Contains(l, "derp(") || strings.Contains(l, " via derp") || strings.Contains(l, "relay(") {
		return Observation{Class: ClassDERP, RelayName: extractParen(out)}
	}
	if strings.Contains(l, "pong") && strings.Contains(l, "via") {
		return Observation{Class: ClassDirect, Endpoint: extractVia(out)}
	}
	if strings.Contains(l, "pong") {
		return Observation{Class: ClassDirect}
	}
	return Observation{Class: ClassUnknown}
}

func extractParen(s string) string {
	i := strings.Index(s, "(")
	j := strings.Index(s, ")")
	if i >= 0 && j > i {
		return s[i+1 : j]
	}
	return ""
}

func extractVia(s string) string {
	l := strings.ToLower(s)
	i := strings.Index(l, "via ")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(s[i+4:])
	f := strings.Fields(rest)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// DebounceRoute decides whether to PAUSE a big transfer on flapping.
// consecutiveDERP = number of consecutive DERP observations.
func DebounceRoute(prev, cur ConnectionClass, consecutiveDERP int, remainingBytes, derpLimit int64) (pause bool) {
	if cur != ClassDERP {
		return false
	}
	if remainingBytes <= derpLimit {
		return false // small tail may finish over DERP
	}
	if prev == ClassDirect && consecutiveDERP >= 2 {
		return true
	}
	if consecutiveDERP >= 3 {
		return true
	}
	return false
}
