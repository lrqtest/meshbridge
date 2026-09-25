// Package scheduler decides transfer routes with Control-VPS protection:
// DIRECT (any size) → PEER_RELAY (quota OK) → S3 → WAITING; DERP only for small tails.
package scheduler

import "github.com/meshbridge/meshbridge/internal/probe"

type Route string

const (
	RouteDirect   Route = "DIRECT"
	RoutePeer     Route = "PEER_RELAY"
	RouteS3       Route = "OBJECT_STORAGE"
	RouteWait     Route = "WAITING_FOR_ROUTE"
	RouteDERPSml  Route = "DERP_SMALL"
	RouteRefused  Route = "REFUSED_DERP_LARGE"
)

type Relay struct {
	ID             string
	Healthy        bool
	BytesMonth     int64
	QuotaBytes     int64 // 0 = unlimited
}

func (r Relay) Usable() bool {
	if !r.Healthy {
		return false
	}
	if r.QuotaBytes <= 0 {
		return true
	}
	// critical 95%: no new big jobs.
	return float64(r.BytesMonth) < float64(r.QuotaBytes)*0.95
}

type Decision struct {
	Route   Route
	RelayID string
	Reason  string
}

// Decide is pure and fully unit-tested.
func Decide(class probe.ConnectionClass, sizeBytes, derpLimit int64, relays []Relay, s3Enabled bool) Decision {
	switch class {
	case probe.ClassDirect:
		return Decision{Route: RouteDirect, Reason: "direct p2p preferred"}
	case probe.ClassPeerRelay:
		for _, r := range relays {
			if r.Usable() {
				return Decision{Route: RoutePeer, RelayID: r.ID, Reason: "peer relay with quota OK"}
			}
		}
		if s3Enabled {
			return Decision{Route: RouteS3, Reason: "no usable relay, s3 fallback"}
		}
		return Decision{Route: RouteWait, Reason: "no usable peer relay; waiting"}
	case probe.ClassDERP:
		if sizeBytes <= derpLimit {
			return Decision{Route: RouteDERPSml, Reason: "small file may use DERP fallback"}
		}
		// Big file over DERP: never silently transfer.
		for _, r := range relays {
			if r.Usable() {
				return Decision{Route: RoutePeer, RelayID: r.ID, Reason: "derp refused for large file; use peer relay"}
			}
		}
		if s3Enabled {
			return Decision{Route: RouteS3, Reason: "derp refused for large file; use object storage"}
		}
		return Decision{Route: RouteRefused, Reason: "derp large file refused; waiting for better route"}
	case probe.ClassUnreach, probe.ClassUnknown:
		if s3Enabled {
			return Decision{Route: RouteS3, Reason: "unreachable; async object storage"}
		}
		return Decision{Route: RouteWait, Reason: "no route; waiting"}
	default:
		return Decision{Route: RouteWait, Reason: "unknown class"}
	}
}
