// Package serverlimits selects Mesh's independent control-plane and visitor
// budgets; shared HTTP primitives own socket and handler admission.
package serverlimits

import (
	"net"
	"net/http"

	"github.com/mineai/kit/httpx"
)

const API = 64
const Gateway = 128

// Listener retains Mesh's blocking admission policy. The shared app family's
// shedding listener is a separate policy for workloads that require it.
func Listener(inner net.Listener, limit int) net.Listener {
	return httpx.BlockingListener(inner, limit)
}

type Requests = httpx.Requests

// Handler holds a slot until the entire handler, including upgrades, returns.
func Handler(next http.Handler, limit int) *Requests {
	return httpx.NewRequests(next, limit)
}
