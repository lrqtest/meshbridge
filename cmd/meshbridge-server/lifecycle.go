package main

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/meshbridge/meshbridge/internal/serverlimits"
	"github.com/meshbridge/meshbridge/internal/tunnel"
	"github.com/mineai/kit/lifecycle"
)

// SQLite remains owned by main until handlers, tunnel session watchers and
// meter work have drained. The shared owner bounds the complete callback,
// including admission locks and listener Close, with the first caller's ctx.
type shutdownOwner struct {
	owner *lifecycle.Owner
}

func newShutdownOwner(cancel context.CancelFunc, servers []*http.Server, listeners []net.Listener, handlers []*serverlimits.Requests, g *tunnel.Gateway) *shutdownOwner {
	return &shutdownOwner{owner: lifecycle.NewOwner(func(ctx context.Context) error {
		return shutdownOwned(ctx, cancel, servers, listeners, handlers, g)
	})}
}

func (o *shutdownOwner) shutdown(ctx context.Context) error {
	return o.owner.Shutdown(ctx)
}

// Mesh supplies its domain-specific drain order to the shared owner. If a
// deadline expires, main must exit without closing SQLite under a live owner.
func shutdownOwned(ctx context.Context, cancel context.CancelFunc, servers []*http.Server, listeners []net.Listener, handlers []*serverlimits.Requests, g *tunnel.Gateway) error {
	for _, h := range handlers {
		h.Stop()
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
	cancel()
	if err := g.ShutdownSessions(ctx); err != nil {
		return err
	}
	result := lifecycle.ShutdownHTTP(ctx, servers...)
	for _, h := range handlers {
		result = errors.Join(result, h.Wait(ctx))
	}
	return errors.Join(result, g.StopMeter(ctx))
}
