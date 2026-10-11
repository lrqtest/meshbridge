package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/db"
	"github.com/meshbridge/meshbridge/internal/serverlimits"
	"github.com/meshbridge/meshbridge/internal/tunnel"
)

func TestShutdownDrainsHandlersAndMeterBeforeDatabaseClose(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "shutdown.sqlite"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = db.RunMigrations(d, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatal(err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := tunnel.NewGateway(tunnel.GatewayConfig{DB: d})
	g.StartMeter(lifetime)
	entered := make(chan struct{})
	owned := make(chan error, 1)
	h := serverlimits.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		_, err := d.Exec(`INSERT INTO settings(key,value) VALUES('shutdown_handler','drained')`)
		owned <- err
	}), 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: h, BaseContext: func(net.Listener) context.Context { return lifetime }}
	served := make(chan error, 1)
	go func() { served <- s.Serve(ln) }()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		resp, err := http.Get("http://" + ln.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	ctx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err = newShutdownOwner(cancel, []*http.Server{s}, []net.Listener{ln}, []*serverlimits.Requests{h}, g).shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-owned; err != nil {
		t.Fatalf("database closed while handler still owned work: %v", err)
	}
	if err = d.Ping(); err != nil {
		t.Fatal("shutdown closed DB before caller drain verification")
	}
	<-served
	<-clientDone
}

func TestShutdownDeadlineBoundsStalledHandler(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := tunnel.NewGateway(tunnel.GatewayConfig{})
	g.StartMeter(lifetime)
	release := make(chan struct{})
	entered := make(chan struct{})
	h := serverlimits.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }), 1)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	s := &http.Server{Handler: h}
	go s.Serve(ln)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	start := time.Now()
	err := newShutdownOwner(cancel, []*http.Server{s}, []net.Listener{ln}, []*serverlimits.Requests{h}, g).shutdown(ctx)
	close(release)
	_ = h.Wait(context.Background())
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("deadline err=%v elapsed=%s", err, time.Since(start))
	}
}

type blockedCloseListener struct {
	entered, release chan struct{}
	calls            atomic.Int32
}

func (l *blockedCloseListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *blockedCloseListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (l *blockedCloseListener) Close() error {
	l.calls.Add(1)
	close(l.entered)
	<-l.release
	return nil
}

func TestShutdownDeadlineIncludesListenerCloseAndRunsOwnerOnce(t *testing.T) {
	l := &blockedCloseListener{entered: make(chan struct{}), release: make(chan struct{})}
	g := tunnel.NewGateway(tunnel.GatewayConfig{})
	var cancelled atomic.Int32
	owner := newShutdownOwner(func() { cancelled.Add(1) }, nil, []net.Listener{l}, nil, g)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := owner.shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 250*time.Millisecond {
		close(l.release)
		t.Fatalf("blocking Close escaped shutdown deadline: %v", err)
	}
	<-l.entered
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer retryCancel()
	if err = owner.shutdown(retryCtx); !errors.Is(err, context.DeadlineExceeded) {
		close(l.release)
		t.Fatal(err)
	}
	if l.calls.Load() != 1 || cancelled.Load() != 0 {
		close(l.release)
		t.Fatal("repeat shutdown spawned another owner or cancelled before listener stop")
	}
	close(l.release)
	// The first caller deadline remains the owner's deadline, so a later wait
	// observes its error after the owner has finished every operation it can.
	_ = owner.shutdown(context.Background())
	if l.calls.Load() != 1 || cancelled.Load() != 1 {
		t.Fatal("shutdown owner did not complete exactly once")
	}
}
