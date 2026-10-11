package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func retainedSession(t *testing.T) *yamux.Session {
	t.Helper()
	a, b := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.AcceptBacklog = 64
	cfg.StreamCloseTimeout = 30 * time.Second
	client, err := yamux.Client(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := yamux.Server(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := peer.AcceptStream(); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close(); <-done })
	return client
}

func TestRetainedStreamAdmissionPerSessionAndGlobal(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	var sessions []*yamux.Session
	for range 5 {
		sessions = append(sessions, retainedSession(t))
	}
	for i, s := range sessions[:4] {
		for range 32 {
			if _, err := g.openStream(context.Background(), s); err != nil {
				t.Fatalf("session %d: %v", i, err)
			}
		}
		if _, err := g.openStream(context.Background(), s); !errors.Is(err, ErrTunnelBusy) {
			t.Fatalf("per-session cap: %v", err)
		}
	}
	if _, err := g.openStream(context.Background(), sessions[4]); !errors.Is(err, ErrTunnelBusy) {
		t.Fatalf("global retained cap: %v", err)
	}
	_ = sessions[0].Close()
	if _, err := g.openStream(context.Background(), sessions[4]); err != nil {
		t.Fatalf("released retained capacity: %v", err)
	}
}

func TestConcurrentAndPendingStreamOpensShareAdmission(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	s := retainedSession(t)
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for range 128 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.openStream(context.Background(), s); err == nil {
				admitted.Add(1)
			} else if !errors.Is(err, ErrTunnelBusy) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() > 32 || s.NumStreams() > 32 {
		t.Fatalf("concurrent opens=%d retained=%d", admitted.Load(), s.NumStreams())
	}
	pending := retainedSession(t)
	g.openMu.Lock()
	g.pendingOpens[pending] = 32
	g.openMu.Unlock()
	if _, err := g.openStream(context.Background(), pending); !errors.Is(err, ErrTunnelBusy) {
		t.Fatalf("pending cap bypass: %v", err)
	}
	g.openMu.Lock()
	delete(g.pendingOpens, pending)
	g.openMu.Unlock()
}

func TestAgentAdmissionCountsPendingAndStopsDuringShutdown(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	var releases []func()
	for range 32 {
		release, ok := g.AcquireAgent()
		if !ok {
			t.Fatal("early agent rejection")
		}
		releases = append(releases, release)
	}
	if release, ok := g.AcquireAgent(); ok {
		release()
		t.Fatal("agent cap bypass")
	}
	releases[0]()
	releases[0]()
	release, ok := g.AcquireAgent()
	if !ok {
		t.Fatal("agent release did not recover")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
	if err := g.ShutdownSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if release, ok := g.AcquireAgent(); ok {
		release()
		t.Fatal("shutdown allowed agent handshake")
	}
}

func TestSessionTeardownUnblocksStalledVisitorUploadAndDeleteDrains(t *testing.T) {
	d := meterDB(t)
	_, err := d.Exec(`UPDATE tunnels SET key_required=0 WHERE id='one'`)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(GatewayConfig{DB: d})
	g.sess["one"] = retainedSession(t)
	s := httptest.NewServer(g.Handler())
	defer s.Close()
	u, _ := url.Parse(s.URL)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Write([]byte("POST /t/11111111111111111111111111111111/upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 32\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		g.meter.mu.Lock()
		active := g.meter.active["one"]
		reserved := int64(0)
		for _, e := range g.meter.entries {
			reserved += e.reserved
		}
		g.meter.mu.Unlock()
		if active == 1 && reserved > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upload did not reserve while waiting for body")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := g.PrepareDelete(ctx, "one")
	if err != nil {
		t.Fatalf("stalled upload did not drain: %v", err)
	}
	if _, err = d.Exec(`DELETE FROM tunnels WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	release()
	h := g.meter.begin(&Tunnel{ID: "one"})
	defer h.close()
	if _, err = h.write(context.Background(), []byte("late"), func([]byte) (int, error) { t.Fatal("late stale tunnel wrote bytes"); return 0, nil }, 0); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("late removed tunnel: %v", err)
	}
	if !g.MeterReady() {
		t.Fatal("legitimate delete degraded meter")
	}
}

func TestProxyResetStaleBuilderUsesCurrentRequestSandbox(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	stale := &Tunnel{ID: "one", Sandbox: false}
	current := &Tunnel{ID: "one", Sandbox: true}
	g.ResetProxy("one")
	g.proxyFor(stale) // A request loaded its config before the PATCH/reset.
	p := g.proxyFor(current)
	ctx := context.WithValue(context.Background(), ctxTunnel{}, current)
	ctx = context.WithValue(ctx, ctxPathMode{}, true)
	r, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/", nil)
	resp := &http.Response{Request: r, Header: make(http.Header)}
	if err := p.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("stale proxy closure bypassed current sandbox")
	}
}

func TestLateAgentAttachAfterDeleteIsRejected(t *testing.T) {
	d := meterDB(t)
	g := NewGateway(GatewayConfig{DB: d})
	release, err := g.PrepareDelete(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	during := retainedSession(t)
	g.Attach("one", during)
	if g.Online("one") || !during.IsClosed() {
		t.Fatal("agent attached during removal")
	}
	if _, err = d.Exec(`DELETE FROM tunnels WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	release()
	late := retainedSession(t)
	g.Attach("one", late)
	if g.Online("one") || !late.IsClosed() {
		t.Fatal("late authenticated handshake resurrected removed tunnel")
	}
}

type stalledVisitorWriter struct {
	*httptest.ResponseRecorder
	ready, unblock       chan struct{}
	readyOnce, closeOnce sync.Once
}

func (w *stalledVisitorWriter) Write([]byte) (int, error) {
	w.readyOnce.Do(func() { close(w.ready) })
	<-w.unblock
	return 0, net.ErrClosed
}
func (w *stalledVisitorWriter) SetReadDeadline(time.Time) error { return nil }
func (w *stalledVisitorWriter) SetWriteDeadline(time.Time) error {
	w.closeOnce.Do(func() { close(w.unblock) })
	return nil
}

func TestSessionTeardownUnblocksStalledVisitorResponseWrite(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	g.sess["hostile"] = hostileSession(t, unfinishedResponse)
	r, _ := http.NewRequest("GET", "http://127.0.0.1/events", nil)
	w := &stalledVisitorWriter{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{}), unblock: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.proxyRequest(w, r, &Tunnel{ID: "hostile", TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 80}, false)
	}()
	select {
	case <-w.ready:
	case <-time.After(time.Second):
		t.Fatal("visitor write did not start")
	}
	g.CloseSessions()
	select {
	case <-done:
	case <-time.After(time.Second):
		w.closeOnce.Do(func() { close(w.unblock) })
		t.Fatal("backend teardown kept visitor Write and quota reservation blocked")
	}
	g.admissionMu.Lock()
	left := len(g.admission)
	g.admissionMu.Unlock()
	if left != 0 || len(g.gsem) != 0 {
		t.Fatal("stalled visitor write retained request admission")
	}
}

func TestDeletionInterruptsBlockedVisitorWrite(t *testing.T) {
	d := meterDB(t)
	if _, err := d.Exec(`UPDATE tunnels SET key_required=0 WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	g := NewGateway(GatewayConfig{DB: d})
	body := strings.Repeat("x", 16<<20)
	g.sess["one"] = hostileSession(t, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	s := httptest.NewServer(g.Handler())
	defer s.Close()
	u, _ := url.Parse(s.URL)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(1024)
	}
	if _, err = fmt.Fprintf(c, "GET /t/11111111111111111111111111111111/big HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var spent int64
	for {
		g.meter.mu.Lock()
		spent = 0
		for _, e := range g.meter.entries {
			spent += e.total
		}
		active := g.meter.active["one"]
		g.meter.mu.Unlock()
		if spent >= 64<<10 && active == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("large response never started")
		}
		time.Sleep(time.Millisecond)
	}
	// The visitor keeps TCP alive but never reads; fill its small receive window.
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := g.PrepareDelete(ctx, "one")
	if err != nil {
		t.Fatalf("cancel kept visitor Write blocked after %d settled bytes: %v", spent, err)
	}
	release()
	g.admissionMu.Lock()
	left := len(g.admission)
	g.admissionMu.Unlock()
	if left != 0 || len(g.gsem) != 0 {
		t.Fatal("unread visitor retained handler admission after drain")
	}
}

func TestShutdownDeadlineIncludesAttachDatabaseWait(t *testing.T) {
	d := meterDB(t)
	held, err := d.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	g := NewGateway(GatewayConfig{DB: d})
	sess := retainedSession(t)
	attached := make(chan struct{})
	go func() { defer close(attached); g.Attach("one", sess) }()
	deadline := time.Now().Add(time.Second)
	for {
		if !g.admissionMu.TryLock() {
			break
		}
		g.admissionMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("Attach did not enter DB validation")
		}
		time.Sleep(time.Millisecond)
	}
	release := time.AfterFunc(500*time.Millisecond, func() { _ = held.Close() })
	defer release.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = g.ShutdownSessions(ctx)
	elapsed := time.Since(start)
	// The production error path exits the process. This test drains remaining
	// owners before fixture cleanup so SQLite never closes under their queries.
	<-attached
	if waitErr := g.ShutdownSessions(context.Background()); waitErr != nil {
		t.Fatal(waitErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) || elapsed > 250*time.Millisecond {
		t.Fatalf("shutdown deadline waited %s for Attach DB lock: %v", elapsed, err)
	}
}
