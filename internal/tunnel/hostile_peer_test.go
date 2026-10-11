package tunnel

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// The peer sends a real framed response but deliberately never closes its
// stream after receiving FIN. A plain yamux.Close cannot unblock local reads.
func hostileSession(t *testing.T, response string) *yamux.Session {
	t.Helper()
	a, b := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	client, err := yamux.Client(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := yamux.Server(b, cfg)
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		stream, err := peer.AcceptStream()
		if err != nil {
			return
		}
		r, err := http.ReadRequest(bufio.NewReader(stream))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		_, _ = io.WriteString(stream, response)
		<-peer.CloseChan() // ignore FIN and keep the response unfinished
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("hostile peer goroutine did not exit")
		}
	})
	return client
}

const unfinishedResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nready\r\n"

func TestHostilePeerBodyReadStopsOnCancelAndClose(t *testing.T) {
	for _, mode := range []string{"cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			g := NewGateway(GatewayConfig{})
			g.sess["hostile"] = hostileSession(t, unfinishedResponse)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/events", nil)
			tr := &yamuxTripper{g: g, tun: &Tunnel{ID: "hostile"}}
			resp, err := tr.RoundTrip(r)
			if err != nil {
				t.Fatal(err)
			}
			ready := make([]byte, 5)
			if _, err := io.ReadFull(resp.Body, ready); err != nil {
				t.Fatal(err)
			}
			readDone := make(chan struct{})
			go func() { _, _ = io.Copy(io.Discard, resp.Body); close(readDone) }()
			closeDone := make(chan struct{})
			go func() {
				if mode == "cancel" {
					cancel()
				}
				_ = resp.Body.Close()
				close(closeDone)
			}()
			select {
			case <-readDone:
			case <-time.After(time.Second):
				t.Fatal("FIN-ignoring peer kept body.Read blocked")
			}
			select {
			case <-closeDone:
			case <-time.After(time.Second):
				t.Fatal("Body.Close kept draining hostile peer")
			}
		})
	}
}

type signalWriter struct {
	*httptest.ResponseRecorder
	ready chan struct{}
	once  sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	w.once.Do(func() { close(w.ready) })
	return n, err
}

func TestHostilePeerCancellationReleasesGatewayAdmission(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	g.sess["hostile"] = hostileSession(t, unfinishedResponse)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/events", nil)
	w := &signalWriter{ResponseRecorder: httptest.NewRecorder(), ready: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.proxyRequest(w, r, &Tunnel{ID: "hostile", TargetScheme: "http", TargetHost: "127.0.0.1", TargetPort: 80}, false)
	}()
	select {
	case <-w.ready:
	case <-time.After(time.Second):
		t.Fatal("stream did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled proxy kept admission held")
	}
	g.admissionMu.Lock()
	left := len(g.admission)
	g.admissionMu.Unlock()
	if left != 0 || len(g.gsem) != 0 {
		t.Fatalf("admission leaked: tunnels=%d global=%d", left, len(g.gsem))
	}
}

// Race header deadline changes against cancellation repeatedly: no header/body
// transition may clear the immediate cancellation deadline.
func TestCancellationCannotClearHeaderDeadline(t *testing.T) {
	for range 24 {
		g := NewGateway(GatewayConfig{})
		g.sess["hostile"] = hostileSession(t, unfinishedResponse)
		ctx, cancel := context.WithCancel(context.Background())
		r, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/events", nil)
		resp, err := (&yamuxTripper{g: g, tun: &Tunnel{ID: "hostile"}}).RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(resp.Body, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		s := resp.Body.(*wrapBody).s.(*interruptibleStream)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; cancel(); _ = s.Close() }()
		go func() {
			defer wg.Done()
			<-start
			_ = s.SetReadDeadline(time.Now().Add(time.Hour))
			_ = s.clearForBody(ctx)
		}()
		close(start)
		wg.Wait()
		readDone := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, resp.Body); close(readDone) }()
		select {
		case <-readDone:
		case <-time.After(time.Second):
			t.Fatal("header transition cleared cancellation on FIN-ignoring peer")
		}
		_ = resp.Body.Close()
	}
}
