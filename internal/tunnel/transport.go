// transport.go — the visitor→agent hop: an http.RoundTripper that opens one
// yamux stream per request on the agent's live session and speaks HTTP/1.1
// over it. WebSocket upgrades pass through because the response body is a
// bidirectional net.Conn wrapper.
package tunnel

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	ErrAgentOffline = errors.New("tunnel: agent offline")
	ErrTunnelBusy   = errors.New("tunnel: too many concurrent requests")
)

// responseHeaderTimeout is the ABSOLUTE cap for upstream response headers,
// counted from when the request has been handed to the transport. It is
// deliberately generous (not a responsiveness SLA): a fast visitor can push
// a large body into the yamux window while the upstream is still consuming
// it, and the gateway cannot tell that apart from a hang. Genuine hangs are
// caught by yamux keepalive (dead agent) and visitor-context cancellation.
// Package var so tests can shorten it.
var responseHeaderTimeout = 30 * time.Minute

// yamuxTripper routes requests onto the gateway's live session for tunnelID.
type yamuxTripper struct {
	g   *Gateway
	tun *Tunnel
	sem chan struct{} // per-tunnel concurrency bound
}

func (t *yamuxTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	default:
		return nil, ErrTunnelBusy
	}
	sess := t.g.session(t.tun.ID)
	if sess == nil {
		return nil, ErrAgentOffline
	}
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentOffline, err)
	}

	type result struct {
		resp *http.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		// No deadline while writing: uploads may legitimately take minutes
		// on slow links (the visitor's pace is not the upstream's fault).
		if err := req.Write(stream); err != nil {
			ch <- result{nil, err}
			return
		}
		// Absolute cap for response headers AFTER the request left us.
		// Deliberately generous: once the request is inside the yamux
		// window the gateway cannot distinguish an upstream legitimately
		// consuming a large body from a hung one — real hangs are caught
		// by yamux keepalive (dead agent) and visitor cancellation.
		_ = stream.SetReadDeadline(time.Now().Add(t.g.headerTimeout))
		br := bufio.NewReaderSize(stream, 32*1024)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		// Keep ReadResponse's body as the reader — it decodes the actual
		// framing (chunked / Content-Length). The raw stream is layered in
		// for Close (connection teardown) and for Write, which ReverseProxy
		// uses for the bidirectional copy after a 101 upgrade.
		body := &wrapBody{r: resp.Body, s: stream}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			// After a 101 there is no framing: read the raw stream (the
			// bufio may already hold early upgrade data).
			body.r = br
		}
		resp.Body = body
		ch <- result{resp, nil}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			stream.Close()
			return nil, r.err
		}
		// Body / upgraded connection may stream for as long as it likes.
		_ = stream.SetDeadline(time.Time{})
		return r.resp, nil
	case <-req.Context().Done():
		stream.Close() // unblocks the goroutine; buffered chan lets it exit
		return nil, req.Context().Err()
	}
}

// wrapBody pairs the framing-aware decoder from http.ReadResponse with the
// raw yamux stream. It implements io.ReadWriteCloser so WebSocket (101)
// upgrades are copied bidirectionally by httputil.ReverseProxy.
type wrapBody struct {
	r io.Reader // ReadResponse's body (decoded)
	s io.ReadWriteCloser
}

func (b *wrapBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *wrapBody) Write(p []byte) (int, error) {
	return b.s.Write(p) // only used after a 101 switch
}
func (b *wrapBody) Close() error {
	if c, ok := b.r.(io.Closer); ok {
		_ = c.Close()
	}
	return b.s.Close()
}

// ---- byte counters (usage accounting) ----

// countReader counts request body bytes as they are consumed.
type countReader struct {
	r io.ReadCloser
	n *int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}

func (c *countReader) Close() error { return c.r.Close() }

// countWriter wraps the visitor-facing ResponseWriter, forwarding Flush and
// Hijack (needed for SSE and upgrades) while counting response bytes.
type countWriter struct {
	http.ResponseWriter
	n *int64
	g *Gateway // set when hijacked traffic must be recorded on close
	t *Tunnel
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}

func (c *countWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack passes the visitor connection to ReverseProxy for upgrades. The
// returned conn keeps counting; once it closes, the bytes written after the
// hijack are added to the tunnel's usage (ReverseProxy has already returned).
func (c *countWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := c.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("tunnel: response writer not hijackable")
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if c.g == nil || c.t == nil {
		return &countConn{Conn: conn, n: c.n}, rw, nil
	}
	return &countConn{Conn: conn, n: c.n, base: atomic.LoadInt64(c.n), g: c.g, t: c.t}, rw, nil
}

type countConn struct {
	net.Conn
	n    *int64
	base int64    // bytes already recorded before the hijack
	g    *Gateway // nil in tests: count only
	t    *Tunnel
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
	}
	return n, err
}

func (c *countConn) Close() error {
	err := c.Conn.Close()
	if c.g != nil && c.t != nil {
		if delta := atomic.LoadInt64(c.n) - c.base; delta > 0 {
			c.g.recordUsage(c.t, 0, delta)
		}
	}
	return err
}

var _ http.RoundTripper = (*yamuxTripper)(nil)
