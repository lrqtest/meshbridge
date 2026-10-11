// transport.go — the visitor→agent hop: an http.RoundTripper that opens one
// yamux stream per request on the agent's live session and speaks HTTP/1.1
// over it. WebSocket upgrades pass through because the response body is a
// bidirectional net.Conn wrapper.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
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
}

func (t *yamuxTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	sess := t.g.session(t.tun.ID)
	if sess == nil {
		return nil, ErrAgentOffline
	}
	rawStream, err := t.g.openStream(req.Context(), sess)
	if err != nil {
		if errors.Is(err, ErrTunnelBusy) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrAgentOffline, err)
	}
	stream := &interruptibleStream{Conn: rawStream}
	// Cancellation must also reach a stalled response body AFTER RoundTrip
	// returns its headers. Without this, abandoned SSE reads keep proxy slots.
	stopCancel := context.AfterFunc(req.Context(), func() { _ = stream.Close() })

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
		body := &wrapBody{r: resp.Body, s: stream, stopCancel: stopCancel}
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
			stopCancel()
			stream.Close()
			return nil, r.err
		}
		// Body / upgraded connection may stream for as long as it likes.
		if err := stream.clearForBody(req.Context()); err != nil {
			_ = r.resp.Body.Close()
			return nil, err
		}
		return r.resp, nil
	case <-req.Context().Done():
		stopCancel()
		stream.Close() // unblocks the goroutine; buffered chan lets it exit
		return nil, req.Context().Err()
	}
}

// yamux.Close sends FIN but permits further reads. Force pending reads and
// writes to stop before sending FIN, and serialize later deadline changes so
// header completion cannot restore an open-ended read after cancellation.
type interruptibleStream struct {
	net.Conn
	mu          sync.Mutex
	interrupted bool
	once        sync.Once
	closeErr    error
}

func (s *interruptibleStream) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.interrupted {
		return nil
	}
	return s.Conn.SetReadDeadline(deadline)
}

func (s *interruptibleStream) clearForBody(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.interrupted {
		return net.ErrClosed
	}
	return s.Conn.SetDeadline(time.Time{})
}

func (s *interruptibleStream) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.interrupted = true
		_ = s.Conn.SetDeadline(time.Now())
		s.mu.Unlock()
		s.closeErr = s.Conn.Close()
	})
	return s.closeErr
}

// wrapBody pairs the framing-aware decoder from http.ReadResponse with the
// raw yamux stream. It implements io.ReadWriteCloser so WebSocket (101)
// upgrades are copied bidirectionally by httputil.ReverseProxy.
type wrapBody struct {
	r          io.Reader // ReadResponse's body (decoded)
	s          io.ReadWriteCloser
	stopCancel func() bool
	once       sync.Once
	closeErr   error
}

func (b *wrapBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *wrapBody) Write(p []byte) (int, error) {
	return b.s.Write(p) // only used after a 101 switch
}
func (b *wrapBody) Close() error {
	b.once.Do(func() {
		if b.stopCancel != nil {
			b.stopCancel()
		}
		// Close the stream before the framing decoder: the decoder otherwise
		// drains a never-ending response and never releases the connection.
		b.closeErr = b.s.Close()
		if c, ok := b.r.(io.Closer); ok {
			_ = c.Close()
		}
	})
	return b.closeErr
}

// ---- byte counters (usage accounting) ----

// countReader counts request body bytes as they are consumed.
type countReader struct {
	r     io.ReadCloser
	meter *requestMeter
	ctx   context.Context
	g     *Gateway
}

func (c *countReader) Read(p []byte) (int, error) {
	return c.meter.read(c.ctx, p, c.r.Read, c.g.globalBudget())
}

func (c *countReader) Close() error { return c.r.Close() }

// countWriter wraps the visitor-facing ResponseWriter, forwarding Flush and
// Hijack (needed for SSE and upgrades) while counting response bytes.
type countWriter struct {
	http.ResponseWriter
	meter *requestMeter
	ctx   context.Context
	g     *Gateway
}

func (c *countWriter) Write(p []byte) (int, error) {
	return c.meter.write(c.ctx, p, c.ResponseWriter.Write, c.g.globalBudget())
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
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	// The server reader may already contain upgraded bytes read with the HTTP
	// headers. Reading it through countConn counts that prefix once, then all
	// subsequent socket reads; ReverseProxy copies directly from the conn.
	cc := &countConn{Conn: conn, reader: rw.Reader, meter: c.meter, ctx: c.ctx, g: c.g}
	return cc, bufio.NewReadWriter(bufio.NewReader(cc), bufio.NewWriter(cc)), nil
}

type countConn struct {
	net.Conn
	reader   io.Reader
	meter    *requestMeter
	ctx      context.Context
	g        *Gateway
	once     sync.Once
	closeErr error
}

func (c *countConn) Read(p []byte) (int, error) {
	return c.meter.read(c.ctx, p, c.reader.Read, c.g.globalBudget())
}

func (c *countConn) Write(p []byte) (int, error) {
	return c.meter.write(c.ctx, p, c.Conn.Write, c.g.globalBudget())
}

func (c *countConn) Close() error {
	c.once.Do(func() {
		_ = c.Conn.SetDeadline(time.Now())
		c.closeErr = c.Conn.Close()
		stopped, err := c.meter.close()
		c.g.meterResult(stopped, err)
	})
	return c.closeErr
}

var _ http.RoundTripper = (*yamuxTripper)(nil)
