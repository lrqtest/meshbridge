// agent.go — the intranet side. One outbound WebSocket per tunnel; each
// visitor request arrives as a yamux stream that is piped to the local
// service. The agent never parses visitor HTTP and never listens inbound.
package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Client manages an agent's tunnel connections (one per tunnel).
type Client struct {
	controller string // https://mineai.top
	token      string // device token

	dialer *net.Dialer

	mu    sync.Mutex
	conns map[string]*agentConn // tunnelID -> running connection

	allow []*net.IPNet // extra dial targets beyond loopback
}

// NewClient builds an agent-side tunnel manager. allowCIDRs extends the dial
// policy past loopback (validated here, not trusted from the server).
func NewClient(controller, deviceToken string, allowCIDRs []string) (*Client, error) {
	c := &Client{
		controller: strings.TrimSuffix(controller, "/"),
		token:      deviceToken,
		dialer:     &net.Dialer{Timeout: 5 * time.Second},
		conns:      make(map[string]*agentConn),
	}
	for _, raw := range allowCIDRs {
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("bad allow CIDR %q: %w", raw, err)
		}
		c.allow = append(c.allow, n)
	}
	return c, nil
}

// agentConn is one running tunnel (goroutine with cancel).
type agentConn struct {
	id     string
	target AgentConfig
	cancel context.CancelFunc
	done   chan struct{}
}

// Reconcile starts tunnels that appeared and stops ones that disappeared.
// Called after each heartbeat with the server's view of this device's
// active tunnels. Targets are re-validated against the local dial policy
// every time: a controller-side config change can never widen what this
// agent is willing to dial.
func (c *Client) Reconcile(ctx context.Context, list []AgentConfig) {
	want := make(map[string]AgentConfig, len(list))
	for _, t := range list {
		if err := TargetOK(t.Scheme, t.Host, t.Port); err != nil {
			log.Printf("tunnel %s: refusing server-supplied target: %v", t.ID, err)
			continue
		}
		if !AllowedBy(t.Host, c.allow) {
			log.Printf("tunnel %s: target %s outside local dial policy (see --tunnel-allow)", t.ID, t.Host)
			continue
		}
		want[t.ID] = t
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ac := range c.conns {
		if w, ok := want[id]; !ok || w != ac.target {
			ac.cancel()
			delete(c.conns, id)
		}
	}
	for id, t := range want {
		if _, running := c.conns[id]; running {
			continue
		}
		sub, cancel := context.WithCancel(ctx)
		ac := &agentConn{id: id, target: t, cancel: cancel, done: make(chan struct{})}
		c.conns[id] = ac
		go c.run(sub, ac)
	}
}

// Close stops every tunnel (agent shutdown).
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ac := range c.conns {
		ac.cancel()
		delete(c.conns, id)
	}
}

// run keeps one tunnel connected until ctx is cancelled, reconnecting with
// capped exponential backoff + jitter.
func (c *Client) run(ctx context.Context, ac *agentConn) {
	defer close(ac.done)
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.serveOnce(ctx, ac)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("tunnel %s: %v", ac.id, err)
		}
		// Backoff with jitter: 1s,2s,4s…60s ±50%.
		delay := backoff/2 + time.Duration(rand.Int63n(int64(backoff)))
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// serveOnce dials the controller, upgrades to yamux server, and pipes every
// accepted stream to the local target until the connection dies.
func (c *Client) serveOnce(ctx context.Context, ac *agentConn) error {
	wsURL := c.controller + "/api/v1/tunnels/" + url.PathEscape(ac.id) + "/connect"
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	hdr := http.Header{"Authorization": []string{"Bearer " + c.token}}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPHeader:      hdr,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	sess, err := yamux.Server(netConn, yamuxServerCfg())
	if err != nil {
		netConn.Close()
		return fmt.Errorf("yamux: %w", err)
	}
	defer sess.Close()
	for {
		stream, err := sess.Accept()
		if err != nil {
			return nil // session closed (controller went away or cancel)
		}
		go c.pipe(stream, ac.target)
	}
}

func yamuxServerCfg() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 32
	cfg.KeepAliveInterval = 20 * time.Second
	return cfg
}

// pipe bridges one visitor request (yamux stream) to the local service.
// HTTP and WebSocket traffic both work because the bytes are never parsed.
func (c *Client) pipe(stream io.ReadWriteCloser, t AgentConfig) {
	defer stream.Close()
	if err := TargetOK(t.Scheme, t.Host, t.Port); err != nil {
		return // belt-and-braces: server sent garbage
	}
	addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))
	var conn net.Conn
	var err error
	if t.Scheme == "https" {
		// Local/self-signed certs are the norm for intranet services; the
		// protected hop is the tunnel itself, TLS here only guards the
		// loopback/LAN leg.
		conn, err = tls.DialWithDialer(c.dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec — see comment
			ServerName:         t.Host,
		})
	} else {
		conn, err = c.dialer.Dial("tcp", addr)
	}
	if err != nil {
		return // upstream down; stream close surfaces as 502 to the visitor
	}
	defer conn.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, stream); done <- struct{}{} }()
	<-done
}
