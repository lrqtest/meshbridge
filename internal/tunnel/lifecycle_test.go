package tunnel_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPerTunnelBudgetCoversStreamingBody(t *testing.T) {
	s := newStack(t)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(app.Close)
	u, _ := url.Parse(app.URL)
	port, _ := strconv.Atoi(u.Port())
	tun, _ := s.createTunnel(t, map[string]any{"device_id": "dev1", "target_port": port, "key_required": false}, adminToken)
	s.reconcile(t, tun["id"].(string))
	path := "/t/" + tun["slug"].(string) + "/events"
	var bodies []io.ReadCloser
	t.Cleanup(func() {
		for _, b := range bodies {
			_ = b.Close()
		}
	})
	for range 16 {
		resp, err := s.visitor.Get(s.gwSrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			t.Fatalf("early status %d", resp.StatusCode)
		}
		bodies = append(bodies, resp.Body)
	}
	s.gw.ResetProxy(tun["id"].(string))
	resp, err := s.visitor.Get(s.gwSrv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("17th stream: %d", resp.StatusCode)
	}
	_ = bodies[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err = s.visitor.Get(s.gwSrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == 200 {
			bodies = append(bodies, resp.Body)
			break
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("stream capacity did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPerTunnelBudgetCoversUpgrade(t *testing.T) {
	s := newStack(t)
	tun, _ := s.createTunnel(t, map[string]any{"device_id": "dev1", "target_port": s.appPort, "key_required": false}, adminToken)
	s.reconcile(t, tun["id"].(string))
	path := "/t/" + tun["slug"].(string) + "/up"
	u, _ := url.Parse(s.gwSrv.URL)
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	connect := func() (net.Conn, int) {
		t.Helper()
		c, err := net.DialTimeout("tcp", u.Host, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: rawtest\r\n\r\n", path, u.Host)
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			_ = c.Close()
			t.Fatalf("bad status %q", line)
		}
		code, _ := strconv.Atoi(parts[1])
		for {
			line, err = br.ReadString('\n')
			if err != nil {
				_ = c.Close()
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		if code == 101 {
			_, _ = c.Write([]byte("ping"))
			buf := make([]byte, 4)
			if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
				_ = c.Close()
				t.Fatalf("upgrade echo %q: %v", buf, err)
			}
			_ = c.SetDeadline(time.Time{})
		}
		return c, code
	}
	for range 16 {
		c, code := connect()
		conns = append(conns, c)
		if code != 101 {
			t.Fatalf("early upgrade status %d", code)
		}
	}
	c, code := connect()
	_ = c.Close()
	if code != 503 {
		t.Fatalf("17th upgrade status %d", code)
	}
	_ = conns[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, code = connect()
		if code == 101 {
			conns = append(conns, c)
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("upgrade capacity did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
