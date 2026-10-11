package serverlimits

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAcceptedSocketsBoundAndCloseReleaseOnce(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := Listener(raw, 1)
	defer l.Close()
	peer, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	first, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	secondPeer, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer secondPeer.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	select {
	case <-accepted:
		t.Fatal("accepted past socket budget")
	case <-time.After(20 * time.Millisecond):
	}
	_ = first.Close()
	_ = first.Close()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("released socket not accepted")
		}
		_ = c.Close()
	case <-time.After(time.Second):
		t.Fatal("closed socket did not release capacity")
	}
	// Verify recovery through the public listener behavior rather than the
	// shared implementation's private semaphore.
	thirdPeer, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer thirdPeer.Close()
	go func() { c, _ := l.Accept(); accepted <- c }()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("double close lost the listener's capacity")
		}
		_ = c.Close()
	case <-time.After(time.Second):
		t.Fatal("double close leaked socket budget")
	}
}

func TestListenerCloseUnblocksSaturatedAccept(t *testing.T) {
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	l := Listener(raw, 1)
	peer, _ := net.Dial("tcp", raw.Addr().String())
	defer peer.Close()
	first, _ := l.Accept()
	defer first.Close()
	done := make(chan error, 1)
	go func() { _, err := l.Accept(); done <- err }()
	_ = l.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("saturated listener close hung")
	}
}

func TestRequestBoundsWaitAndStreamingBody(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte("done"))
	}), 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil)) }()
	}
	<-entered
	<-entered
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("overflow: %d %s", w.Code, w.Body.String())
	}
	done := make(chan error, 1)
	go func() { done <- h.Wait(context.Background()) }()
	select {
	case <-done:
		t.Fatal("drain returned while handlers running")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("shutdown admitted request")
	}
}
