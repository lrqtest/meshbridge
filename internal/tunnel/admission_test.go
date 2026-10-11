package tunnel

import (
	"sync"
	"testing"
)

func TestProxyCacheAndAdmissionAreSharedAcrossReset(t *testing.T) {
	g := NewGateway(GatewayConfig{})
	tun := &Tunnel{ID: "same"}
	var wg sync.WaitGroup
	proxies := make(chan *tunProxy, 24)
	for range 24 {
		wg.Add(1)
		go func() { defer wg.Done(); g.proxyFor(tun); v, _ := g.proxy.Load(tun.ID); proxies <- v.(*tunProxy) }()
	}
	wg.Wait()
	close(proxies)
	var first *tunProxy
	for p := range proxies {
		if first == nil {
			first = p
		} else if first != p {
			t.Fatal("separate proxy cache entries")
		}
	}
	var releases []func()
	for range maxConcurrentPerTunnel {
		release, ok := g.admitTunnel(tun.ID)
		if !ok {
			t.Fatal("early admission rejection")
		}
		releases = append(releases, release)
	}
	g.ResetProxy(tun.ID)
	g.proxyFor(tun)
	if release, ok := g.admitTunnel(tun.ID); ok {
		release()
		t.Fatal("reset bypassed full admission budget")
	}
	releases[0]()
	releases[0]() // release is idempotent
	release, ok := g.admitTunnel(tun.ID)
	if !ok {
		t.Fatal("released capacity did not recover")
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
	if len(g.admission) != 0 {
		t.Fatal("idle admission state leaked")
	}
}
