package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordAdmissionSerialAndCancelled(t *testing.T) {
	hash, err := HashPassword("budget-test-password")
	if err != nil {
		t.Fatal(err)
	}
	release, err := acquirePasswordWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func(context.Context) error{
		"hash": func(ctx context.Context) error {
			_, err := HashPasswordContext(ctx, "budget-test-password")
			return err
		},
		"verify": func(ctx context.Context) error {
			_, err := VerifyPasswordContext(ctx, hash, "budget-test-password")
			return err
		},
		"dummy": func(ctx context.Context) error { return DummyVerifyContext(ctx, "budget-test-password") },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		if err := call(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: %v", name, err)
		}
		cancel()
	}
	release()
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := acquirePasswordWork(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			n := active.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("concurrent password jobs: %d", peak.Load())
	}
	if ok, err := VerifyPasswordContext(context.Background(), hash, "budget-test-password"); err != nil || !ok {
		t.Fatalf("gate did not recover: %v %v", ok, err)
	}
}
