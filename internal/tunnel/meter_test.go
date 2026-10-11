package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meshbridge/meshbridge/internal/db"
)

func meterDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "meter.sqlite"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err = db.RunMigrations(d, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id,username,password_hash,role,created_at) VALUES('u','owner','unused','admin',1)`,
		`INSERT INTO devices(id,hostname,owner_user_id,created_at) VALUES('d','box','u',1)`,
		`INSERT INTO tunnels(id,device_id,slug,target_port,monthly_quota_bytes,created_by,created_at,updated_at) VALUES('one','d','11111111111111111111111111111111',80,0,'u',1,1),('two','d','22222222222222222222222222222222',80,0,'u',1,1)`,
	} {
		if _, err = d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func usage(t *testing.T, d *sql.DB, id, month string) (int64, int64) {
	t.Helper()
	var in, out int64
	if err := d.QueryRow(`SELECT bytes_in,bytes_out FROM tunnel_usage WHERE tunnel_id=? AND month=?`, id, month).Scan(&in, &out); err != nil {
		t.Fatal(err)
	}
	return in, out
}

func TestMeterOrdinaryBothDirectionsAndWriterSemantics(t *testing.T) {
	d := meterDB(t)
	m := newUsageMeter(d)
	h := m.begin(&Tunnel{ID: "one"})
	ctx := context.Background()
	in := bytes.Repeat([]byte("i"), meterChunk*2+7)
	if n, err := io.Copy(io.Discard, &countReader{r: io.NopCloser(bytes.NewReader(in)), meter: h, ctx: ctx, g: NewGateway(GatewayConfig{})}); err != nil || n != int64(len(in)) {
		t.Fatalf("read %d %v", n, err)
	}
	out := bytes.Repeat([]byte("o"), meterChunk*3+9)
	var dst bytes.Buffer
	if n, err := h.write(ctx, out, dst.Write, 0); err != nil || n != len(out) {
		t.Fatalf("write %d %v", n, err)
	}
	if n, err := h.write(ctx, []byte("short"), func(p []byte) (int, error) { return 2, nil }, 0); n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer: %d %v", n, err)
	}
	if _, err := h.close(); err != nil {
		t.Fatal(err)
	}
	_, _ = h.close()
	a, b := usage(t, d, "one", MonthKey(time.Now()))
	if a != int64(len(in)) || b != int64(len(out)+2) {
		t.Fatalf("usage %d/%d", a, b)
	}
	if len(m.entries) != 0 || len(m.active) != 0 || m.pending != 0 {
		t.Fatal("idle/dirty meter state leaked")
	}
}

func TestMeterConcurrentTunnelAndGlobalReservations(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(map[bool]string{false: "tunnel", true: "global"}[global], func(t *testing.T) {
			d := meterDB(t)
			if !global {
				if _, err := d.Exec(`UPDATE tunnels SET monthly_quota_bytes=1024 WHERE id='one'`); err != nil {
					t.Fatal(err)
				}
			}
			m := newUsageMeter(d)
			var accepted atomic.Int64
			var wg sync.WaitGroup
			for i := range 128 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					id := "one"
					quota := int64(1024)
					limit := int64(0)
					if global {
						if i%2 != 0 {
							id = "two"
						}
						quota = 0
						limit = 1024
					}
					h := m.begin(&Tunnel{ID: id, MonthlyQuotaByte: quota})
					defer h.close()
					for range 32 {
						n, err := h.write(context.Background(), make([]byte, 64), func(p []byte) (int, error) { accepted.Add(int64(len(p))); return len(p), nil }, limit)
						if err != nil {
							if !errors.Is(err, ErrQuota) && !errors.Is(err, ErrGlobalQuota) && !errors.Is(err, ErrTunnelBusy) && !errors.Is(err, ErrAgentOffline) {
								t.Error(err)
							}
							break
						}
						if n != 64 {
							t.Error("short full write")
						}
					}
				}()
			}
			wg.Wait()
			if accepted.Load() != 1024 {
				t.Fatalf("shared balance allowed %d bytes", accepted.Load())
			}
		})
	}
}

func TestMeterReservedOnlySaturationDoesNotTripQuota(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(map[bool]string{false: "tunnel", true: "global"}[global], func(t *testing.T) {
			d := meterDB(t)
			g := NewGateway(GatewayConfig{DB: d})
			quota := int64(32)
			limit := int64(0)
			if global {
				quota = 0
				limit = 32
			}
			if _, err := d.Exec(`UPDATE tunnels SET monthly_quota_bytes=? WHERE id='one'`, quota); err != nil {
				t.Fatal(err)
			}
			h := g.meter.begin(&Tunnel{ID: "one", MonthlyQuotaByte: quota})
			other := g.meter.begin(&Tunnel{ID: "one", MonthlyQuotaByte: quota})
			defer h.close()
			defer other.close()
			started := make(chan struct{})
			release := make(chan struct{})
			readDone := make(chan error, 1)
			go func() {
				_, err := h.read(context.Background(), make([]byte, 32), func([]byte) (int, error) { close(started); <-release; return 0, io.EOF }, limit)
				readDone <- err
			}()
			<-started
			if _, err := other.write(context.Background(), []byte("ok"), func(p []byte) (int, error) { t.Fatal("write bypassed active reservation"); return len(p), nil }, limit); !errors.Is(err, ErrTunnelBusy) {
				t.Fatalf("reserved-only saturation: %v", err)
			}
			var status string
			_ = d.QueryRow(`SELECT status FROM tunnels WHERE id='one'`).Scan(&status)
			if status != "active" || !g.MeterReady() {
				t.Fatalf("reservation tripped persistent quota/degradation: %s %v", status, g.MeterReady())
			}
			close(release)
			if err := <-readDone; !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if n, err := other.write(context.Background(), []byte("ok"), func(p []byte) (int, error) { return len(p), nil }, limit); n != 2 || err != nil {
				t.Fatalf("unused reservation not returned: %d %v", n, err)
			}
		})
	}
}

func TestMeterFinalCloseWaitsForIOAndIsIdempotent(t *testing.T) {
	d := meterDB(t)
	m := newUsageMeter(d)
	h := m.begin(&Tunnel{ID: "one"})
	started := make(chan struct{})
	release := make(chan struct{})
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = h.write(context.Background(), []byte("done"), func(p []byte) (int, error) { close(started); <-release; return len(p), nil }, 0)
	}()
	<-started
	closed := make(chan struct{})
	go func() { defer close(closed); _, _ = h.close() }()
	select {
	case <-closed:
		t.Fatal("final close discarded in-flight bytes")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-written
	<-closed
	_, _ = h.close()
	a, b := usage(t, d, "one", MonthKey(time.Now()))
	if a != 0 || b != 4 {
		t.Fatalf("usage %d/%d", a, b)
	}
}

type meterHijacker struct {
	net.Conn
	rw     *bufio.ReadWriter
	header http.Header
}

func (w *meterHijacker) Header() http.Header                          { return w.header }
func (w *meterHijacker) Write(p []byte) (int, error)                  { return w.Conn.Write(p) }
func (w *meterHijacker) WriteHeader(int)                              {}
func (w *meterHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.Conn, w.rw, nil }

func TestMeterUpgradeBufferedPrefixBothDirectionsDoubleClose(t *testing.T) {
	d := meterDB(t)
	g := NewGateway(GatewayConfig{DB: d})
	h := g.meter.begin(&Tunnel{ID: "one"})
	a, b := net.Pipe()
	defer b.Close()
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte("prefix")), a))
	_, _ = reader.Peek(6)
	w := &meterHijacker{Conn: a, rw: bufio.NewReadWriter(reader, bufio.NewWriter(a)), header: make(http.Header)}
	cw := &countWriter{ResponseWriter: w, meter: h, ctx: context.Background(), g: g}
	c, _, err := cw.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	drained := make(chan struct{})
	go func() { defer close(drained); _, _ = io.Copy(io.Discard, b) }()
	if _, err = c.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_ = c.Close()
	_, _ = h.close()
	<-drained
	in, out := usage(t, d, "one", MonthKey(time.Now()))
	if in != 6 || out != 7 {
		t.Fatalf("prefix/payload counted %d/%d", in, out)
	}
}

func TestMeterStreamPeriodicAndGlobalThresholdFlush(t *testing.T) {
	d := meterDB(t)
	g := NewGateway(GatewayConfig{DB: d})
	ctx, cancel := context.WithCancel(context.Background())
	g.StartMeter(ctx)
	defer cancel()
	h := g.meter.begin(&Tunnel{ID: "one"})
	if _, err := h.write(ctx, []byte("live"), func(p []byte) (int, error) { return len(p), nil }, 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int64
		_ = d.QueryRow(`SELECT COALESCE(SUM(bytes_out),0) FROM tunnel_usage`).Scan(&n)
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live stream not flushed within timer")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := h.write(ctx, make([]byte, meterFlushBytes), func(p []byte) (int, error) { return len(p), nil }, 0); err != nil {
		t.Fatal(err)
	}
	_, out := usage(t, d, "one", MonthKey(time.Now()))
	if out < meterFlushBytes {
		t.Fatalf("global threshold not flushed: %d", out)
	}
	_, _ = h.close()
	cancel()
	if err := g.StopMeter(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMeterMonthRolloverAndManualQuotaResetPolicy(t *testing.T) {
	d := meterDB(t)
	if _, err := d.Exec(`UPDATE tunnels SET monthly_quota_bytes=10 WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	m := newUsageMeter(d)
	now := time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC)
	m.now = func() time.Time { return now }
	h := m.begin(&Tunnel{ID: "one", MonthlyQuotaByte: 10})
	r, err := h.reserve(context.Background(), 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err = h.settle(r, 8, true); err != nil {
		t.Fatal(err)
	}
	if _, err = h.write(context.Background(), make([]byte, 10), func(p []byte) (int, error) { return len(p), nil }, 0); err != nil {
		t.Fatal(err)
	}
	_, _ = h.close()
	in, _ := usage(t, d, "one", "2026-10")
	_, out := usage(t, d, "one", "2026-11")
	if in != 8 || out != 10 {
		t.Fatalf("month split %d/%d", in, out)
	}
	now = now.AddDate(0, 1, 0)
	_, _ = m.flush(context.Background())
	var status string
	_ = d.QueryRow(`SELECT status FROM tunnels WHERE id='one'`).Scan(&status)
	if status != "quota_exceeded" {
		t.Fatalf("quota stop was automatically reset: %q", status)
	}
	if len(m.entries) != 0 || len(m.months) > 1 {
		t.Fatal("old month cache leaked")
	}
}

func TestMeterEntryUsesCurrentQuotaAfterPatchBeforeFirstReservation(t *testing.T) {
	d := meterDB(t)
	g := NewGateway(GatewayConfig{DB: d})
	stale := &Tunnel{ID: "one", MonthlyQuotaByte: 100}
	if _, err := d.Exec(`UPDATE tunnels SET monthly_quota_bytes=10 WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	g.UpdateQuota("one", 10) // No entry existed when PATCH invalidated runtime state.
	h := g.meter.begin(stale)
	defer h.close()
	n, err := h.write(context.Background(), make([]byte, 20), func(p []byte) (int, error) { return len(p), nil }, 0)
	if n != 10 || !errors.Is(err, ErrQuota) {
		t.Fatalf("captured quota bypassed PATCH: %d %v", n, err)
	}
	_, out := usage(t, d, "one", MonthKey(time.Now()))
	if out != 10 {
		t.Fatalf("actual quota=%d", out)
	}
}

func TestQuotaCallbacksCannotReorderCommittedLimit(t *testing.T) {
	d := meterDB(t)
	g := NewGateway(GatewayConfig{DB: d})
	h := g.meter.begin(&Tunnel{ID: "one"})
	defer h.close()
	r, err := h.reserve(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.settle(r, 0, true)
	if _, err = d.Exec(`UPDATE tunnels SET monthly_quota_bytes=100 WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE tunnels SET monthly_quota_bytes=10 WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	g.UpdateQuota("one", 10)
	g.UpdateQuota("one", 100) // The first PATCH callback arrived after the second.
	n, err := h.write(context.Background(), make([]byte, 20), func(p []byte) (int, error) { return len(p), nil }, 0)
	if n != 10 || !errors.Is(err, ErrQuota) {
		t.Fatalf("late PATCH callback restored stale quota: %d %v", n, err)
	}
}

func TestMeterDBFailureFailClosedPreservesDirtyData(t *testing.T) {
	d := meterDB(t)
	g := NewGateway(GatewayConfig{DB: d})
	h := g.meter.begin(&Tunnel{ID: "one"})
	if _, err := h.write(context.Background(), []byte("dirty"), func(p []byte) (int, error) { return len(p), nil }, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TRIGGER fail_meter BEFORE INSERT ON tunnel_usage BEGIN SELECT RAISE(ABORT,'disk failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := g.meter.flush(context.Background()); !errors.Is(err, ErrMeterUnavailable) {
		t.Fatal(err)
	}
	if g.MeterReady() || g.meter.pending != 5 {
		t.Fatal("DB failure lost dirty bytes or stayed ready")
	}
	if _, err := h.write(context.Background(), []byte("blocked"), func([]byte) (int, error) { t.Fatal("IO after DB error"); return 0, nil }, 0); !errors.Is(err, ErrMeterUnavailable) {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DROP TRIGGER fail_meter`); err != nil {
		t.Fatal(err)
	}
	_, _ = h.close()
	_, out := usage(t, d, "one", MonthKey(time.Now()))
	if out != 5 || g.MeterReady() {
		t.Fatalf("retry bytes=%d readiness=%v", out, g.MeterReady())
	}
}
