package tunnel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var ErrQuota = errors.New("tunnel: traffic budget exhausted")
var ErrGlobalQuota = errors.New("tunnel: shared traffic budget exhausted")
var ErrMeterUnavailable = errors.New("tunnel: traffic meter unavailable")

const meterChunk = 16 << 10
const meterFlushBytes = 256 << 10

type meterKey struct{ id, month string }
type meterEntry struct {
	total, reserved, in, out, quota  int64
	warned, warnPending, stopPending bool
}
type monthBalance struct{ total, reserved, limit int64 }

// usageMeter owns all process-local reservations and unapplied deltas. The
// shared reservation prevents concurrent requests from spending the same byte.
// SQLite writes coalesce globally; dirty entries survive every failed flush.
type usageMeter struct {
	mu       sync.Mutex
	db       *sql.DB
	entries  map[meterKey]*meterEntry
	months   map[string]*monthBalance
	active   map[string]int
	pending  int64
	failure  error
	now      func() time.Time
	onResult func([]string, error)
}

func newUsageMeter(db *sql.DB) *usageMeter {
	return &usageMeter{db: db, entries: make(map[meterKey]*meterEntry), months: make(map[string]*monthBalance), active: make(map[string]int), now: time.Now}
}

func (m *usageMeter) ready() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.failure == nil }

func (m *usageMeter) entry(ctx context.Context, t *Tunnel, month string) (*meterEntry, *monthBalance, error) {
	if m.failure != nil {
		return nil, nil, ErrMeterUnavailable
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b := m.months[month]
	if b == nil {
		b = &monthBalance{}
		if m.db != nil {
			if err := m.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes_in+bytes_out),0) FROM tunnel_usage WHERE month=?`, month).Scan(&b.total); err != nil {
				if parent.Err() != nil {
					return nil, nil, parent.Err()
				}
				m.failure = err
				return nil, nil, ErrMeterUnavailable
			}
		}
		m.months[month] = b
	}
	k := meterKey{t.ID, month}
	e := m.entries[k]
	if e == nil {
		e = &meterEntry{quota: t.MonthlyQuotaByte}
		if m.db != nil {
			var warned int
			err := m.db.QueryRowContext(ctx, `SELECT COALESCE(u.bytes_in+u.bytes_out,0),COALESCE(u.warned,0),t.monthly_quota_bytes
 FROM tunnels t LEFT JOIN tunnel_usage u ON u.tunnel_id=t.id AND u.month=? WHERE t.id=? AND t.status='active'`, month, t.ID).Scan(&e.total, &warned, &e.quota)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil, ErrAgentOffline
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				if parent.Err() != nil {
					return nil, nil, parent.Err()
				}
				m.failure = err
				return nil, nil, ErrMeterUnavailable
			}
			e.warned = warned != 0
		}
		m.entries[k] = e
	}
	return e, b, nil
}

type requestMeter struct {
	m      *usageMeter
	t      *Tunnel
	once   sync.Once
	mu     sync.Mutex
	closed bool
	io     sync.WaitGroup
}
type byteReservation struct {
	key meterKey
	n   int64
}

func (m *usageMeter) begin(t *Tunnel) *requestMeter {
	m.mu.Lock()
	m.active[t.ID]++
	m.mu.Unlock()
	return &requestMeter{m: m, t: t}
}

func (h *requestMeter) reserve(ctx context.Context, n int, globalLimit int64) (byteReservation, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return byteReservation{}, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return byteReservation{}, err
	}
	m := h.m
	m.mu.Lock()
	defer m.mu.Unlock()
	month := MonthKey(m.now())
	e, b, err := m.entry(ctx, h.t, month)
	if err != nil {
		return byteReservation{}, err
	}
	b.limit = globalLimit
	want := int64(n)
	if want > meterChunk {
		want = meterChunk
	}
	if e.quota > 0 && want > e.quota-e.total-e.reserved {
		want = e.quota - e.total - e.reserved
	}
	if globalLimit > 0 && want > globalLimit-b.total-b.reserved {
		want = globalLimit - b.total - b.reserved
	}
	if want <= 0 {
		if e.quota > 0 && e.total >= e.quota {
			return byteReservation{}, ErrQuota
		}
		if globalLimit > 0 && b.total >= globalLimit {
			return byteReservation{}, ErrGlobalQuota
		}
		// Pending I/O owns reservations, not spent traffic. Temporary
		// contention cannot persist a quota stop or kill an agent session.
		return byteReservation{}, ErrTunnelBusy
	}
	e.reserved += want
	b.reserved += want
	h.io.Add(1)
	return byteReservation{key: meterKey{h.t.ID, month}, n: want}, nil
}

func (h *requestMeter) settle(r byteReservation, n int, in bool) ([]string, error) {
	m := h.m
	m.mu.Lock()
	defer func() { m.mu.Unlock(); h.io.Done() }()
	e := m.entries[r.key]
	b := m.months[r.key.month]
	e.reserved -= r.n
	b.reserved -= r.n
	e.total += int64(n)
	b.total += int64(n)
	m.pending += int64(n)
	if in {
		e.in += int64(n)
	} else {
		e.out += int64(n)
	}
	if e.quota > 0 && e.total >= e.quota {
		e.stopPending = true
	}
	if e.quota > 0 && !e.warned && e.total >= e.quota*8/10 {
		e.warnPending = true
		e.warned = true
	}
	if m.pending >= meterFlushBytes || e.stopPending || (b.limit > 0 && b.total >= b.limit) {
		stopped, err := m.flushLocked(context.Background())
		if err == nil && b.limit > 0 && b.total >= b.limit {
			err = ErrGlobalQuota
		}
		return stopped, err
	}
	return nil, nil
}

// Read/write reserve only the next bounded chunk. A pending read may hold a
// reservation, but never records bytes until I/O returns. Partial writes return
// their actual byte count and error; larger writes loop rather than short-write.
func (h *requestMeter) read(ctx context.Context, p []byte, read func([]byte) (int, error), global int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r, err := h.reserve(ctx, len(p), global)
	if err != nil {
		if h.m.onResult != nil {
			h.m.onResult(nil, err)
		}
		return 0, err
	}
	n, ioErr := read(p[:r.n])
	stopped, err := h.settle(r, n, true)
	if h.m.onResult != nil {
		h.m.onResult(stopped, err)
	}
	if err != nil {
		return n, err
	}
	return n, ioErr
}

func (h *requestMeter) write(ctx context.Context, p []byte, write func([]byte) (int, error), global int64) (int, error) {
	total := 0
	for len(p) > 0 {
		r, err := h.reserve(ctx, len(p), global)
		if err != nil {
			if h.m.onResult != nil {
				h.m.onResult(nil, err)
			}
			return total, err
		}
		n, ioErr := write(p[:r.n])
		stopped, err := h.settle(r, n, false)
		if h.m.onResult != nil {
			h.m.onResult(stopped, err)
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if ioErr != nil {
			return total, ioErr
		}
		if int64(n) != r.n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (h *requestMeter) close() ([]string, error) {
	var stopped []string
	var err error
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
		h.io.Wait()
		m := h.m
		m.mu.Lock()
		defer m.mu.Unlock()
		m.active[h.t.ID]--
		if m.active[h.t.ID] == 0 {
			delete(m.active, h.t.ID)
		}
		stopped, err = m.flushLocked(context.Background())
	})
	return stopped, err
}

func (m *usageMeter) flush(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushLocked(ctx)
}

func (m *usageMeter) flushLocked(ctx context.Context) ([]string, error) {
	if m.pending == 0 {
		m.prune()
		if m.failure != nil {
			return nil, ErrMeterUnavailable
		}
		return nil, nil
	}
	if m.db == nil {
		for _, e := range m.entries {
			e.in = 0
			e.out = 0
			e.warnPending = false
			e.stopPending = false
		}
		m.pending = 0
		m.prune()
		return nil, nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		m.failure = err
		return nil, ErrMeterUnavailable
	}
	defer tx.Rollback()
	var stopped []string
	for k, e := range m.entries {
		if e.in == 0 && e.out == 0 {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO tunnel_usage(tunnel_id,month,bytes_in,bytes_out,warned) VALUES(?,?,?,?,?)
 ON CONFLICT(tunnel_id,month) DO UPDATE SET bytes_in=bytes_in+excluded.bytes_in,bytes_out=bytes_out+excluded.bytes_out,warned=MAX(warned,excluded.warned)`, k.id, k.month, e.in, e.out, e.warned)
		if err != nil {
			break
		}
		if e.warnPending {
			_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(ts,actor,event,project_id,device_id,job_id,detail) VALUES(?,'gateway','tunnel quota warning','',?,'',?)`, m.now().Unix(), k.id, "80% of monthly budget")
			if err != nil {
				break
			}
		}
		if e.stopPending {
			var res sql.Result
			res, err = tx.ExecContext(ctx, `UPDATE tunnels SET status='quota_exceeded',updated_at=? WHERE id=? AND status='active'`, m.now().Unix(), k.id)
			if err != nil {
				break
			}
			n, _ := res.RowsAffected()
			stopped = append(stopped, k.id)
			if n > 0 {
				_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(ts,actor,event,project_id,device_id,job_id,detail) VALUES(?,'gateway','tunnel quota exceeded','',?,'',?)`, m.now().Unix(), k.id, fmt.Sprintf("%d bytes", e.total))
				if err != nil {
					break
				}
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		m.failure = err
		return nil, ErrMeterUnavailable
	}
	for _, e := range m.entries {
		e.in = 0
		e.out = 0
		e.warnPending = false
		e.stopPending = false
	}
	m.pending = 0
	// A failed write latches admission until restart even if a final retry
	// succeeds; readiness stays degraded, and no unapplied delta is discarded.
	m.prune()
	if m.failure != nil {
		return stopped, ErrMeterUnavailable
	}
	return stopped, nil
}

func (m *usageMeter) prune() {
	current := MonthKey(m.now())
	for k, e := range m.entries {
		if e.in == 0 && e.out == 0 && e.reserved == 0 && (m.active[k.id] == 0 || k.month != current) {
			delete(m.entries, k)
		}
	}
	for month, b := range m.months {
		if month == current || b.reserved != 0 {
			continue
		}
		used := false
		for k := range m.entries {
			if k.month == month {
				used = true
				break
			}
		}
		if !used {
			delete(m.months, month)
		}
	}
}
