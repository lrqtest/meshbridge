package db

import (
	"context"
	"database/sql/driver"
	"path/filepath"
	"testing"
)

// Revocation of platform-derived sessions rests on ON DELETE CASCADE, and
// SQLite enforces foreign keys per connection. A pooled connection that is
// dropped and replaced must come back with the same pragmas, not silently
// without enforcement.
func TestPragmasSurviveAReplacedConnection(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "mesh.sqlite"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pragma := func(name string) int {
		t.Helper()
		var v int
		if err := d.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	want := map[string]int{"foreign_keys": 1, "busy_timeout": 5000}
	for round := 0; round < 3; round++ {
		for name, v := range want {
			if got := pragma(name); got != v {
				t.Fatalf("round %d: PRAGMA %s = %d, want %d", round, name, got, v)
			}
		}
		// Make database/sql discard the only connection; the next use opens a new one.
		conn, err := d.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	}
	if _, err := d.Exec(`CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE c(id INTEGER PRIMARY KEY, p INTEGER REFERENCES p(id) ON DELETE CASCADE);
		INSERT INTO p VALUES(1); INSERT INTO c VALUES(1,1); DELETE FROM p;`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM c`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("cascade did not run on the replacement connection: n=%d err=%v", n, err)
	}
}
