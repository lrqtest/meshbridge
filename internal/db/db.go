// Package db wraps SQLite with WAL, busy_timeout, migrations and helpers.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// Open opens (creating parent dirs) and applies pragmas + schema file.
func Open(path, schemaFile string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("sqlite", path+"?cache=shared")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	ctx := context.Background()
	for _, p := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA synchronous=NORMAL;",
	} {
		if _, err := sqlDB.ExecContext(ctx, p); err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	if schemaFile != "" {
		raw, err := os.ReadFile(schemaFile)
		if err != nil {
			sqlDB.Close()
			return nil, err
		}
		if _, err := sqlDB.ExecContext(ctx, string(raw)); err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	return sqlDB, nil
}

// RunMigrations executes every .sql file in dir in lexical order, statement by
// statement. ALTER TABLE statements that fail with "duplicate column" are
// skipped, which makes re-runs against an already-migrated database safe.
func RunMigrations(sqlDB *sql.DB, dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".sql" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		for _, stmt := range SplitStatements(string(raw)) {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := sqlDB.Exec(stmt); err != nil {
				// Idempotence: adding a column that already exists is fine.
				if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "ALTER TABLE") &&
					strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
					continue
				}
				return fmt.Errorf("%s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// SplitStatements splits a SQL script on semicolons, honouring single-quoted
// strings and stripping `--` line comments (migrations are comment-rich and
// comment text may contain semicolons).
func SplitStatements(script string) []string {
	var out []string
	cur := strings.Builder{}
	inStr := false
	runes := []rune(script)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case inStr:
			cur.WriteRune(r)
			if r == '\'' {
				inStr = false
			}
		case r == '\'':
			inStr = true
			cur.WriteRune(r)
		case r == '-' && i+1 < len(runes) && runes[i+1] == '-':
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
			if i < len(runes) {
				cur.WriteRune('\n')
			}
		case r == ';' && !inStr:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// OpenMemory is for tests.
func OpenMemory(schemaFile string) (*sql.DB, error) {
	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	if _, err := sqlDB.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return nil, err
	}
	if schemaFile != "" {
		raw, err := os.ReadFile(schemaFile)
		if err != nil {
			return nil, err
		}
		if _, err := sqlDB.Exec(string(raw)); err != nil {
			return nil, err
		}
	}
	return sqlDB, nil
}
