// Package db wraps SQLite with WAL, busy_timeout, migrations and helpers.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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
