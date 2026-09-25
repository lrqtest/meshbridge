// Package settings reads/writes the key-value settings table.
package settings

import (
	"database/sql"
)

func Get(db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func GetDefault(db *sql.DB, key, def string) string {
	v, err := Get(db, key)
	if err != nil || v == "" {
		return def
	}
	return v
}

func Set(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
