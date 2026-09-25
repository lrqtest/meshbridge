// Package metrics exposes lightweight aggregates (no Prometheus dependency).
package metrics

import (
	"database/sql"
)

type Summary struct {
	AgentsOnline int `json:"agents_online"`
	JobsActive   int `json:"jobs_active"`
	BytesMonth   int64 `json:"-"`
}

func SummaryFromDB(db *sql.DB) Summary {
	var s Summary
	_, _ = db, s
	row := db.QueryRow(`SELECT COUNT(*) FROM agents WHERE online=1`)
	_ = row.Scan(&s.AgentsOnline)
	row = db.QueryRow(`SELECT COUNT(*) FROM transfer_jobs WHERE state IN ('QUEUED','PROBING','TRANSFERRING','VERIFYING')`)
	_ = row.Scan(&s.JobsActive)
	return s
}
