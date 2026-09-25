// Package audit appends structured events; logs never contain secrets (enforced by callers).
package audit

import (
	"context"
	"database/sql"
	"time"
)

func Log(ctx context.Context, db *sql.DB, actor, event, projectID, deviceID, jobID, detail string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_logs(ts,actor,event,project_id,device_id,job_id,detail) VALUES(?,?,?,?,?,?,?)`,
		time.Now().Unix(), actor, event, projectID, deviceID, jobID, detail)
	return err
}
