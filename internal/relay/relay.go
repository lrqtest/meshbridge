// Package relay tracks relay health/quota (metadata only; no data plane here).
package relay

const (
	WarnRatio     = 0.80
	CriticalRatio = 0.95
)

type Status string

const (
	StatusOK       Status = "OK"
	StatusWarn     Status = "WARN_QUOTA"
	StatusCritical Status = "CRITICAL_QUOTA"
	StatusDown     Status = "DOWN"
)

func Evaluate(healthy bool, bytesMonth, quota int64) Status {
	if !healthy {
		return StatusDown
	}
	if quota <= 0 {
		return StatusOK
	}
	r := float64(bytesMonth) / float64(quota)
	switch {
	case r >= CriticalRatio:
		return StatusCritical
	case r >= WarnRatio:
		return StatusWarn
	default:
		return StatusOK
	}
}

// AllowNewBigJob reports whether a new large transfer may use this relay.
func AllowNewBigJob(healthy bool, bytesMonth, quota int64) bool {
	return Evaluate(healthy, bytesMonth, quota) == StatusOK || Evaluate(healthy, bytesMonth, quota) == StatusWarn
}
