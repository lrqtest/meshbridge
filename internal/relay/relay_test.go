package relay

import "testing"

func TestEvaluate(t *testing.T) {
	if Evaluate(true, 10, 100) != StatusOK {
		t.Fatal("ok")
	}
	if Evaluate(true, 85, 100) != StatusWarn {
		t.Fatal("warn")
	}
	if Evaluate(true, 97, 100) != StatusCritical {
		t.Fatal("critical")
	}
	if Evaluate(false, 0, 100) != StatusDown {
		t.Fatal("down")
	}
	if AllowNewBigJob(true, 97, 100) {
		t.Fatal("critical must block new big jobs")
	}
}
