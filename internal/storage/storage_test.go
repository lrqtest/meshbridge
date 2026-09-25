package storage

import "testing"

func TestCopyArgs(t *testing.T) {
	p := Profile{Name: "s", Endpoint: "https://s3.example.com", Region: "us-west-1", Bucket: "b", PathPrefix: "mesh"}
	args := p.CopyToArgs("/tmp/a.bin", "job1/a.bin", 0)
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	for _, want := range []string{"copyto", "--transfers", "--s3-chunk-size", "--retries"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s in %v", want, args)
		}
	}
	_ = joined
}

func TestCompareVer(t *testing.T) {
	if compareVer("1.75.0", "1.75.0") != 0 {
		t.Fatal("eq")
	}
	if compareVer("1.74.0", "1.75.0") >= 0 {
		t.Fatal("lt")
	}
	if parseVersion("rclone v1.75.0-DEV") != "1.75.0" {
		t.Fatal("parse")
	}
}
