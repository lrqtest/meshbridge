// Package storage builds rclone invocations for S3 fallback (multipart, retry)
// and checks rclone version. Controller never proxies object data.
package storage

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const MinRclone = "1.75.0"

// Profile is a server-side S3 config (secret stays encrypted at rest; agents get env/presigned only).
type Profile struct {
	Name       string
	Endpoint   string
	Region     string
	Bucket     string
	PathPrefix string
}

// RemoteAddr returns bucket path for rclone.
func (p Profile) RemoteAddr() string {
	pre := strings.Trim(p.PathPrefix, "/")
	if pre == "" {
		return fmt.Sprintf(":s3:%s/", p.Bucket)
	}
	return fmt.Sprintf(":s3:%s/%s/", p.Bucket, pre)
}

// CopyToArgs builds: rclone copyto <local> <remote> --s3-endpoint ... --transfers 8 --s3-chunk-size 64M ...
func (p Profile) CopyToArgs(local, remoteName string, transfers int) []string {
	if transfers <= 0 || transfers > 16 {
		transfers = 8
	}
	return []string{
		"copyto", local, p.RemoteAddr() + remoteName,
		"--s3-provider", "Other",
		"--s3-endpoint", p.Endpoint,
		"--s3-region", p.Region,
		"--transfers", strconv.Itoa(transfers),
		"--s3-chunk-size", "64M",
		"--s3-upload-concurrency", "4",
		"--retries", "5",
		"--stats", "5s",
	}
}

// CheckRclone runs `rclone version` and requires >= MinRclone.
func CheckRclone(path string) (string, error) {
	if path == "" {
		path = "rclone"
	}
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return "", fmt.Errorf("rclone not found: %w", err)
	}
	ver := parseVersion(string(out))
	if ver == "" {
		return "", fmt.Errorf("cannot parse rclone version")
	}
	if compareVer(ver, MinRclone) < 0 {
		return ver, fmt.Errorf("rclone %s < minimum %s", ver, MinRclone)
	}
	return ver, nil
}

func parseVersion(out string) string {
	// "rclone v1.75.0-DEV ..." or "rclone v1.75.0 ..."
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "v") && strings.Count(f, ".") >= 2 {
			return strings.TrimPrefix(strings.Split(f, "-")[0], "v")
		}
	}
	return ""
}

func compareVer(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
