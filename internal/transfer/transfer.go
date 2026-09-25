// Package transfer implements the resumable chunked protocol:
// manifest + fixed chunking + BLAKE3 per-chunk + bitmap + WriteAt + atomic rename,
// plus path-safety (allowed_roots, no traversal/symlink escape).
package transfer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeebo/blake3"
)

const (
	MinChunk = 8 << 20
	MaxChunk = 256 << 20
	DefChunk = 64 << 20
)

// Manifest describes one file inside a job.
type Manifest struct {
	FileID     string   `json:"file_id"`
	RelPath    string   `json:"rel_path"`
	Size       int64    `json:"size"`
	ChunkSize  int64    `json:"chunk_size"`
	ChunkCount int      `json:"chunk_count"`
	Chunks     []string `json:"chunks"` // hex BLAKE3 per chunk
	Final      string   `json:"final"`  // hex BLAKE3 of whole file
}

// ChunkCountFor computes ceil(size/chunkSize).
func ChunkCountFor(size, chunkSize int64) int {
	if size == 0 {
		return 0
	}
	return int((size + chunkSize - 1) / chunkSize)
}

// BuildManifest streams src file, computing per-chunk + final BLAKE3 without loading whole file.
func BuildManifest(fileID, relPath, srcPath string, chunkSize int64) (*Manifest, error) {
	if chunkSize < MinChunk || chunkSize > MaxChunk {
		return nil, fmt.Errorf("chunk size out of range")
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	m := &Manifest{FileID: fileID, RelPath: relPath, Size: st.Size(), ChunkSize: chunkSize}
	m.ChunkCount = ChunkCountFor(m.Size, chunkSize)
	final := blake3.New()
	buf := make([]byte, 1<<20) // 1MiB streaming buffer (bounded)
	var cur hash.Hash
	var curN int64
	flush := func() {
		sum := cur.Sum(nil)
		m.Chunks = append(m.Chunks, hex.EncodeToString(sum))
		cur = nil
		curN = 0
	}
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			final.Write(buf[:n])
			off := 0
			for off < n {
				if cur == nil {
					cur = blake3.New()
				}
				room := int(chunkSize - curN)
				take := n - off
				if take > room {
					take = room
				}
				cur.Write(buf[off : off+take])
				curN += int64(take)
				off += take
				if curN == chunkSize {
					flush()
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	if cur != nil {
		flush()
	}
	m.Final = hex.EncodeToString(final.Sum(nil))
	if len(m.Chunks) != m.ChunkCount {
		return nil, fmt.Errorf("chunk count mismatch: %d vs %d", len(m.Chunks), m.ChunkCount)
	}
	return m, nil
}

// ---- Bitmap ----

// Bitmap tracks completed chunks persistently (JSON file, not thousands of files).
type Bitmap struct {
	path string
	Done []bool `json:"done"`
}

func OpenBitmap(statePath string, n int) (*Bitmap, error) {
	b := &Bitmap{path: statePath, Done: make([]bool, n)}
	if raw, err := os.ReadFile(statePath); err == nil {
		var disk Bitmap
		if err := json.Unmarshal(raw, &disk); err == nil && len(disk.Done) == n {
			disk.path = statePath
			return &disk, nil
		}
	}
	return b, nil
}

func (b *Bitmap) MarkDone(i int) error {
	b.Done[i] = true
	return b.save()
}

func (b *Bitmap) IsDone(i int) bool { return b.Done[i] }

func (b *Bitmap) Remaining() []int {
	var out []int
	for i, d := range b.Done {
		if !d {
			out = append(out, i)
		}
	}
	return out
}

func (b *Bitmap) Complete() bool {
	for _, d := range b.Done {
		if !d {
			return false
		}
	}
	return true
}

func (b *Bitmap) save() error {
	raw, _ := json.Marshal(b)
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

// ---- Receiver file helpers ----

// PreparePartial creates/pre-sizes <dst>.meshbridge.part (checks free space best-effort).
func PreparePartial(dstPath string, size int64) (*os.File, string, error) {
	part := dstPath + ".meshbridge.part"
	if err := os.MkdirAll(filepath.Dir(part), 0o755); err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, "", err
	}
	if st, err := f.Stat(); err == nil && st.Size() != size {
		if err := f.Truncate(size); err != nil {
			f.Close()
			return nil, "", err
		}
	}
	return f, part, nil
}

// WriteChunk verifies hash then WriteAt(offset). Caller fsyncs periodically (not per chunk).
func WriteChunk(f *os.File, data []byte, offset int64, wantHex string) error {
	h := blake3.New()
	h.Write(data)
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		return fmt.Errorf("chunk hash mismatch")
	}
	if _, err := f.WriteAt(data, offset); err != nil {
		return err
	}
	return nil
}

// Finalize verifies final hash of part file, fsyncs, atomically renames to dst.
func Finalize(partPath, dstPath, wantFinal string, overwrite bool) error {
	if _, err := os.Stat(dstPath); err == nil && !overwrite {
		return fmt.Errorf("destination exists (refusing silent overwrite): %s", dstPath)
	}
	f, err := os.OpenFile(partPath, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	h := blake3.New()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantFinal {
		return fmt.Errorf("final hash mismatch")
	}
	// Durability before visibility: fsync data, rename, fsync directory.
	if err := f.Sync(); err != nil {
		return err
	}
	if err := os.Rename(partPath, dstPath); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(dstPath)); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

// ---- Path safety ----

// SafeJoin resolves rel against one of allowedRoots, rejecting traversal + symlink escape.
func SafeJoin(allowedRoots []string, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	// Strict: reject any ".." segment or absolute path before Clean collapses it.
	// This is intentionally stricter than lexical containment (a/../b is also refused)
	// to avoid ambiguity and to match "no ../ traversal" policy.
	slash := filepath.ToSlash(rel)
	for _, seg := range strings.Split(slash, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal refused: %q", rel)
		}
	}
	clean := filepath.Clean("/" + rel)[1:] // strip leading /
	if clean == "." || strings.HasPrefix(clean, "..") || strings.Contains(clean, "../") {
		return "", fmt.Errorf("path traversal refused: %q", rel)
	}
	for _, root := range allowedRoots {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if st, err := os.Stat(absRoot); err != nil || !st.IsDir() {
			continue // nonexistent roots never match
		}
		// resolve root symlinks once
		realRoot, err := filepath.EvalSymlinks(absRoot)
		if err != nil {
			realRoot = absRoot
		}
		cand := filepath.Join(realRoot, clean)
		// Walk up from cand to root; the first existing ancestor must resolve
		// (EvalSymlinks) back inside realRoot, which catches symlink escapes.
		p := cand
		for {
			if _, err := os.Lstat(p); err == nil {
				rp, err := filepath.EvalSymlinks(p)
				if err == nil {
					rel2, err := filepath.Rel(realRoot, rp)
					if err != nil || rel2 == ".." || strings.HasPrefix(rel2, "../") {
						return "", fmt.Errorf("symlink escape refused")
					}
					break
				}
			}
			np := filepath.Dir(p)
			if np == p || len(np) < len(realRoot) {
				break
			}
			p = np
		}
		// final containment: cand must be within realRoot lexically (after clean, no ..)
		if rel3, err := filepath.Rel(realRoot, cand); err == nil && rel3 != ".." && !strings.HasPrefix(rel3, "../") {
			return cand, nil
		}
	}
	return "", fmt.Errorf("path outside allowed_roots: %q", rel)
}

func RandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
