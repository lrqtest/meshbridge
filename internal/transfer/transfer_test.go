package transfer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChunkResume(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	// deterministic pseudo-random (NOT zeros — zeros would mislead bandwidth tests).
	data := make([]byte, 20<<20) // 20MiB
	x := uint64(0x12345678)
	for i := range data {
		x = x*6364136223846793005 + 1
		data[i] = byte(x >> 33)
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := BuildManifest("f1", "a.bin", src, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if m.ChunkCount != 3 { // 20/8 => 3
		t.Fatalf("chunk count %d", m.ChunkCount)
	}
	dst := filepath.Join(dir, "sub", "a.bin")
	f, part, err := PreparePartial(dst, m.Size)
	if err != nil {
		t.Fatal(err)
	}
	// write chunks 0 and 2, skip 1 (simulate kill at ~47%).
	for _, idx := range []int{0, 2} {
		off := int64(idx) * m.ChunkSize
		n := m.ChunkSize
		if off+n > m.Size {
			n = m.Size - off
		}
		if _, err := f.WriteAt(data[off:off+n], off); err != nil {
			t.Fatal(err)
		}
		// verify hash path via WriteChunk on a copy buffer
		if err := WriteChunk(f, data[off:off+n], off, m.Chunks[idx]); err != nil {
			t.Fatal(err)
		}
	}
	f.Sync()
	f.Close()
	bm, _ := OpenBitmap(filepath.Join(dir, "state.json"), m.ChunkCount)
	_ = bm.MarkDone(0)
	_ = bm.MarkDone(2)
	if bm.Complete() {
		t.Fatalf("should be incomplete")
	}
	rem := bm.Remaining()
	if len(rem) != 1 || rem[0] != 1 {
		t.Fatalf("remaining %v", rem)
	}
	// resume: reopen + write missing chunk
	f2, _, err := PreparePartial(dst, m.Size)
	if err != nil {
		t.Fatal(err)
	}
	off := int64(1) * m.ChunkSize
	n := m.ChunkSize
	if off+n > m.Size {
		n = m.Size - off
	}
	if err := WriteChunk(f2, data[off:off+n], off, m.Chunks[1]); err != nil {
		t.Fatal(err)
	}
	f2.Sync()
	f2.Close()
	if err := Finalize(part, dst, m.Final, false); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if len(got) != len(data) {
		t.Fatalf("size mismatch")
	}
	for i := range got {
		if got[i] != data[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}
	// wrong hash must fail
	f3, part3, _ := PreparePartial(filepath.Join(dir, "b.bin"), m.Size)
	defer f3.Close()
	if err := WriteChunk(f3, []byte("corrupt!"), 0, m.Chunks[0]); err == nil {
		t.Fatalf("corrupt chunk must fail")
	}
	_ = part3
}

func TestSafeJoin(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "allowed")
	os.MkdirAll(root, 0o755)
	ok, err := SafeJoin([]string{root}, "projects/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	if ok == "" {
		t.Fatalf("empty")
	}
	if _, err := SafeJoin([]string{root}, "../etc/passwd"); err == nil {
		t.Fatalf("traversal must fail")
	}
	if _, err := SafeJoin([]string{root}, "../../etc/passwd"); err == nil {
		t.Fatalf("traversal must fail")
	}
	if _, err := SafeJoin([]string{root}, ".."); err == nil {
		t.Fatalf("bare .. must fail")
	}
	if _, err := SafeJoin([]string{"/nonexistent-root-xyz"}, "a.bin"); err == nil {
		t.Fatalf("outside roots must fail")
	}
	// symlink escape: link inside root pointing outside
	outside := filepath.Join(dir, "outside.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	_ = os.Symlink(outside, filepath.Join(root, "evil"))
	if _, err := SafeJoin([]string{root}, "evil"); err == nil {
		t.Fatalf("symlink escape must fail")
	}
}
