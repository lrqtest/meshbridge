package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderIsolation(t *testing.T) {
	p := Render(Input{
		Projects: []Project{{Slug: "alpha"}, {Slug: "beta"}},
		Relays:   []Relay{{Name: "relay-jp-01", Tag: "tag:relay-jp"}},
	})
	if err := Validate(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := Marshal(p)
	s := string(raw)
	// alpha members must reach alpha, but no grant alpha->beta should exist.
	foundAlphaBeta := false
	for _, g := range p.Grants {
		has := func(xs []string, v string) bool {
			for _, x := range xs {
				if x == v {
					return true
				}
			}
			return false
		}
		if has(g.Src, "tag:project-alpha") && has(g.Dst, "tag:project-beta") {
			foundAlphaBeta = true
		}
	}
	if foundAlphaBeta {
		t.Fatalf("cross-project grant must not exist by default:\n%s", s)
	}
	// relay grant must be narrow.
	for _, g := range p.Grants {
		if _, ok := g.App["tailscale.com/cap/relay"]; ok {
			for _, src := range g.Src {
				if src == "*" {
					t.Fatalf("relay grant wildcard src forbidden")
				}
			}
		}
	}
}

func TestWriteAtomicKeepsSnapshots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.hujson")
	snap := filepath.Join(dir, "snaps")
	p1, _ := Marshal(Render(Input{Projects: []Project{{Slug: "a"}}}))
	if err := WriteAtomic(path, p1, 2, snap); err != nil {
		t.Fatal(err)
	}
	p2, _ := Marshal(Render(Input{Projects: []Project{{Slug: "a"}, {Slug: "b"}}}))
	if err := WriteAtomic(path, p2, 2, snap); err != nil {
		t.Fatal(err)
	}
	p3, _ := Marshal(Render(Input{Projects: []Project{{Slug: "c"}}}))
	if err := WriteAtomic(path, p3, 2, snap); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(snap)
	if len(ents) != 2 {
		t.Fatalf("want 2 snapshots, got %d", len(ents))
	}
	bad := []byte(`{invalid`)
	if err := WriteAtomic(path, bad, 2, snap); err == nil {
		t.Fatalf("invalid json must fail")
	}
}

func TestSlugify(t *testing.T) {
	if Slugify("Project Alpha") != "project-alpha" {
		t.Fatalf("slugify failed: %q", Slugify("Project Alpha"))
	}
	if Slugify("  ") != "proj" {
		t.Fatalf("empty fallback failed")
	}
}
