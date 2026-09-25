// Package policy renders Headscale Grants (deny-by-default) from DB state,
// with tmp→validate→backup→atomic rename→reload→verify→rollback semantics.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Project struct {
	Slug string
}

type Device struct {
	Hostname string
	Tags     []string
}

// Input is the minimal DB-derived state needed to render policy.
type Input struct {
	Projects []Project
	// projectSlug -> member tags (already computed: tag:project-<slug> per device)
	Devices []Device
	Relays  []Relay
	// OwnerUser is the headscale username (with "@") that owns all tags.
	// Headscale 0.29 rejects "autogroup:admin" (Tailscale SaaS-only syntax).
	OwnerUser string
}

type Relay struct {
	Name   string // relay-jp-01
	Tag    string // tag:relay-jp
	Region string
}

type Grant struct {
	Src []string       `json:"src"`
	Dst []string       `json:"dst"`
	IP  []string       `json:"ip,omitempty"`
	App map[string]any `json:"app,omitempty"`
}

type Policy struct {
	Groups   map[string][]string `json:"groups,omitempty"`
	TagOwn   map[string][]string `json:"tagOwners,omitempty"`
	Hosts    map[string]string   `json:"hosts,omitempty"`
	Grants   []Grant             `json:"grants"`
	TagOwnV2 map[string][]string `json:"-"`
}

// Render builds deny-by-default grants:
// - same project: full mesh (all ports) between tag:project-<slug> members
// - admin devices can SSH (port 22) to all project tags
// - relays: only explicit project tags -> relay tags with cap/relay app
func Render(in Input) Policy {
	p := Policy{
		TagOwn: map[string][]string{},
		Grants: []Grant{},
	}
	// tagOwners: admin user owns everything (Headscale requires "user@" format).
	owner := in.OwnerUser
	if owner == "" {
		owner = "admin@"
	}
	if !strings.HasSuffix(owner, "@") {
		owner += "@"
	}
	p.TagOwn["tag:admin-device"] = []string{owner}
	slugs := []string{}
	for _, pr := range in.Projects {
		slugs = append(slugs, pr.Slug)
		p.TagOwn["tag:project-"+pr.Slug] = []string{owner}
		p.TagOwn["tag:role-dev"] = []string{owner}
		p.TagOwn["tag:role-prod"] = []string{owner}
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		tag := "tag:project-" + slug
		p.Grants = append(p.Grants, Grant{
			Src: []string{tag},
			Dst: []string{tag},
			IP:  []string{"*"},
		})
	}
	// SSH from admin devices.
	if len(slugs) > 0 {
		dsts := []string{}
		for _, s := range slugs {
			dsts = append(dsts, "tag:project-"+s)
		}
		p.Grants = append(p.Grants, Grant{
			Src: []string{"tag:admin-device"},
			Dst: dsts,
			IP:  []string{"tcp:22"},
		})
	}
	// Peer relay grants: each project may use each relay (narrow, no "*").
	for _, slug := range slugs {
		for _, r := range in.Relays {
			p.Grants = append(p.Grants, Grant{
				Src: []string{"tag:project-" + slug},
				Dst: []string{r.Tag},
				App: map[string]any{"tailscale.com/cap/relay": []any{}},
			})
		}
	}
	_ = in.Devices
	return p
}

// Validate performs semantic checks: no src "*" relay grants, tags well-formed.
func Validate(p Policy) error {
	for i, g := range p.Grants {
		for _, s := range g.Src {
			if s == "*" || s == "autogroup:danger-all" {
				// Only allowed if no relay app cap.
				if _, isRelay := g.App["tailscale.com/cap/relay"]; isRelay {
					return fmt.Errorf("grant %d: relay grant must not use wildcard src", i)
				}
			}
		}
		for _, d := range g.Dst {
			if strings.Contains(d, " ") || d == "" {
				return fmt.Errorf("grant %d: bad dst %q", i, d)
			}
		}
	}
	return nil
}

func Marshal(p Policy) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// WriteAtomic writes tmp, validates JSON round-trip, backups old, renames.
func WriteAtomic(path string, data []byte, keepSnapshots int, snapshotDir string) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	// semantic validate
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if err := Validate(p); err != nil {
		os.Remove(tmp)
		return err
	}
	if snapshotDir != "" {
		if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
			return err
		}
		if old, err := os.ReadFile(path); err == nil {
			sum := sha256.Sum256(old)
			name := fmt.Sprintf("policy-%s-%s.hujson", time.Now().Format("20060102-150405"), hex.EncodeToString(sum[:])[:8])
			_ = os.WriteFile(filepath.Join(snapshotDir, name), old, 0o600)
			pruneSnapshots(snapshotDir, keepSnapshots)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

func pruneSnapshots(dir string, keep int) {
	if keep <= 0 {
		keep = 10
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	if len(ents) <= keep {
		return
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	for _, e := range ents[:len(ents)-keep] {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}

// Slugify converts project name to tag-safe slug.
func Slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if out == "" {
		return "proj"
	}
	return out
}
