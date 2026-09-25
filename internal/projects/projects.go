// Package projects holds project helpers (slug + membership roles).
package projects

import "github.com/meshbridge/meshbridge/internal/policy"

func Slug(name string) string { return policy.Slugify(name) }

var ValidRoles = map[string]bool{"owner": true, "admin": true, "member": true, "viewer": true}
