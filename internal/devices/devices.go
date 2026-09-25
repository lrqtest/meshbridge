// Package devices holds device/tag helpers.
package devices

import "fmt"

// TagsFor builds canonical tags for a device.
func TagsFor(projectSlugs []string, role string, isRelay, isAdmin bool) []string {
	tags := []string{}
	for _, s := range projectSlugs {
		tags = append(tags, "tag:project-"+s)
	}
	if role == "dev" || role == "prod" {
		tags = append(tags, "tag:role-"+role)
	}
	if isRelay {
		tags = append(tags, "tag:relay")
	}
	if isAdmin {
		tags = append(tags, "tag:admin-device")
	}
	return tags
}

func ValidateHostname(h string) error {
	if h == "" || len(h) > 63 {
		return fmt.Errorf("bad hostname")
	}
	return nil
}
