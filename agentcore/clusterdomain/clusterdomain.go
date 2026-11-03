// Package clusterdomain normalises and validates the configured Kubernetes
// cluster domain.
package clusterdomain

import (
	"fmt"
	"strings"
)

// Normalize normalises (trim space, lowercase, trim dots) and
// validates a configured cluster domain once, at config load. It rejects
// anything that is not a syntactically valid DNS name.
func Normalize(raw string) (string, error) {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(raw)), ".")
	if d == "" || len(d) > 253 {
		return "", fmt.Errorf("invalid cluster domain %q", raw)
	}

	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid cluster domain %q", raw)
		}

		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid cluster domain %q", raw)
			}
		}
	}

	return d, nil
}
