package buildmeta

import (
	"fmt"
	"regexp"
)

var (
	releaseVersionPattern = regexp.MustCompile(`^v0\.[1-9][0-9]*\.(0|[1-9][0-9]*)$`)
	commitPattern         = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Format validates and renders build metadata for operator-visible output.
func Format(version, commit string) (string, error) {
	if version == "dev" && commit == "" {
		return "dev", nil
	}
	if err := ValidateRelease(version, commit); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s (%s)", version, commit), nil
}

// ValidateRelease accepts only the repository's canonical pre-1.0 release metadata.
func ValidateRelease(version, commit string) error {
	if len(version) > 32 {
		return fmt.Errorf("version exceeds 32 characters")
	}
	if !releaseVersionPattern.MatchString(version) {
		return fmt.Errorf("version %q is not a canonical v0.<minor>.<patch> release", version)
	}
	if !commitPattern.MatchString(commit) {
		return fmt.Errorf("commit must be a full lowercase 40-character SHA")
	}
	return nil
}
