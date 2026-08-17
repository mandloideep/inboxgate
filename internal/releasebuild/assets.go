package releasebuild

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ValidateAssetSet requires the exact six archives, SPDX SBOM, and checksum file.
func ValidateAssetSet(directory, version, workspace string) error {
	if err := ValidateMetadata(version, strings.Repeat("0", 40)); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	want := expectedAssetNames(version)
	if len(entries) != len(want) {
		return fmt.Errorf("release asset count = %d, want %d", len(entries), len(want))
	}
	var payloads []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("release asset %q is not a regular file", entry.Name())
		}
		if _, found := want[entry.Name()]; !found {
			return fmt.Errorf("unexpected release asset %q", entry.Name())
		}
		delete(want, entry.Name())
		if entry.Name() != "SHA256SUMS" {
			payloads = append(payloads, filepath.Join(directory, entry.Name()))
		}
	}
	if len(want) != 0 {
		return fmt.Errorf("release asset set is missing %d files", len(want))
	}
	sort.Strings(payloads)
	versionNumber := strings.TrimPrefix(version, "v")
	if err := ValidateSBOM(filepath.Join(directory, fmt.Sprintf("inboxgate_%s_sbom.spdx.json", versionNumber)), version, workspace); err != nil {
		return err
	}
	return ValidateChecksums(filepath.Join(directory, "SHA256SUMS"), payloads)
}

func expectedAssetNames(version string) map[string]struct{} {
	versionNumber := strings.TrimPrefix(version, "v")
	want := map[string]struct{}{
		"SHA256SUMS": {},
		fmt.Sprintf("inboxgate_%s_sbom.spdx.json", versionNumber): {},
	}
	for _, target := range Targets {
		extension := ".tar.gz"
		if target.GOOS == "windows" {
			extension = ".zip"
		}
		want[fmt.Sprintf("inboxgate_%s_%s_%s%s", versionNumber, target.GOOS, target.GOARCH, extension)] = struct{}{}
	}
	return want
}
