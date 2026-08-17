package releasebuild

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAssetSetRequiresExactlyEightAssets(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	version := "v0.1.0"
	versionNumber := strings.TrimPrefix(version, "v")
	var payloads []string
	for _, target := range Targets {
		extension := ".tar.gz"
		if target.GOOS == "windows" {
			extension = ".zip"
		}
		path := filepath.Join(directory, "inboxgate_"+versionNumber+"_"+target.GOOS+"_"+target.GOARCH+extension)
		if err := os.WriteFile(path, []byte(target.GOOS+target.GOARCH), 0o600); err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, path)
	}
	sbomPath := filepath.Join(directory, "inboxgate_0.1.0_sbom.spdx.json")
	if err := os.WriteFile(sbomPath, validSBOMJSON(t), 0o600); err != nil {
		t.Fatal(err)
	}
	payloads = append(payloads, sbomPath)
	if err := WriteChecksums(filepath.Join(directory, "SHA256SUMS"), payloads); err != nil {
		t.Fatal(err)
	}

	if err := ValidateAssetSet(directory, version, directory); err != nil {
		t.Fatalf("ValidateAssetSet() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected.txt"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAssetSet(directory, version, directory); err == nil {
		t.Fatal("ValidateAssetSet() accepted a ninth asset")
	}
}

func validSBOMJSON(t *testing.T) []byte {
	t.Helper()
	document := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "InboxGate",
		"documentNamespace": "https://github.com/mandloideep/inboxgate/releases/v0.1.0/sbom",
		"creationInfo": map[string]any{
			"created":  "2026-08-16T00:00:00Z",
			"creators": []string{"Tool: syft-1.51.0"},
		},
		"packages": []map[string]any{{
			"name":             "InboxGate",
			"SPDXID":           "SPDXRef-Package-InboxGate",
			"versionInfo":      "v0.1.0",
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"licenseConcluded": "NOASSERTION",
			"licenseDeclared":  "NOASSERTION",
			"copyrightText":    "NOASSERTION",
		}},
		"files": []map[string]any{
			{"fileName": "inboxgate_0.1.0_darwin_amd64/inboxgate"},
			{"fileName": "inboxgate_0.1.0_darwin_arm64/inboxgate"},
			{"fileName": "inboxgate_0.1.0_linux_amd64/inboxgate"},
			{"fileName": "inboxgate_0.1.0_linux_arm64/inboxgate"},
			{"fileName": "inboxgate_0.1.0_windows_amd64/inboxgate.exe"},
			{"fileName": "inboxgate_0.1.0_windows_arm64/inboxgate.exe"},
		},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
