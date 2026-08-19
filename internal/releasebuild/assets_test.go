package releasebuild

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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
		"packages": validSBOMPackages(),
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

func validSBOMPackages() []map[string]any {
	packages := []struct {
		name    string
		version string
	}{
		{name: "InboxGate", version: "v0.1.0"},
		{name: "github.com/google/jsonschema-go", version: "v0.4.3"},
		{name: "github.com/modelcontextprotocol/go-sdk", version: "v1.7.0"},
		{name: "github.com/segmentio/asm", version: "v1.1.3"},
		{name: "github.com/segmentio/encoding", version: "v0.5.4"},
		{name: "github.com/yosida95/uritemplate/v3", version: "v3.0.2"},
		{name: "go.yaml.in/yaml/v3", version: "v3.0.5"},
		{name: "golang.org/x/oauth2", version: "v0.36.0"},
		{name: "golang.org/x/sync", version: "v0.20.0"},
		{name: "golang.org/x/sys", version: "v0.41.0"},
		{name: "golang.org/x/time", version: "v0.15.0"},
		{name: "turso.tech/database/tursogo-serverless", version: "v0.0.0-20260817122138-24adc316cdc4"},
	}
	result := make([]map[string]any, 0, len(packages))
	for index, pkg := range packages {
		result = append(result, map[string]any{
			"name":             pkg.name,
			"SPDXID":           "SPDXRef-Package-" + strings.NewReplacer("/", "-", ".", "-").Replace(pkg.name) + "-" + strconv.Itoa(index),
			"versionInfo":      pkg.version,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"licenseConcluded": "NOASSERTION",
			"licenseDeclared":  "NOASSERTION",
			"copyrightText":    "NOASSERTION",
		})
	}
	return result
}
