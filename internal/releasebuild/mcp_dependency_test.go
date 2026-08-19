package releasebuild

import (
	"debug/buildinfo"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestReleaseBinaryIncludesReviewedMCPRuntimeModules(t *testing.T) {
	root := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "inboxgate")
	command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/inboxgate")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build release dependency probe: %v: %s", err, output)
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, dependency := range info.Deps {
		got = append(got, dependency.Path+" "+dependency.Version)
	}
	sort.Strings(got)
	wantRequired := []string{
		"github.com/modelcontextprotocol/go-sdk v1.7.0",
		"github.com/google/jsonschema-go v0.4.3",
		"github.com/segmentio/encoding v0.5.4",
		"github.com/yosida95/uritemplate/v3 v3.0.2",
	}
	for _, dependency := range wantRequired {
		if !containsString(got, dependency) {
			t.Errorf("release binary dependencies omit %q: %q", dependency, got)
		}
	}
}

func TestSBOMValidationRequiresExactMCPPackage(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "sbom.json")
	var document map[string]any
	if err := json.Unmarshal(validSBOMJSON(t), &document); err != nil {
		t.Fatal(err)
	}
	packages := document["packages"].([]any)
	mcpPackage := map[string]any{
		"name":             "github.com/modelcontextprotocol/go-sdk",
		"SPDXID":           "SPDXRef-Package-go-sdk",
		"versionInfo":      "v1.7.0",
		"downloadLocation": "NOASSERTION",
		"filesAnalyzed":    false,
		"licenseConcluded": "Apache-2.0",
		"licenseDeclared":  "Apache-2.0",
		"copyrightText":    "NOASSERTION",
	}
	document["packages"] = append(packages, mcpPackage)
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSBOM(path, "v0.1.0", directory); err != nil {
		t.Fatalf("SBOM with exact MCP package rejected: %v", err)
	}

	document["packages"] = packages
	data, _ = json.Marshal(document)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSBOM(path, "v0.1.0", directory); err == nil {
		t.Fatal("SBOM without MCP package accepted")
	}
}

func containsString(values []string, target string) bool {
	return sort.SearchStrings(values, target) < len(values) && values[sort.SearchStrings(values, target)] == target
}

func TestReviewedMCPModuleListIsUnique(t *testing.T) {
	values := []string{
		"github.com/modelcontextprotocol/go-sdk v1.7.0",
		"github.com/google/jsonschema-go v0.4.3",
		"github.com/segmentio/encoding v0.5.4",
		"github.com/yosida95/uritemplate/v3 v3.0.2",
	}
	copyOfValues := append([]string(nil), values...)
	sort.Strings(copyOfValues)
	if reflect.DeepEqual(copyOfValues, []string{}) {
		t.Fatal("reviewed module list is empty")
	}
	for index := 1; index < len(copyOfValues); index++ {
		if copyOfValues[index] == copyOfValues[index-1] {
			t.Fatalf("duplicate reviewed module %q", copyOfValues[index])
		}
	}
}
