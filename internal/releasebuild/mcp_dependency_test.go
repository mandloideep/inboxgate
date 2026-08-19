package releasebuild

import (
	"debug/buildinfo"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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

func TestSyntheticSBOMMatchesPinnedSyftSixBinaryShape(t *testing.T) {
	packages := validSBOMPackages()
	if len(packages) != 81 {
		t.Fatalf("synthetic pinned-Syft package rows = %d, want 81", len(packages))
	}
	wantCounts := map[string]int{
		"InboxGate": 1, "github.com/mandloideep/inboxgate": 6, "github.com/google/jsonschema-go": 6,
		"github.com/modelcontextprotocol/go-sdk": 6, "github.com/segmentio/asm": 6, "github.com/segmentio/encoding": 6,
		"github.com/yosida95/uritemplate/v3": 6, "go.yaml.in/yaml/v3": 6, "golang.org/x/oauth2": 6,
		"golang.org/x/sync": 6, "golang.org/x/sys": 6, "golang.org/x/time": 6,
		"turso.tech/database/tursogo-serverless": 6, "stdlib": 6, "inboxgate": 2,
	}
	gotCounts := map[string]int{}
	locationCounts := map[string]int{}
	for _, pkg := range packages {
		name := pkg["name"].(string)
		gotCounts[name]++
		if sourceInfo := sbomSourceInfo(pkg); sourceInfo != "" {
			location := strings.TrimPrefix(sourceInfo, "acquired package info from go module information: ")
			if location == sourceInfo {
				location = strings.TrimPrefix(sourceInfo, "acquired package info from the following paths: ")
			}
			locationCounts[location]++
		}
	}
	if !reflect.DeepEqual(gotCounts, wantCounts) {
		t.Fatalf("synthetic pinned-Syft package counts = %#v, want %#v", gotCounts, wantCounts)
	}
	for _, location := range []string{
		"/inboxgate_0.1.0_darwin_amd64/inboxgate", "/inboxgate_0.1.0_darwin_arm64/inboxgate",
		"/inboxgate_0.1.0_linux_amd64/inboxgate", "/inboxgate_0.1.0_linux_arm64/inboxgate",
		"/inboxgate_0.1.0_windows_amd64/inboxgate.exe", "/inboxgate_0.1.0_windows_arm64/inboxgate.exe",
	} {
		want := 13
		if strings.Contains(location, "_windows_") {
			want = 14
		}
		if got := locationCounts[location]; got != want {
			t.Errorf("synthetic pinned-Syft rows at %q = %d, want %d", location, got, want)
		}
	}
}

func TestSBOMValidationRequiresCompleteExactLinkedRuntimeInventory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "sbom.json")
	write := func(t *testing.T, mutate func(map[string]any)) error {
		t.Helper()
		var document map[string]any
		if err := json.Unmarshal(validSBOMJSON(t), &document); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(document)
		}
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return ValidateSBOM(path, "v0.1.0", directory)
	}
	if err := write(t, nil); err != nil {
		t.Errorf("pinned Syft six-binary inventory rejected: %v", err)
	}

	mutants := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing distinct module", mutate: func(document map[string]any) {
			document["packages"] = filterSBOMPackages(document, func(pkg map[string]any) bool {
				return pkg["name"] != "github.com/modelcontextprotocol/go-sdk"
			})
		}},
		{name: "missing module at one binary", mutate: func(document map[string]any) {
			document["packages"] = filterSBOMPackages(document, func(pkg map[string]any) bool {
				return pkg["name"] != "github.com/modelcontextprotocol/go-sdk" || !strings.Contains(sbomSourceInfo(pkg), "linux_amd64")
			})
		}},
		{name: "wrong module version", mutate: func(document map[string]any) {
			forEachSBOMPackage(document, "github.com/segmentio/asm", func(pkg map[string]any) { pkg["versionInfo"] = "v1.1.4" })
		}},
		{name: "inconsistent duplicate versions", mutate: func(document map[string]any) {
			mutateFirstSBOMPackage(document, "golang.org/x/time", func(pkg map[string]any) { pkg["versionInfo"] = "v0.15.1" })
		}},
		{name: "unexpected module", mutate: func(document map[string]any) {
			appendSBOMPackage(document, map[string]any{
				"name": "example.invalid/unreviewed-runtime", "SPDXID": "SPDXRef-Package-unexpected", "versionInfo": "v1.0.0",
				"sourceInfo":       "acquired package info from go module information: /inboxgate_0.1.0_linux_amd64/inboxgate",
				"downloadLocation": "NOASSERTION", "filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
			})
		}},
		{name: "missing stdlib", mutate: func(document map[string]any) {
			document["packages"] = filterSBOMPackages(document, func(pkg map[string]any) bool { return pkg["name"] != "stdlib" })
		}},
		{name: "wrong stdlib", mutate: func(document map[string]any) {
			forEachSBOMPackage(document, "stdlib", func(pkg map[string]any) { pkg["versionInfo"] = "go1.26.5" })
		}},
		{name: "duplicate expected location", mutate: func(document map[string]any) {
			duplicateFirstSBOMPackage(document, "golang.org/x/sync", nil)
		}},
		{name: "duplicate with unexpected location", mutate: func(document map[string]any) {
			duplicateFirstSBOMPackage(document, "github.com/google/jsonschema-go", func(pkg map[string]any) {
				pkg["sourceInfo"] = "acquired package info from go module information: /unexpected/inboxgate"
			})
		}},
		{name: "location escape", mutate: func(document map[string]any) {
			mutateFirstSBOMPackage(document, "github.com/yosida95/uritemplate/v3", func(pkg map[string]any) {
				pkg["sourceInfo"] = "acquired package info from go module information: /inboxgate_0.1.0_linux_amd64/../inboxgate"
			})
		}},
		{name: "location alias", mutate: func(document map[string]any) {
			mutateFirstSBOMPackage(document, "go.yaml.in/yaml/v3", func(pkg map[string]any) {
				pkg["sourceInfo"] = "acquired package info from go module information: //inboxgate_0.1.0_darwin_amd64/inboxgate"
			})
		}},
		{name: "missing main module location", mutate: func(document map[string]any) {
			document["packages"] = filterSBOMPackages(document, func(pkg map[string]any) bool {
				return pkg["name"] != "github.com/mandloideep/inboxgate" || !strings.Contains(sbomSourceInfo(pkg), "windows_arm64")
			})
		}},
		{name: "unexpected binary classifier scope", mutate: func(document map[string]any) {
			duplicateFirstSBOMPackage(document, "inboxgate", func(pkg map[string]any) {
				pkg["sourceInfo"] = "acquired package info from the following paths: /inboxgate_0.1.0_linux_amd64/inboxgate"
			})
		}},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			if err := write(t, mutant.mutate); err == nil {
				t.Fatal("SBOM accepted mutated pinned-Syft inventory")
			}
		})
	}
}

func filterSBOMPackages(document map[string]any, keep func(map[string]any) bool) []any {
	result := make([]any, 0, len(document["packages"].([]any)))
	for _, value := range document["packages"].([]any) {
		if pkg := value.(map[string]any); keep(pkg) {
			result = append(result, pkg)
		}
	}
	return result
}

func forEachSBOMPackage(document map[string]any, name string, mutate func(map[string]any)) {
	for _, value := range document["packages"].([]any) {
		if pkg := value.(map[string]any); pkg["name"] == name {
			mutate(pkg)
		}
	}
}

func mutateFirstSBOMPackage(document map[string]any, name string, mutate func(map[string]any)) {
	for _, value := range document["packages"].([]any) {
		if pkg := value.(map[string]any); pkg["name"] == name {
			mutate(pkg)
			return
		}
	}
}

func duplicateFirstSBOMPackage(document map[string]any, name string, mutate func(map[string]any)) {
	for _, value := range document["packages"].([]any) {
		pkg := value.(map[string]any)
		if pkg["name"] != name {
			continue
		}
		duplicate := make(map[string]any, len(pkg))
		for key, item := range pkg {
			duplicate[key] = item
		}
		duplicate["SPDXID"] = duplicate["SPDXID"].(string) + "-duplicate"
		if mutate != nil {
			mutate(duplicate)
		}
		appendSBOMPackage(document, duplicate)
		return
	}
}

func appendSBOMPackage(document map[string]any, pkg map[string]any) {
	document["packages"] = append(document["packages"].([]any), pkg)
}

func sbomSourceInfo(pkg map[string]any) string {
	value, _ := pkg["sourceInfo"].(string)
	return value
}

func containsString(values []string, target string) bool {
	return sort.SearchStrings(values, target) < len(values) && values[sort.SearchStrings(values, target)] == target
}

func TestReviewedMCPModuleListIsUnique(t *testing.T) {
	values := []string{
		"github.com/google/jsonschema-go v0.4.3",
		"github.com/modelcontextprotocol/go-sdk v1.7.0",
		"github.com/segmentio/asm v1.1.3",
		"github.com/segmentio/encoding v0.5.4",
		"github.com/yosida95/uritemplate/v3 v3.0.2",
		"go.yaml.in/yaml/v3 v3.0.5",
		"golang.org/x/oauth2 v0.36.0",
		"golang.org/x/sync v0.20.0",
		"golang.org/x/sys v0.41.0",
		"golang.org/x/time v0.15.0",
		"turso.tech/database/tursogo-serverless v0.0.0-20260817122138-24adc316cdc4",
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
