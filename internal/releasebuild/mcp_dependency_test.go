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
		t.Fatalf("exact linked runtime inventory rejected: %v", err)
	}

	want := []struct {
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
	for _, expected := range want {
		t.Run("omit_"+expected.name, func(t *testing.T) {
			err := write(t, func(document map[string]any) {
				var kept []any
				for _, value := range document["packages"].([]any) {
					if value.(map[string]any)["name"] != expected.name {
						kept = append(kept, value)
					}
				}
				document["packages"] = kept
			})
			if err == nil {
				t.Fatal("SBOM accepted omitted reviewed runtime package")
			}
		})
		t.Run("wrong_version_"+expected.name, func(t *testing.T) {
			err := write(t, func(document map[string]any) {
				for _, value := range document["packages"].([]any) {
					pkg := value.(map[string]any)
					if pkg["name"] == expected.name {
						pkg["versionInfo"] = expected.version + ".wrong"
					}
				}
			})
			if err == nil {
				t.Fatal("SBOM accepted wrong reviewed runtime version")
			}
		})
		t.Run("duplicate_"+expected.name, func(t *testing.T) {
			err := write(t, func(document map[string]any) {
				for _, value := range document["packages"].([]any) {
					pkg := value.(map[string]any)
					if pkg["name"] == expected.name {
						duplicate := make(map[string]any, len(pkg))
						for key, item := range pkg {
							duplicate[key] = item
						}
						duplicate["SPDXID"] = duplicate["SPDXID"].(string) + "-duplicate"
						document["packages"] = append(document["packages"].([]any), duplicate)
						return
					}
				}
			})
			if err == nil {
				t.Fatal("SBOM accepted duplicate reviewed runtime package")
			}
		})
	}

	if err := write(t, func(document map[string]any) {
		unexpected := map[string]any{
			"name": "example.invalid/unreviewed-runtime", "SPDXID": "SPDXRef-Package-unexpected", "versionInfo": "v1.0.0",
			"downloadLocation": "NOASSERTION", "filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
		}
		document["packages"] = append(document["packages"].([]any), unexpected)
	}); err == nil {
		t.Fatal("SBOM accepted unexpected runtime package")
	}
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
