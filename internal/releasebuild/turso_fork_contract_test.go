package releasebuild

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	tursoForkVersion      = "v0.0.0-20260817122138-24adc316cdc4"
	tursoForkCommit       = "24adc316cdc4ebf93d90b94dbfda727195540497"
	tursoForkPath         = "./third_party/tursogo-serverless"
	tursoForkTreeSHA256   = "4ce5b8f1db237ec167eb7ca26bf9383e2971bdc6432ecead3441abc1a053e40c"
	maximumForkManifest   = 64 * 1024
	ambientCredentialText = "turso fork tests refuse ambient live configuration"
)

var acceptedUpstreamTursoFileSHA256 = map[string]string{
	"LICENSE":                   "b646f9ee8bcaf87e8de75153b9df7a2861c7ac445c87e741768b3c2bccf47bc5",
	"README.md":                 "372c9e177a79aa9df94a4d31a4b6f70dfc644d59ecfe6e2d5012a4c81e276c28",
	"driver.go":                 "0d809bd67b3b3e6c86618be2561073be1e929b5b61f75d6e43ded87c66e1894e",
	"driver_test.go":            "a8ab2e634d9e3da011f067561545a060f790a8544fe0d167fa254897dd0f43eb",
	"encryption_header_test.go": "8ca1300bb14acea96fbf307315d2a605b5919ad0626b99835094b821df1ef997",
	"example_test.go":           "19d78d621c7bd5ca589cf369e8f3b62ff13f673a02a1f3638abc6729ce843a3f",
	"go.mod":                    "82ecd1f2909a4fd369f9446473902de9b4d9d2153bb63cd118522cd98c36f15f",
	"protocol.go":               "bb2b1dd96bdf7abcc3698611b2e40ee90dc578525f3915a6fe045a96d072db00",
	"session.go":                "e3113a9f5438782c52fd8355aaa3452214a82ff3ae2cc3fba2c61c6f8c4b8029",
}

type tursoForkManifest struct {
	SchemaVersion     int                     `json:"schema_version"`
	ModulePath        string                  `json:"module_path"`
	UpstreamVersion   string                  `json:"upstream_version"`
	UpstreamCommit    string                  `json:"upstream_commit"`
	UpstreamModuleSum string                  `json:"upstream_module_sum"`
	UpstreamModSum    string                  `json:"upstream_go_mod_sum"`
	UpstreamTreeHash  string                  `json:"upstream_tree_sha256"`
	LocalModulePath   string                  `json:"local_module_path"`
	ModifiedFiles     []string                `json:"modified_files"`
	NormalizedFiles   []string                `json:"normalized_files"`
	Files             []tursoForkManifestFile `json:"files"`
}

type tursoForkManifestFile struct {
	Path           string `json:"path"`
	Source         string `json:"source"`
	UpstreamSHA256 string `json:"upstream_sha256"`
	LocalSHA256    string `json:"local_sha256"`
}

var exactManifestJSONKeys = map[string]struct{}{
	"schema_version":       {},
	"module_path":          {},
	"upstream_version":     {},
	"upstream_commit":      {},
	"upstream_module_sum":  {},
	"upstream_go_mod_sum":  {},
	"upstream_tree_sha256": {},
	"local_module_path":    {},
	"modified_files":       {},
	"normalized_files":     {},
	"files":                {},
	"path":                 {},
	"source":               {},
	"upstream_sha256":      {},
	"local_sha256":         {},
}

func decodeTursoForkManifest(data []byte) (tursoForkManifest, error) {
	if len(data) == 0 || len(data) > maximumForkManifest {
		return tursoForkManifest{}, errors.New("Turso fork manifest size is outside the accepted bound")
	}
	keys := json.NewDecoder(bytes.NewReader(data))
	if err := scanExactManifestJSON(keys); err != nil {
		return tursoForkManifest{}, err
	}
	if _, err := keys.Token(); !errors.Is(err, io.EOF) {
		return tursoForkManifest{}, errors.New("Turso fork manifest contains trailing JSON")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest tursoForkManifest
	if err := decoder.Decode(&manifest); err != nil {
		return tursoForkManifest{}, err
	}
	if err := validateTursoForkManifestShape(manifest); err != nil {
		return tursoForkManifest{}, err
	}
	return manifest, nil
}

func scanExactManifestJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("Turso fork manifest object key is not a string")
			}
			if _, ok := exactManifestJSONKeys[key]; !ok {
				return errors.New("Turso fork manifest contains an unknown or noncanonical key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("Turso fork manifest contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := scanExactManifestJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("Turso fork manifest object is malformed")
		}
	case '[':
		for decoder.More() {
			if err := scanExactManifestJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("Turso fork manifest array is malformed")
		}
	default:
		return errors.New("Turso fork manifest contains an unexpected delimiter")
	}
	return nil
}

func validateTursoForkManifestShape(manifest tursoForkManifest) error {
	if !isLowerHexSHA256(manifest.UpstreamTreeHash) {
		return errors.New("Turso fork upstream tree hash is not canonical SHA-256")
	}
	seenPaths := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if file.Path == "" {
			return errors.New("Turso fork manifest contains an empty file path")
		}
		if _, duplicate := seenPaths[file.Path]; duplicate {
			return errors.New("Turso fork manifest contains a duplicate file path")
		}
		seenPaths[file.Path] = struct{}{}
		if !isLowerHexSHA256(file.LocalSHA256) {
			return errors.New("Turso fork manifest contains a noncanonical local hash")
		}
		switch file.Source {
		case "upstream":
			if !isLowerHexSHA256(file.UpstreamSHA256) {
				return errors.New("Turso fork manifest contains a noncanonical upstream hash")
			}
		case "local":
			if file.UpstreamSHA256 != "" {
				return errors.New("Turso fork local file has an upstream hash")
			}
		default:
			return errors.New("Turso fork manifest contains an invalid source")
		}
	}
	return nil
}

func isLowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func TestTursoForkManifestPinsEveryCopiedAndLocalFile(t *testing.T) {
	root := repositoryRoot(t)
	forkRoot := filepath.Join(root, "third_party", "tursogo-serverless")
	manifestPath := filepath.Join(forkRoot, "INBOXGATE_PROVENANCE.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read Turso fork manifest: %v", err)
	}
	manifest, err := decodeTursoForkManifest(data)
	if err != nil {
		t.Fatalf("decode Turso fork manifest: %v", err)
	}
	if manifest.SchemaVersion != 1 ||
		manifest.ModulePath != tursoModulePath ||
		manifest.UpstreamVersion != tursoForkVersion ||
		manifest.UpstreamCommit != tursoForkCommit ||
		manifest.UpstreamModuleSum != tursoModuleSum ||
		manifest.UpstreamModSum != "h1:KWrz0BzLKiXUkLmM5HXyr/gWA8ySNZexfW0NV0GGk0A=" ||
		manifest.LocalModulePath != tursoForkPath {
		t.Fatalf("Turso fork manifest identity = %#v, want exact accepted upstream and local fork", manifest)
	}
	if manifest.UpstreamTreeHash != tursoForkTreeSHA256 {
		t.Fatalf("upstream tree hash = %q, want accepted %q", manifest.UpstreamTreeHash, tursoForkTreeSHA256)
	}
	wantModified := []string{"driver.go", "session.go"}
	if !reflect.DeepEqual(manifest.ModifiedFiles, wantModified) {
		t.Fatalf("modified files = %q, want %q", manifest.ModifiedFiles, wantModified)
	}
	wantNormalized := []string{"README.md", "encryption_header_test.go"}
	if !reflect.DeepEqual(manifest.NormalizedFiles, wantNormalized) {
		t.Fatalf("normalized files = %q, want %q", manifest.NormalizedFiles, wantNormalized)
	}

	wantFiles := []string{
		"INBOXGATE_PROVENANCE.json",
		"LICENSE",
		"README.md",
		"close_contract_test.go",
		"driver.go",
		"driver_test.go",
		"encryption_header_test.go",
		"example_test.go",
		"go.mod",
		"protocol.go",
		"session.go",
	}
	entries, err := os.ReadDir(forkRoot)
	if err != nil {
		t.Fatalf("read local fork directory: %v", err)
	}
	var gotFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected directory in local fork: %q", entry.Name())
		}
		gotFiles = append(gotFiles, entry.Name())
	}
	sort.Strings(gotFiles)
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("local fork files = %q, want exact copied and local contract files %q", gotFiles, wantFiles)
	}

	wantManifestFiles := append([]string(nil), wantFiles...)
	wantManifestFiles = wantManifestFiles[1:]
	gotManifestFiles := make([]string, 0, len(manifest.Files))
	modified := map[string]bool{"driver.go": true, "session.go": true}
	normalized := map[string]bool{"README.md": true, "encryption_header_test.go": true}
	for _, file := range manifest.Files {
		gotManifestFiles = append(gotManifestFiles, file.Path)
		contents, err := os.ReadFile(filepath.Join(forkRoot, file.Path))
		if err != nil {
			t.Fatalf("read manifested file %q: %v", file.Path, err)
		}
		digest := sha256.Sum256(contents)
		if got := hex.EncodeToString(digest[:]); got != file.LocalSHA256 {
			t.Fatalf("local hash for %q = %q, want manifest %q", file.Path, got, file.LocalSHA256)
		}
		switch file.Source {
		case "upstream":
			if want, ok := acceptedUpstreamTursoFileSHA256[file.Path]; !ok || file.UpstreamSHA256 != want {
				t.Fatalf("upstream hash for %q = %q, want independently accepted %q", file.Path, file.UpstreamSHA256, want)
			}
			changed := modified[file.Path] || normalized[file.Path]
			if changed == (file.UpstreamSHA256 == file.LocalSHA256) {
				t.Fatalf("manifest change status for %q does not match the semantic and normalization allowlists", file.Path)
			}
		case "local":
			if file.Path != "close_contract_test.go" || file.UpstreamSHA256 != "" || len(file.LocalSHA256) != 64 {
				t.Fatalf("local-only manifest entry = %#v, want the exact close contract test", file)
			}
		default:
			t.Fatalf("manifest source for %q = %q, want upstream or local", file.Path, file.Source)
		}
	}
	sort.Strings(gotManifestFiles)
	if !reflect.DeepEqual(gotManifestFiles, wantManifestFiles) {
		t.Fatalf("manifest files = %q, want %q", gotManifestFiles, wantManifestFiles)
	}
	if len(acceptedUpstreamTursoFileSHA256) != 9 {
		t.Fatalf("accepted upstream file hash count = %d, want 9", len(acceptedUpstreamTursoFileSHA256))
	}
}

func TestTursoForkManifestStrictlyRejectsAmbiguousOrMalformedEvidence(t *testing.T) {
	manifestPath := filepath.Join(repositoryRoot(t), "third_party", "tursogo-serverless", "INBOXGATE_PROVENANCE.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	tests := []struct {
		name string
		data string
	}{
		{name: "duplicate key", data: strings.Replace(valid, "{", "{\n  \"schema_version\": 1,", 1)},
		{name: "case alias", data: strings.Replace(valid, "\"schema_version\"", "\"SCHEMA_VERSION\"", 1)},
		{name: "unknown field", data: strings.Replace(valid, "{", "{\n  \"unexpected\": true,", 1)},
		{name: "malformed JSON", data: valid[:len(valid)-2]},
		{name: "uppercase hash", data: strings.Replace(valid, tursoForkTreeSHA256, strings.ToUpper(tursoForkTreeSHA256), 1)},
		{name: "nonhex hash", data: strings.Replace(valid, tursoForkTreeSHA256, "z"+tursoForkTreeSHA256[1:], 1)},
		{name: "inconsistent source", data: strings.Replace(valid, "\"source\": \"upstream\"", "\"source\": \"local\"", 1)},
		{name: "trailing JSON", data: valid + "{}"},
		{name: "oversized", data: valid + strings.Repeat(" ", maximumForkManifest)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeTursoForkManifest([]byte(test.data)); err == nil {
				t.Fatal("decode accepted invalid provenance evidence")
			}
		})
	}
}

func TestMakeCheckRequiresCredentialFreeNestedTursoModuleGates(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join(repositoryRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(contents)
	for _, required := range []string{
		"turso-fork-tidy-check:",
		"turso-fork-verify:",
		"turso-fork-vet:",
		"turso-fork-test:",
		"turso-fork-test-race:",
		"unset TURSO_DATABASE_URL TURSO_AUTH_TOKEN;",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile does not require %q", required)
		}
	}
	checkLine := "check: fmt-check tidy-check verify vet test test-fuzz test-race vuln actionlint turso-fork-tidy-check turso-fork-verify turso-fork-vet turso-fork-test turso-fork-test-race storage-cross-build release-contract build"
	if !strings.Contains(makefile, checkLine) {
		t.Errorf("Makefile check target does not include the exact nested fork gates")
	}
}

func TestTursoForkTestsFailClosedWithAmbientLiveVariables(t *testing.T) {
	root := repositoryRoot(t)
	command := exec.Command("go", "-C", filepath.Join(root, "third_party", "tursogo-serverless"), "test", "-run", "^$")
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "TURSO_DATABASE_URL=") && !strings.HasPrefix(variable, "TURSO_AUTH_TOKEN=") {
			command.Env = append(command.Env, variable)
		}
	}
	command.Env = append(command.Env, "TURSO_DATABASE_URL=https://synthetic.invalid", "TURSO_AUTH_TOKEN=synthetic-never-used")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("nested Turso tests accepted ambient live configuration")
	}
	if !strings.Contains(string(output), ambientCredentialText) {
		t.Fatalf("nested Turso test refusal = %q, want fixed credential-free diagnostic", output)
	}
}

func TestGoModuleUsesExactReviewedLocalTursoReplacementWithoutGraphGrowth(t *testing.T) {
	root := repositoryRoot(t)
	command := exec.Command("go", "list", "-mod=readonly", "-m", "-json", "all")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list module graph: %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	type module struct {
		Path    string
		Version string
		Replace *struct {
			Path    string
			Version string
		}
	}
	var modules []module
	for {
		var value module
		if err := decoder.Decode(&value); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode module graph: %v", err)
		}
		modules = append(modules, value)
	}
	if len(modules) != 16 {
		t.Fatalf("module graph size = %d, want unchanged 16-module selected graph", len(modules))
	}
	var found *module
	for index := range modules {
		if modules[index].Path == tursoModulePath {
			found = &modules[index]
			break
		}
	}
	if found == nil || found.Version != tursoForkVersion || found.Replace == nil ||
		found.Replace.Path != tursoForkPath || found.Replace.Version != "" {
		t.Fatalf("Turso module resolution = %#v, want exact requirement replaced only by %q", found, tursoForkPath)
	}
}

func TestReleaseBinaryIdentifiesReviewedLocalTursoReplacement(t *testing.T) {
	root := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "inboxgate")
	command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/inboxgate")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build release dependency probe: %v: %s", err, output)
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatalf("read release dependency probe: %v", err)
	}
	for _, dependency := range info.Deps {
		if dependency.Path != tursoModulePath {
			continue
		}
		if dependency.Version != tursoForkVersion || dependency.Replace == nil ||
			dependency.Replace.Path != tursoForkPath || dependency.Replace.Version != "(devel)" || dependency.Replace.Sum != "" {
			t.Fatalf("release Turso build metadata = %#v, want exact upstream requirement and local replacement", dependency)
		}
		return
	}
	t.Fatal("release binary omits the reviewed Turso local replacement")
}

func TestModifiedTursoSourceNoticeIsExact(t *testing.T) {
	notice, err := os.ReadFile(filepath.Join(repositoryRoot(t), "THIRD_PARTY_NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(notice)
	for _, required := range []string{
		"modified local source",
		tursoForkVersion,
		tursoForkCommit,
		"third_party/tursogo-serverless",
		"driver.go",
		"session.go",
		"MIT License",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("Turso modified-source notice is missing %q", required)
		}
	}
}
