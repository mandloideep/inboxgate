package releasebuild

import (
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
	tursoForkVersion = "v0.0.0-20260817122138-24adc316cdc4"
	tursoForkCommit  = "24adc316cdc4ebf93d90b94dbfda727195540497"
	tursoForkPath    = "./third_party/tursogo-serverless"
)

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
	Files             []tursoForkManifestFile `json:"files"`
}

type tursoForkManifestFile struct {
	Path           string `json:"path"`
	Source         string `json:"source"`
	UpstreamSHA256 string `json:"upstream_sha256"`
	LocalSHA256    string `json:"local_sha256"`
}

func TestTursoForkManifestPinsEveryCopiedAndLocalFile(t *testing.T) {
	root := repositoryRoot(t)
	forkRoot := filepath.Join(root, "third_party", "tursogo-serverless")
	manifestPath := filepath.Join(forkRoot, "INBOXGATE_PROVENANCE.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read Turso fork manifest: %v", err)
	}
	var manifest tursoForkManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
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
	if len(manifest.UpstreamTreeHash) != 64 {
		t.Fatalf("upstream tree hash = %q, want SHA-256", manifest.UpstreamTreeHash)
	}
	wantModified := []string{"driver.go", "session.go"}
	if !reflect.DeepEqual(manifest.ModifiedFiles, wantModified) {
		t.Fatalf("modified files = %q, want %q", manifest.ModifiedFiles, wantModified)
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
			if len(file.UpstreamSHA256) != 64 || len(file.LocalSHA256) != 64 {
				t.Fatalf("manifest hashes for upstream file %q are not SHA-256 values", file.Path)
			}
			if modified[file.Path] == (file.UpstreamSHA256 == file.LocalSHA256) {
				t.Fatalf("manifest modification status for %q does not match the two-file allowlist", file.Path)
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
