package releasebuild

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestValidateMetadata(t *testing.T) {
	t.Parallel()

	valid := []string{"v0.1.0", "v0.12.3", "v0.1.10"}
	for _, version := range valid {
		version := version
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			if err := ValidateMetadata(version, testCommit); err != nil {
				t.Fatalf("ValidateMetadata(%q, valid commit) error = %v", version, err)
			}
		})
	}

	invalidVersions := []string{
		"", "0.1.0", "v0.0.1", "v0.01.0", "v0.1.01", "v0.1.0-rc.1",
		"v0.1.0+build", "v1.0.0", "v0.1.0;echo", "v0.1.0\nnext", "v0.123456789012345678901234567890.1",
	}
	for _, version := range invalidVersions {
		version := version
		t.Run("invalid_"+strings.NewReplacer("/", "_", "\n", "newline").Replace(version), func(t *testing.T) {
			t.Parallel()
			if err := ValidateMetadata(version, testCommit); err == nil {
				t.Fatalf("ValidateMetadata(%q, valid commit) succeeded, want error", version)
			}
		})
	}

	invalidCommits := []string{"", testCommit[:12], strings.ToUpper(testCommit), strings.Repeat("g", 40), testCommit + "0"}
	for _, commit := range invalidCommits {
		commit := commit
		t.Run("invalid_commit_"+commit, func(t *testing.T) {
			t.Parallel()
			if err := ValidateMetadata("v0.1.0", commit); err == nil {
				t.Fatalf("ValidateMetadata(valid version, %q) succeeded, want error", commit)
			}
		})
	}
}

func TestBuildAllTargetsIsDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compilation is an integration test")
	}

	root := repositoryRoot(t)
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")

	firstResult := buildValidateAndPackage(t, BuildOptions{Root: root, Output: first, Version: "v0.1.0", Commit: testCommit})
	secondResult := buildValidateAndPackage(t, BuildOptions{Root: root, Output: second, Version: "v0.1.0", Commit: testCommit})

	if got, want := len(firstResult.Archives), 6; got != want {
		t.Fatalf("archive count = %d, want %d", got, want)
	}
	if got, want := len(firstResult.Binaries), 6; got != want {
		t.Fatalf("binary count = %d, want %d", got, want)
	}
	if !reflect.DeepEqual(baseNames(firstResult.Archives), baseNames(secondResult.Archives)) {
		t.Fatalf("archive names differ: %v != %v", baseNames(firstResult.Archives), baseNames(secondResult.Archives))
	}
	for i := range firstResult.Archives {
		firstDigest := fileDigest(t, firstResult.Archives[i])
		secondDigest := fileDigest(t, secondResult.Archives[i])
		if firstDigest != secondDigest {
			t.Errorf("archive %s digest = %s, second build = %s", filepath.Base(firstResult.Archives[i]), firstDigest, secondDigest)
		}
		inspectArchive(t, firstResult.Archives[i], firstResult.Binaries[i].Path, root)
	}
	for _, binary := range firstResult.Binaries {
		if err := ValidateBinary(binary.Path, binary.GOOS, binary.GOARCH); err != nil {
			t.Errorf("ValidateBinary(%s) error = %v", filepath.Base(binary.Path), err)
		}
	}

	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if err := ValidateNativeVersion(firstResult.Binaries, "v0.1.0", testCommit); err != nil {
			t.Fatalf("ValidateNativeVersion() error = %v", err)
		}
	}
}

func TestBuildRefusesExistingOutput(t *testing.T) {
	t.Parallel()

	_, err := BuildBinaries(BuildOptions{
		Root:    repositoryRoot(t),
		Output:  t.TempDir(),
		Version: "v0.1.0",
		Commit:  testCommit,
	})
	if err == nil {
		t.Fatal("BuildBinaries() accepted an existing output directory")
	}
}

func buildValidateAndPackage(t *testing.T, options BuildOptions) Result {
	t.Helper()
	result, err := BuildBinaries(options)
	if err != nil {
		t.Fatalf("BuildBinaries() error = %v", err)
	}
	if err := ValidateHostVersion(result.Binaries, options.Version, options.Commit); err != nil {
		t.Fatalf("ValidateHostVersion() before packaging error = %v", err)
	}
	result.Archives, err = Package(options, result.Binaries)
	if err != nil {
		t.Fatalf("Package() error = %v", err)
	}
	return result
}

func TestWriteAndValidateChecksums(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for name, content := range map[string]string{"b.zip": "b", "a.tar.gz": "a", "release.spdx.json": "sbom"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checksumPath := filepath.Join(directory, "SHA256SUMS")
	files := []string{filepath.Join(directory, "b.zip"), filepath.Join(directory, "release.spdx.json"), filepath.Join(directory, "a.tar.gz")}
	if err := WriteChecksums(checksumPath, files); err != nil {
		t.Fatalf("WriteChecksums() error = %v", err)
	}
	if err := ValidateChecksums(checksumPath, files); err != nil {
		t.Fatalf("ValidateChecksums() error = %v", err)
	}
	contents, err := os.ReadFile(checksumPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	originalLines := append([]string(nil), lines...)
	var names []string
	for _, line := range lines {
		if !strings.Contains(line, "  ") {
			t.Errorf("checksum line %q is not GNU text format", line)
		}
		_, name, _ := strings.Cut(line, "  ")
		names = append(names, name)
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("checksum filenames are not sorted: %q", names)
	}
	for left, right := 0, len(lines)-1; left < right; left, right = left+1, right-1 {
		lines[left], lines[right] = lines[right], lines[left]
	}
	if err := os.WriteFile(checksumPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksums(checksumPath, files); err == nil {
		t.Fatal("ValidateChecksums() accepted entries in reverse filename order")
	}

	corrupt := append([]string(nil), originalLines...)
	corrupt[0] = strings.Repeat("0", sha256.Size*2) + corrupt[0][sha256.Size*2:]
	if err := os.WriteFile(checksumPath, []byte(strings.Join(corrupt, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksums(checksumPath, files); err == nil {
		t.Fatal("ValidateChecksums() accepted a corrupted digest")
	}

	if err := os.WriteFile(checksumPath, []byte(strings.Join(originalLines[:len(originalLines)-1], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksums(checksumPath, files); err == nil {
		t.Fatal("ValidateChecksums() accepted a missing entry")
	}

	extra := append(append([]string(nil), originalLines...), strings.Repeat("0", sha256.Size*2)+"  unexpected.txt")
	if err := os.WriteFile(checksumPath, []byte(strings.Join(extra, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksums(checksumPath, files); err == nil {
		t.Fatal("ValidateChecksums() accepted an extra entry")
	}
}

func TestValidateSBOM(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	valid := map[string]any{
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
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inboxgate_0.1.0_sbom.spdx.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSBOM(path, "v0.1.0", directory); err != nil {
		t.Fatalf("ValidateSBOM() error = %v", err)
	}

	valid["comment"] = directory
	data, err = json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSBOM(path, "v0.1.0", directory); err == nil {
		t.Fatal("ValidateSBOM() accepted a local path")
	}
}

func TestReleaseWorkflowIsManualAndPinned(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	contents, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(contents)
	onStart := strings.Index(workflow, "on:\n")
	permissionsStart := strings.Index(workflow, "\npermissions:\n")
	if onStart < 0 || permissionsStart < 0 || permissionsStart <= onStart {
		t.Fatal("release workflow is missing top-level trigger or permissions blocks")
	}
	triggerBlock := workflow[onStart:permissionsStart]
	if strings.Count(triggerBlock, "workflow_dispatch:") != 1 {
		t.Errorf("workflow_dispatch trigger count = %d, want 1", strings.Count(triggerBlock, "workflow_dispatch:"))
	}
	for _, forbidden := range []string{"pull_request:", "push:", "schedule:", "release:"} {
		if strings.Contains(triggerBlock, forbidden) {
			t.Errorf("release trigger block contains forbidden trigger %q", forbidden)
		}
	}

	usesPattern := regexp.MustCompile(`(?m)^\s+uses: [^\s@]+@([0-9a-f]{40}) # v[^\s]+$`)
	usesLines := regexp.MustCompile(`(?m)^\s+uses: .+$`).FindAllString(workflow, -1)
	pinnedUses := usesPattern.FindAllStringSubmatch(workflow, -1)
	if len(usesLines) == 0 || len(pinnedUses) != len(usesLines) {
		t.Errorf("fully pinned uses lines = %d, all uses lines = %d", len(pinnedUses), len(usesLines))
	}
	concurrencyStart := strings.Index(workflow, "\nconcurrency:\n")
	if concurrencyStart < permissionsStart {
		t.Fatal("release workflow is missing top-level concurrency after permissions")
	}
	permissionsBlock := workflow[permissionsStart+1 : concurrencyStart]
	wantPermissions := "permissions:\n  contents: write\n  checks: read\n  id-token: write\n  attestations: write\n  artifact-metadata: write\n"
	if permissionsBlock != wantPermissions {
		t.Errorf("release permissions block = %q, want exact least-privilege block %q", permissionsBlock, wantPermissions)
	}
	if strings.Contains(workflow, "anchore/sbom-action") || strings.Contains(workflow, "install.sh") {
		t.Error("release workflow trusts the rejected Syft download Action or install script")
	}
	if strings.Contains(workflow, "GET /repos/{owner}/{repo}/immutable-releases") {
		t.Error("release workflow calls an Administration-protected immutable-release settings endpoint with GITHUB_TOKEN")
	}
	if strings.Contains(workflow, "${{ secrets.") {
		t.Error("release workflow depends on an external repository secret")
	}

	for _, required := range []string{
		"  contents: write\n",
		"  checks: read\n",
		"  id-token: write\n",
		"  attestations: write\n",
		"  artifact-metadata: write\n",
		"  cancel-in-progress: false\n",
		"          persist-credentials: false\n",
		"        run: make check\n",
		"          git diff --exit-code\n",
		"TRIGGERING_ACTOR: ${{ github.triggering_actor }}",
		"RUN_ATTEMPT: ${{ github.run_attempt }}",
		"process.env.DISPATCH_ACTOR !== process.env.REPOSITORY_OWNER",
		"process.env.TRIGGERING_ACTOR !== process.env.REPOSITORY_OWNER",
		"process.env.RUN_ATTEMPT !== \"1\"",
		"process.env.DISPATCH_REF !== \"refs/heads/main\"",
		"process.env.DISPATCH_SHA !== expected",
		"main.data.object.sha !== expected",
		"check_name: \"ci-required\"",
		"completed[0].conclusion !== \"success\"",
		"releases.some((release) => release.tag_name === version)",
		"github.rest.git.createRef({owner, repo, ref: `refs/tags/${version}`, sha: expected})",
		"for (const asset of draftAssets) await downloadAndVerify(asset);",
		"for (const asset of assets) await downloadAndVerify(asset);",
		"published.data.immutable === true",
		"published.data.immutable !== true",
		"GOCACHE=\"${WORKSPACE_PATH}/.release/cache-first\"",
		"GOCACHE=\"${WORKSPACE_PATH}/.release/cache-second\"",
		"go run ./cmd/release acquire-syft --output .release/tools/syft",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("release workflow is missing required fragment %q", required)
		}
	}

	ordered := []string{
		"go run ./cmd/release build-binaries",
		"go run ./cmd/release validate-native",
		"go run ./cmd/release package",
		"github.rest.git.createRef",
		"github.rest.repos.createRelease",
		"for (const asset of draftAssets) await downloadAndVerify(asset);",
		"const main = await github.rest.git.getRef({owner, repo, ref: \"heads/main\"});",
		"const tag = await github.rest.git.getRef({owner, repo, ref: `tags/${version}`});",
		"const draft = await github.rest.repos.getRelease",
		"github.rest.repos.updateRelease",
		"for (const asset of assets) await downloadAndVerify(asset);",
	}
	previous := -1
	for _, marker := range ordered {
		index := strings.Index(workflow[previous+1:], marker)
		if index < 0 {
			t.Errorf("release workflow is missing ordered publication marker %q", marker)
			continue
		}
		previous += index + 1
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func baseNames(paths []string) []string {
	result := make([]string, len(paths))
	for i, path := range paths {
		result[i] = filepath.Base(path)
	}
	return result
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func inspectArchive(t *testing.T, path, binaryPath, root string) {
	t.Helper()
	if strings.HasSuffix(path, ".tar.gz") {
		inspectTarGz(t, path, binaryPath, root)
		return
	}
	inspectZip(t, path, binaryPath, root)
}

func inspectTarGz(t *testing.T, archivePath, binaryPath, root string) {
	t.Helper()
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	if !gz.ModTime.Equal(ArchiveTime) || gz.OS != 255 || gz.Name != "" || gz.Comment != "" {
		t.Errorf("gzip header is not normalized: modtime=%s os=%d name=%q comment=%q", gz.ModTime, gz.OS, gz.Name, gz.Comment)
	}
	reader := tar.NewReader(gz)
	var names []string
	var modes []fs.FileMode
	contents := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		modes = append(modes, header.FileInfo().Mode())
		if header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			contents[header.Name] = data
		}
		if !header.ModTime.Equal(ArchiveTime) {
			t.Errorf("tar entry %s timestamp = %s, want %s", header.Name, header.ModTime, ArchiveTime)
		}
	}
	top := assertArchiveNames(t, archivePath, names)
	assertArchiveModes(t, modes)
	assertArchiveContents(t, top, binaryPath, root, contents)
}

func inspectZip(t *testing.T, archivePath, binaryPath, root string) {
	t.Helper()
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var names []string
	var modes []fs.FileMode
	contents := map[string][]byte{}
	for _, file := range reader.File {
		names = append(names, file.Name)
		modes = append(modes, file.Mode())
		if !file.Modified.Equal(ArchiveTime) {
			t.Errorf("zip entry %s timestamp = %s, want %s", file.Name, file.Modified, ArchiveTime)
		}
		if !file.FileInfo().IsDir() {
			entry, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, readErr := io.ReadAll(entry)
			closeErr := entry.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			contents[file.Name] = data
		}
	}
	top := assertArchiveNames(t, archivePath, names)
	assertArchiveModes(t, modes)
	assertArchiveContents(t, top, binaryPath, root, contents)
}

func assertArchiveModes(t *testing.T, modes []fs.FileMode) {
	t.Helper()
	want := []fs.FileMode{fs.ModeDir | 0o755, 0o755, 0o644, 0o644}
	if len(modes) != len(want) {
		t.Fatalf("archive mode count = %d, want %d", len(modes), len(want))
	}
	for i := range want {
		if got := modes[i]; got != want[i] {
			t.Errorf("archive entry %d mode = %s, want %s", i, got, want[i])
		}
	}
}

func assertArchiveNames(t *testing.T, archivePath string, names []string) string {
	t.Helper()
	if len(names) != 4 {
		t.Fatalf("archive entries = %v, want directory and three files", names)
	}
	if !strings.HasSuffix(names[0], "/") {
		t.Errorf("first archive entry %q is not top-level directory", names[0])
	}
	top := names[0]
	wantTop := strings.TrimSuffix(filepath.Base(archivePath), ".zip")
	wantTop = strings.TrimSuffix(wantTop, ".tar.gz") + "/"
	if top != wantTop {
		t.Errorf("archive top-level directory = %q, want basename %q", top, wantTop)
	}
	wantSuffixes := []string{"", "LICENSE", "README.md"}
	if strings.HasSuffix(names[1], ".exe") {
		wantSuffixes[0] = "inboxgate.exe"
	} else {
		wantSuffixes[0] = "inboxgate"
	}
	for i, suffix := range wantSuffixes {
		if got, want := names[i+1], top+suffix; got != want {
			t.Errorf("archive entry %d = %q, want %q", i+1, got, want)
		}
	}
	return top
}

func assertArchiveContents(t *testing.T, top, binaryPath, root string, contents map[string][]byte) {
	t.Helper()
	binaryName := "inboxgate"
	if strings.HasSuffix(binaryPath, ".exe") {
		binaryName += ".exe"
	}
	for archiveName, sourcePath := range map[string]string{
		top + binaryName:  binaryPath,
		top + "LICENSE":   filepath.Join(root, "LICENSE"),
		top + "README.md": filepath.Join(root, "README.md"),
	} {
		want, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		got, found := contents[archiveName]
		if !found {
			t.Errorf("archive content %q is missing", archiveName)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("archive content %q differs from %s", archiveName, sourcePath)
		}
	}
}
