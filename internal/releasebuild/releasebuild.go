// Package releasebuild creates and validates deterministic InboxGate release artifacts.
package releasebuild

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mandloideep/inboxgate/internal/buildmeta"
)

const modulePath = "github.com/mandloideep/inboxgate"
const goVersion = "go1.26.6"
const jsonschemaModulePath = "github.com/google/jsonschema-go"
const jsonschemaModuleVersion = "v0.4.3"
const jsonschemaModuleSum = "h1:/DBOLZTfDow7pe2GmaJNhltueGTtDKICi8V8p+DQPd0="
const mcpModulePath = "github.com/modelcontextprotocol/go-sdk"
const mcpModuleVersion = "v1.7.0"
const mcpModuleSum = "h1:yqjY2dsbKAC0LSuWZVBMrHgiG8ukXv6NRo0JiALay44="
const segmentioASMModulePath = "github.com/segmentio/asm"
const segmentioASMModuleVersion = "v1.1.3"
const segmentioASMModuleSum = "h1:WM03sfUOENvvKexOLp+pCqgb/WDjsi7EK8gIsICtzhc="
const segmentioEncodingModulePath = "github.com/segmentio/encoding"
const segmentioEncodingModuleVersion = "v0.5.4"
const segmentioEncodingModuleSum = "h1:OW1VRern8Nw6ITAtwSZ7Idrl3MXCFwXHPgqESYfvNt0="
const uriTemplateModulePath = "github.com/yosida95/uritemplate/v3"
const uriTemplateModuleVersion = "v3.0.2"
const uriTemplateModuleSum = "h1:Ed3Oyj9yrmi9087+NczuL5BwkIc4wvTb5zIM+UJPGz4="
const yamlModulePath = "go.yaml.in/yaml/v3"
const yamlModuleVersion = "v3.0.5"
const yamlModuleSum = "h1:N6y/pJk8buWs9NY5ERU2HSMfm+IuD/OtfdAnq6kESPw="
const oauthModulePath = "golang.org/x/oauth2"
const oauthModuleVersion = "v0.36.0"
const oauthModuleSum = "h1:peZ/1z27fi9hUOFCAZaHyrpWG5lwe0RJEEEeH0ThlIs="
const syncModulePath = "golang.org/x/sync"
const syncModuleVersion = "v0.20.0"
const syncModuleSum = "h1:e0PTpb7pjO8GAtTs2dQ6jYa5BWYlMuX047Dco/pItO4="
const sysModulePath = "golang.org/x/sys"
const sysModuleVersion = "v0.41.0"
const sysModuleSum = "h1:Ivj+2Cp/ylzLiEU89QhWblYnOE9zerudt9Ftecq2C6k="
const timeModulePath = "golang.org/x/time"
const timeModuleVersion = "v0.15.0"
const timeModuleSum = "h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U="
const tursoModulePath = "turso.tech/database/tursogo-serverless"
const tursoModuleVersion = "v0.0.0-20260817122138-24adc316cdc4"
const tursoModuleSum = "h1:Fnxwfn492a+9kTegF2G7QUT1aF0Vfjz0dMrNO+HmthA="

// ArchiveTime is the fixed timestamp stored in every release archive.
// The ZIP format cannot represent dates before 1980.
var ArchiveTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// Target is a supported release platform.
type Target struct {
	GOOS   string
	GOARCH string
}

// Targets is the complete, stable platform matrix.
var Targets = []Target{
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
	{GOOS: "windows", GOARCH: "amd64"},
	{GOOS: "windows", GOARCH: "arm64"},
}

// BuildOptions describes one isolated release build.
type BuildOptions struct {
	Root    string
	Output  string
	Version string
	Commit  string
}

// Binary is one uncompressed platform executable.
type Binary struct {
	Path   string
	GOOS   string
	GOARCH string
}

// Result lists deterministic outputs from one release build.
type Result struct {
	Archives []string
	Binaries []Binary
}

// ValidateMetadata validates release workflow inputs without interpreting them as shell source.
func ValidateMetadata(version, commit string) error {
	return buildmeta.ValidateRelease(version, commit)
}

// BuildBinaries cross-compiles and validates every supported target without creating archives.
func BuildBinaries(options BuildOptions) (Result, error) {
	if err := ValidateMetadata(options.Version, options.Commit); err != nil {
		return Result{}, fmt.Errorf("validate release metadata: %w", err)
	}
	if options.Root == "" || options.Output == "" {
		return Result{}, errors.New("root and output directories are required")
	}
	root, err := filepath.Abs(options.Root)
	if err != nil {
		return Result{}, fmt.Errorf("resolve repository root: %w", err)
	}
	output, err := filepath.Abs(options.Output)
	if err != nil {
		return Result{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if _, err := os.Lstat(output); err == nil {
		return Result{}, fmt.Errorf("output directory %q already exists", output)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Result{}, fmt.Errorf("inspect output directory: %w", err)
	}
	binariesDir := filepath.Join(output, "binaries")
	if err := os.MkdirAll(binariesDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create binaries directory: %w", err)
	}

	versionNumber := strings.TrimPrefix(options.Version, "v")
	result := Result{}
	for _, target := range Targets {
		base := fmt.Sprintf("inboxgate_%s_%s_%s", versionNumber, target.GOOS, target.GOARCH)
		binaryName := "inboxgate"
		if target.GOOS == "windows" {
			binaryName += ".exe"
		}
		binaryPath := filepath.Join(binariesDir, base, binaryName)
		if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
			return Result{}, fmt.Errorf("create binary directory: %w", err)
		}
		if err := buildBinary(root, binaryPath, target, options.Version, options.Commit); err != nil {
			return Result{}, err
		}
		if err := ValidateBinary(binaryPath, target.GOOS, target.GOARCH); err != nil {
			return Result{}, fmt.Errorf("validate %s/%s binary: %w", target.GOOS, target.GOARCH, err)
		}
		result.Binaries = append(result.Binaries, Binary{Path: binaryPath, GOOS: target.GOOS, GOARCH: target.GOARCH})
	}
	return result, nil
}

// Package creates deterministic archives from a complete, already validated binary set.
func Package(options BuildOptions, binaries []Binary) ([]string, error) {
	if err := ValidateMetadata(options.Version, options.Commit); err != nil {
		return nil, fmt.Errorf("validate release metadata: %w", err)
	}
	root, err := filepath.Abs(options.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	output, err := filepath.Abs(options.Output)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	if len(binaries) != len(Targets) {
		return nil, fmt.Errorf("binary count = %d, want %d", len(binaries), len(Targets))
	}
	assetsDir := filepath.Join(output, "assets")
	if err := os.Mkdir(assetsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create new assets directory: %w", err)
	}
	binaryByTarget := make(map[string]Binary, len(binaries))
	for _, binary := range binaries {
		key := binary.GOOS + "/" + binary.GOARCH
		if _, exists := binaryByTarget[key]; exists {
			return nil, fmt.Errorf("duplicate binary target %s", key)
		}
		binaryByTarget[key] = binary
	}
	versionNumber := strings.TrimPrefix(options.Version, "v")
	archives := make([]string, 0, len(Targets))
	for _, target := range Targets {
		key := target.GOOS + "/" + target.GOARCH
		binary, found := binaryByTarget[key]
		if !found {
			return nil, fmt.Errorf("missing binary target %s", key)
		}
		if err := ValidateBinary(binary.Path, target.GOOS, target.GOARCH); err != nil {
			return nil, fmt.Errorf("validate %s binary before packaging: %w", key, err)
		}
		base := fmt.Sprintf("inboxgate_%s_%s_%s", versionNumber, target.GOOS, target.GOARCH)
		binaryName := "inboxgate"
		if target.GOOS == "windows" {
			binaryName += ".exe"
		}
		extension := ".tar.gz"
		if target.GOOS == "windows" {
			extension = ".zip"
		}
		archivePath := filepath.Join(assetsDir, base+extension)
		entries := []archiveEntry{
			{Name: binaryName, Path: binary.Path, Mode: 0o755},
			{Name: "LICENSE", Path: filepath.Join(root, "LICENSE"), Mode: 0o644},
			{Name: "README.md", Path: filepath.Join(root, "README.md"), Mode: 0o644},
			{Name: "THIRD_PARTY_NOTICES.md", Path: filepath.Join(root, "THIRD_PARTY_NOTICES.md"), Mode: 0o644},
		}
		if err := writeArchive(archivePath, base, entries); err != nil {
			return nil, fmt.Errorf("write %s: %w", filepath.Base(archivePath), err)
		}
		archives = append(archives, archivePath)
	}
	return archives, nil
}

func buildBinary(root, output string, target Target, version, commit string) error {
	linkerFlags := fmt.Sprintf("-buildid= -X main.version=%s -X main.commit=%s", version, commit)
	command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags="+linkerFlags, "-o", output, "./cmd/inboxgate")
	command.Dir = root
	command.Env = append(filteredEnvironment(os.Environ(), "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS"),
		"GOOS="+target.GOOS,
		"GOARCH="+target.GOARCH,
		"CGO_ENABLED=0",
		"GOFLAGS=-mod=readonly",
	)
	combined, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build %s/%s: %w: %s", target.GOOS, target.GOARCH, err, strings.TrimSpace(string(combined)))
	}
	return nil
}

func filteredEnvironment(environment []string, names ...string) []string {
	blocked := make(map[string]struct{}, len(names))
	for _, name := range names {
		blocked[name] = struct{}{}
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if _, found := blocked[name]; !found {
			result = append(result, entry)
		}
	}
	return result
}

// ValidateBinary checks the Go build information embedded in one platform binary.
func ValidateBinary(path, goos, goarch string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Go build information: %w", err)
	}
	if info.Path != modulePath+"/cmd/inboxgate" {
		return fmt.Errorf("module command path = %q, want %q", info.Path, modulePath+"/cmd/inboxgate")
	}
	if info.GoVersion != goVersion {
		return fmt.Errorf("Go version = %q, want %q", info.GoVersion, goVersion)
	}
	expectedDependencies := map[string]struct{ version, sum string }{
		jsonschemaModulePath:        {jsonschemaModuleVersion, jsonschemaModuleSum},
		mcpModulePath:               {mcpModuleVersion, mcpModuleSum},
		segmentioASMModulePath:      {segmentioASMModuleVersion, segmentioASMModuleSum},
		segmentioEncodingModulePath: {segmentioEncodingModuleVersion, segmentioEncodingModuleSum},
		uriTemplateModulePath:       {uriTemplateModuleVersion, uriTemplateModuleSum},
		yamlModulePath:              {yamlModuleVersion, yamlModuleSum},
		oauthModulePath:             {oauthModuleVersion, oauthModuleSum},
		syncModulePath:              {syncModuleVersion, syncModuleSum},
		sysModulePath:               {sysModuleVersion, sysModuleSum},
		timeModulePath:              {timeModuleVersion, timeModuleSum},
		tursoModulePath:             {tursoModuleVersion, tursoModuleSum},
	}
	if len(info.Deps) != len(expectedDependencies) {
		return fmt.Errorf("release binary has %d module dependencies, want %d", len(info.Deps), len(expectedDependencies))
	}
	for _, dependency := range info.Deps {
		expected, ok := expectedDependencies[dependency.Path]
		if !ok || dependency.Version != expected.version || dependency.Sum != expected.sum || dependency.Replace != nil {
			return fmt.Errorf("release binary dependency does not match the reviewed module graph")
		}
		delete(expectedDependencies, dependency.Path)
	}
	if len(expectedDependencies) != 0 {
		return fmt.Errorf("release binary is missing a reviewed module dependency")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
		if strings.HasPrefix(setting.Key, "vcs") {
			return fmt.Errorf("automatic VCS metadata %q is present", setting.Key)
		}
	}
	for key, want := range map[string]string{"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"} {
		if got := settings[key]; got != want {
			return fmt.Errorf("build setting %s = %q, want %q", key, got, want)
		}
	}
	buildID := exec.Command("go", "tool", "buildid", path)
	output, err := buildID.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect Go linker build ID: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if strings.TrimSpace(string(output)) != "" {
		return fmt.Errorf("Go linker build ID is present")
	}
	return nil
}

// ValidateNativeVersion executes the linux/amd64 release binary and checks exact metadata output.
func ValidateNativeVersion(binaries []Binary, version, commit string) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("native validation requires linux/amd64, running %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return ValidateHostVersion(binaries, version, commit)
}

// ValidateHostVersion executes the release binary matching the current host.
func ValidateHostVersion(binaries []Binary, version, commit string) error {
	for _, binary := range binaries {
		if binary.GOOS != runtime.GOOS || binary.GOARCH != runtime.GOARCH {
			continue
		}
		output, err := exec.Command(binary.Path, "version").CombinedOutput()
		if err != nil {
			return fmt.Errorf("execute native release binary: %w: %s", err, strings.TrimSpace(string(output)))
		}
		want := fmt.Sprintf("inboxgate %s (%s)\n", version, commit)
		if string(output) != want {
			return fmt.Errorf("native version output = %q, want %q", output, want)
		}
		return nil
	}
	return fmt.Errorf("%s/%s binary was not built", runtime.GOOS, runtime.GOARCH)
}

type archiveEntry struct {
	Name string
	Path string
	Mode fs.FileMode
}

func writeArchive(path, topLevel string, entries []archiveEntry) error {
	if strings.HasSuffix(path, ".zip") {
		return writeZip(path, topLevel, entries)
	}
	return writeTarGz(path, topLevel, entries)
}

func writeTarGz(path, topLevel string, entries []archiveEntry) (returnedErr error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer closeWithError(file, &returnedErr)
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = ArchiveTime
	gzipWriter.Header.OS = 255
	defer closeWithError(gzipWriter, &returnedErr)
	tarWriter := tar.NewWriter(gzipWriter)
	defer closeWithError(tarWriter, &returnedErr)

	if err := tarWriter.WriteHeader(&tar.Header{Name: topLevel + "/", Mode: 0o755, Typeflag: tar.TypeDir, ModTime: ArchiveTime, Format: tar.FormatUSTAR}); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := writeTarEntry(tarWriter, topLevel, entry); err != nil {
			return err
		}
	}
	return nil
}

func writeTarEntry(writer *tar.Writer, topLevel string, entry archiveEntry) error {
	file, err := os.Open(entry.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	header := &tar.Header{
		Name:     topLevel + "/" + entry.Name,
		Mode:     int64(entry.Mode.Perm()),
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
		ModTime:  ArchiveTime,
		Format:   tar.FormatUSTAR,
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(writer, file)
	return err
}

func writeZip(path, topLevel string, entries []archiveEntry) (returnedErr error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer closeWithError(file, &returnedErr)
	writer := zip.NewWriter(file)
	defer closeWithError(writer, &returnedErr)

	directoryHeader := &zip.FileHeader{Name: topLevel + "/", Method: zip.Store}
	directoryHeader.SetMode(0o755 | fs.ModeDir)
	directoryHeader.SetModTime(ArchiveTime)
	if _, err := writer.CreateHeader(directoryHeader); err != nil {
		return err
	}
	for _, entry := range entries {
		data, err := os.ReadFile(entry.Path)
		if err != nil {
			return err
		}
		header := &zip.FileHeader{Name: topLevel + "/" + entry.Name, Method: zip.Deflate}
		header.SetMode(entry.Mode)
		header.SetModTime(ArchiveTime)
		entryWriter, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := entryWriter.Write(data); err != nil {
			return err
		}
	}
	return nil
}

type closer interface {
	Close() error
}

func closeWithError(value closer, returnedErr *error) {
	if err := value.Close(); *returnedErr == nil && err != nil {
		*returnedErr = err
	}
}

// CompareArchives proves that two builds produced the same named archive bytes.
func CompareArchives(first, second []string) error {
	if len(first) != len(second) {
		return fmt.Errorf("archive count differs: %d != %d", len(first), len(second))
	}
	firstByName := map[string]string{}
	for _, path := range first {
		firstByName[filepath.Base(path)] = path
	}
	for _, secondPath := range second {
		name := filepath.Base(secondPath)
		firstPath, found := firstByName[name]
		if !found {
			return fmt.Errorf("archive %q is missing from first build", name)
		}
		firstDigest, firstSize, err := digestFile(firstPath)
		if err != nil {
			return err
		}
		secondDigest, secondSize, err := digestFile(secondPath)
		if err != nil {
			return err
		}
		if firstDigest != secondDigest || firstSize != secondSize {
			return fmt.Errorf("archive %q is not byte-identical", name)
		}
	}
	return nil
}

// WriteChecksums writes sorted GNU-style SHA-256 entries for the supplied files.
func WriteChecksums(path string, files []string) (returnedErr error) {
	type checksumEntry struct {
		name   string
		digest string
	}
	entries := make([]checksumEntry, 0, len(files))
	seen := map[string]struct{}{}
	for _, file := range files {
		name := filepath.Base(file)
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate checksum filename %q", name)
		}
		seen[name] = struct{}{}
		digest, _, err := digestFile(file)
		if err != nil {
			return err
		}
		entries = append(entries, checksumEntry{name: name, digest: digest})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer closeWithError(file, &returnedErr)
	for _, entry := range entries {
		if _, err := fmt.Fprintf(file, "%s  %s\n", entry.digest, entry.name); err != nil {
			return err
		}
	}
	return nil
}

// ValidateChecksums rejects missing, extra, unsorted, or incorrect entries.
func ValidateChecksums(path string, expectedFiles []string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	want := map[string]string{}
	for _, path := range expectedFiles {
		digest, _, err := digestFile(path)
		if err != nil {
			return err
		}
		want[filepath.Base(path)] = digest
	}
	var lines []string
	var names []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			return errors.New("checksum file contains an empty line")
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(lines) != len(want) {
		return fmt.Errorf("checksum entry count = %d, want %d", len(lines), len(want))
	}
	for _, line := range lines {
		digest, name, found := strings.Cut(line, "  ")
		if !found || len(digest) != sha256.Size*2 || filepath.Base(name) != name {
			return fmt.Errorf("invalid GNU checksum entry %q", line)
		}
		names = append(names, name)
		wantDigest, found := want[name]
		if !found {
			return fmt.Errorf("unexpected checksum entry %q", name)
		}
		if digest != wantDigest {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
	}
	if !sort.StringsAreSorted(names) {
		return errors.New("checksum entries are not lexicographically sorted by filename")
	}
	return nil
}

func digestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

type spdxDocument struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	CreationInfo      *creationInfo `json:"creationInfo"`
	Packages          []spdxPackage `json:"packages"`
	Files             []spdxFile    `json:"files"`
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo"`
	SourceInfo       string `json:"sourceInfo"`
	DownloadLocation string `json:"downloadLocation"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	CopyrightText    string `json:"copyrightText"`
	FilesAnalyzed    *bool  `json:"filesAnalyzed"`
}

type spdxFile struct {
	FileName string `json:"fileName"`
}

// ValidateSBOM checks required SPDX fields, product identity, version, and sensitive local paths.
func ValidateSBOM(path, version, workspace string) error {
	if err := ValidateMetadata(version, strings.Repeat("0", 40)); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return errors.New("SBOM is not valid JSON")
	}
	absoluteWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	for _, forbidden := range []string{absoluteWorkspace, filepath.ToSlash(absoluteWorkspace), "file://"} {
		if forbidden != "" && strings.Contains(string(data), forbidden) {
			return fmt.Errorf("SBOM contains forbidden local path marker %q", forbidden)
		}
	}
	var document spdxDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse SPDX document: %w", err)
	}
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense == "" || document.SPDXID == "" {
		return errors.New("SBOM is missing required SPDX 2.3 document fields")
	}
	if !strings.EqualFold(document.Name, "InboxGate") {
		return fmt.Errorf("SBOM name = %q, want InboxGate", document.Name)
	}
	if document.DocumentNamespace == "" || document.CreationInfo == nil || document.CreationInfo.Created == "" || len(document.CreationInfo.Creators) == 0 {
		return errors.New("SBOM is missing namespace or creation information")
	}
	if _, err := time.Parse(time.RFC3339, document.CreationInfo.Created); err != nil {
		return fmt.Errorf("SBOM created timestamp is invalid: %w", err)
	}
	foundSyft := false
	for _, creator := range document.CreationInfo.Creators {
		if creator == "Tool: syft-1.51.0" {
			foundSyft = true
		}
	}
	if !foundSyft {
		return errors.New("SBOM was not generated by Syft v1.51.0")
	}
	if len(document.Packages) == 0 {
		return errors.New("SBOM contains no packages")
	}
	reviewedModules := map[string]string{
		jsonschemaModulePath:        jsonschemaModuleVersion,
		mcpModulePath:               mcpModuleVersion,
		segmentioASMModulePath:      segmentioASMModuleVersion,
		segmentioEncodingModulePath: segmentioEncodingModuleVersion,
		uriTemplateModulePath:       uriTemplateModuleVersion,
		yamlModulePath:              yamlModuleVersion,
		oauthModulePath:             oauthModuleVersion,
		syncModulePath:              syncModuleVersion,
		sysModulePath:               sysModuleVersion,
		timeModulePath:              timeModuleVersion,
		tursoModulePath:             tursoModuleVersion,
	}
	expectedRuntime := make(map[string]string, len(reviewedModules)+2)
	expectedRuntime[modulePath] = "UNKNOWN"
	expectedRuntime["stdlib"] = goVersion
	for name, moduleVersion := range reviewedModules {
		expectedRuntime[name] = moduleVersion
	}
	versionNumber := strings.TrimPrefix(version, "v")
	expectedLocations := make(map[string]struct{}, len(Targets))
	expectedBinaryClassifiers := make(map[string]struct{}, 2)
	wantFiles := make(map[string]struct{}, len(Targets))
	for _, target := range Targets {
		binaryName := "inboxgate"
		if target.GOOS == "windows" {
			binaryName += ".exe"
		}
		fileName := fmt.Sprintf("inboxgate_%s_%s_%s/%s", versionNumber, target.GOOS, target.GOARCH, binaryName)
		location := "/" + fileName
		expectedLocations[location] = struct{}{}
		wantFiles[fileName] = struct{}{}
		if target.GOOS == "windows" {
			expectedBinaryClassifiers[location] = struct{}{}
		}
	}
	const goSourcePrefix = "acquired package info from go module information: "
	const binarySourcePrefix = "acquired package info from the following paths: "
	locationInventory := make(map[string]map[string]int, len(expectedLocations))
	for location := range expectedLocations {
		locationInventory[location] = make(map[string]int, len(expectedRuntime))
	}
	seenSPDXIDs := make(map[string]struct{}, len(document.Packages))
	rootCount := 0
	binaryClassifiers := make(map[string]int, len(expectedBinaryClassifiers))
	for _, pkg := range document.Packages {
		if pkg.Name == "" || pkg.SPDXID == "" || pkg.DownloadLocation == "" || pkg.LicenseConcluded == "" || pkg.LicenseDeclared == "" || pkg.CopyrightText == "" || pkg.FilesAnalyzed == nil {
			return fmt.Errorf("SBOM package %q is missing required SPDX fields", pkg.Name)
		}
		if _, duplicate := seenSPDXIDs[pkg.SPDXID]; duplicate {
			return fmt.Errorf("SBOM contains duplicate package SPDX identifier %q", pkg.SPDXID)
		}
		seenSPDXIDs[pkg.SPDXID] = struct{}{}
		if pkg.Name == "InboxGate" {
			if pkg.VersionInfo != version || pkg.SourceInfo != "" {
				return fmt.Errorf("SBOM document-root package does not match InboxGate version %s", version)
			}
			rootCount++
			continue
		}
		if pkg.Name == "inboxgate" {
			location, found := strings.CutPrefix(pkg.SourceInfo, binarySourcePrefix)
			if !found || pkg.SourceInfo != binarySourcePrefix+location || pkg.VersionInfo != "UNKNOWN" {
				return errors.New("SBOM binary classifier does not match the pinned Syft shape")
			}
			if _, expected := expectedBinaryClassifiers[location]; !expected {
				return fmt.Errorf("SBOM binary classifier has unexpected location %q", location)
			}
			binaryClassifiers[location]++
			continue
		}
		expectedVersion, reviewed := expectedRuntime[pkg.Name]
		if !reviewed {
			return fmt.Errorf("SBOM contains unexpected linked runtime package %q", pkg.Name)
		}
		if pkg.VersionInfo != expectedVersion {
			return fmt.Errorf("SBOM package %q version = %q, want %q", pkg.Name, pkg.VersionInfo, expectedVersion)
		}
		location, found := strings.CutPrefix(pkg.SourceInfo, goSourcePrefix)
		if !found || pkg.SourceInfo != goSourcePrefix+location {
			return fmt.Errorf("SBOM package %q is missing its exact pinned-Syft location", pkg.Name)
		}
		inventory, expected := locationInventory[location]
		if !expected {
			return fmt.Errorf("SBOM package %q has unexpected location %q", pkg.Name, location)
		}
		inventory[pkg.Name]++
	}
	if rootCount != 1 {
		return fmt.Errorf("SBOM document-root package count = %d, want 1", rootCount)
	}
	for location, inventory := range locationInventory {
		if len(inventory) != len(expectedRuntime) {
			return fmt.Errorf("SBOM location %q has %d distinct runtime packages, want %d", location, len(inventory), len(expectedRuntime))
		}
		for name := range expectedRuntime {
			if inventory[name] != 1 {
				return fmt.Errorf("SBOM location %q package %q count = %d, want 1", location, name, inventory[name])
			}
		}
	}
	for location := range expectedBinaryClassifiers {
		if binaryClassifiers[location] != 1 {
			return fmt.Errorf("SBOM binary classifier count at %q = %d, want 1", location, binaryClassifiers[location])
		}
	}
	expectedPackageRows := 1 + len(expectedLocations)*len(expectedRuntime) + len(expectedBinaryClassifiers)
	if len(document.Packages) != expectedPackageRows {
		return fmt.Errorf("SBOM package count = %d, want %d exact pinned-Syft rows", len(document.Packages), expectedPackageRows)
	}
	if len(document.Files) != len(wantFiles) {
		return fmt.Errorf("SBOM file count = %d, want %d release binaries", len(document.Files), len(wantFiles))
	}
	for _, file := range document.Files {
		if _, found := wantFiles[file.FileName]; !found {
			return fmt.Errorf("SBOM contains unexpected file %q", file.FileName)
		}
		delete(wantFiles, file.FileName)
	}
	if len(wantFiles) != 0 {
		return fmt.Errorf("SBOM is missing %d release binaries", len(wantFiles))
	}
	return nil
}
