// Command release provides repository-owned release construction and validation.
// It performs no network or GitHub writes.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mandloideep/inboxgate/internal/releasebuild"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "release validation failed: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("a subcommand is required")
	}
	switch args[0] {
	case "acquire-syft":
		return acquireSyft(args[1:])
	case "list-targets":
		if len(args) != 1 {
			return fmt.Errorf("list-targets accepts no arguments")
		}
		return writeTargets(os.Stdout)
	case "validate-metadata":
		values, err := parseCommon(args[1:])
		if err != nil {
			return err
		}
		return releasebuild.ValidateMetadata(values.version, values.commit)
	case "build-binaries":
		return buildBinaries(args[1:])
	case "package":
		return packageArtifacts(args[1:])
	case "compare":
		return compare(args[1:])
	case "validate-native":
		return validateNative(args[1:])
	case "validate-host":
		return validateHost(args[1:])
	case "validate-sbom":
		return validateSBOM(args[1:])
	case "checksums":
		return checksums(args[1:])
	case "validate-assets":
		return validateAssets(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func writeTargets(output io.Writer) error {
	for _, target := range releasebuild.Targets {
		if _, err := fmt.Fprintf(output, "%s/%s\n", target.GOOS, target.GOARCH); err != nil {
			return fmt.Errorf("write release target: %w", err)
		}
	}
	return nil
}

func acquireSyft(args []string) error {
	set := flag.NewFlagSet("acquire-syft", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	output := set.String("output", "", "new path for the verified Syft executable")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *output == "" {
		return fmt.Errorf("output is required and positional arguments are forbidden")
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	return releasebuild.AcquireSyft(context.Background(), client, releasebuild.SyftURL, releasebuild.SyftSHA256, *output)
}

type commonValues struct {
	version string
	commit  string
}

func parseCommon(args []string) (commonValues, error) {
	set := flag.NewFlagSet("metadata", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	values := commonValues{}
	set.StringVar(&values.version, "version", "", "canonical release version")
	set.StringVar(&values.commit, "commit", "", "full release commit SHA")
	if err := set.Parse(args); err != nil {
		return commonValues{}, err
	}
	if set.NArg() != 0 {
		return commonValues{}, fmt.Errorf("unexpected positional arguments")
	}
	return values, nil
}

func buildBinaries(args []string) error {
	set := flag.NewFlagSet("build-binaries", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	root := set.String("root", ".", "repository root")
	output := set.String("output", "", "isolated output directory")
	version := set.String("version", "", "canonical release version")
	commit := set.String("commit", "", "full release commit SHA")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *output == "" {
		return fmt.Errorf("output is required and positional arguments are forbidden")
	}
	_, err := releasebuild.BuildBinaries(releasebuild.BuildOptions{Root: *root, Output: *output, Version: *version, Commit: *commit})
	return err
}

func packageArtifacts(args []string) error {
	set := flag.NewFlagSet("package", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	root := set.String("root", ".", "repository root")
	output := set.String("output", "", "existing build output directory")
	version := set.String("version", "", "canonical release version")
	commit := set.String("commit", "", "full release commit SHA")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *output == "" {
		return fmt.Errorf("output is required and positional arguments are forbidden")
	}
	found, err := binaries(filepath.Join(*output, "binaries"))
	if err != nil {
		return err
	}
	_, err = releasebuild.Package(releasebuild.BuildOptions{Root: *root, Output: *output, Version: *version, Commit: *commit}, found)
	return err
}

func compare(args []string) error {
	set := flag.NewFlagSet("compare", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	first := set.String("first", "", "first build output")
	second := set.String("second", "", "second build output")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *first == "" || *second == "" {
		return fmt.Errorf("first and second are required")
	}
	firstArchives, err := archives(filepath.Join(*first, "assets"))
	if err != nil {
		return err
	}
	secondArchives, err := archives(filepath.Join(*second, "assets"))
	if err != nil {
		return err
	}
	return releasebuild.CompareArchives(firstArchives, secondArchives)
}

func validateNative(args []string) error {
	set := flag.NewFlagSet("validate-native", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	output := set.String("output", "", "build output")
	version := set.String("version", "", "canonical release version")
	commit := set.String("commit", "", "full release commit SHA")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *output == "" {
		return fmt.Errorf("output is required")
	}
	binaries, err := binaries(filepath.Join(*output, "binaries"))
	if err != nil {
		return err
	}
	return releasebuild.ValidateNativeVersion(binaries, *version, *commit)
}

func validateHost(args []string) error {
	set := flag.NewFlagSet("validate-host", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	output := set.String("output", "", "build output")
	version := set.String("version", "", "canonical release version")
	commit := set.String("commit", "", "full release commit SHA")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *output == "" {
		return fmt.Errorf("output is required")
	}
	binaries, err := binaries(filepath.Join(*output, "binaries"))
	if err != nil {
		return err
	}
	return releasebuild.ValidateHostVersion(binaries, *version, *commit)
}

func validateSBOM(args []string) error {
	set := flag.NewFlagSet("validate-sbom", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	path := set.String("path", "", "SPDX JSON path")
	version := set.String("version", "", "canonical release version")
	workspace := set.String("workspace", "", "workspace path forbidden from the SBOM")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *path == "" || *workspace == "" {
		return fmt.Errorf("path and workspace are required")
	}
	return releasebuild.ValidateSBOM(*path, *version, *workspace)
}

func checksums(args []string) error {
	set := flag.NewFlagSet("checksums", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	assetsDir := set.String("assets", "", "release assets directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *assetsDir == "" {
		return fmt.Errorf("assets is required")
	}
	files, err := payloadFiles(*assetsDir)
	if err != nil {
		return err
	}
	path := filepath.Join(*assetsDir, "SHA256SUMS")
	if err := releasebuild.WriteChecksums(path, files); err != nil {
		return err
	}
	return releasebuild.ValidateChecksums(path, files)
}

func validateAssets(args []string) error {
	set := flag.NewFlagSet("validate-assets", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	assetsDir := set.String("assets", "", "release assets directory")
	version := set.String("version", "", "canonical release version")
	workspace := set.String("workspace", "", "workspace path forbidden from the SBOM")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *assetsDir == "" || *workspace == "" {
		return fmt.Errorf("assets and workspace are required")
	}
	return releasebuild.ValidateAssetSet(*assetsDir, *version, *workspace)
}

func archives(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && (strings.HasSuffix(entry.Name(), ".tar.gz") || strings.HasSuffix(entry.Name(), ".zip")) {
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) != 6 {
		return nil, fmt.Errorf("archive count = %d, want 6", len(paths))
	}
	return paths, nil
}

func binaries(directory string) ([]releasebuild.Binary, error) {
	var result []releasebuild.Binary
	for _, target := range releasebuild.Targets {
		pattern := fmt.Sprintf("inboxgate_*_%s_%s", target.GOOS, target.GOARCH)
		matches, err := filepath.Glob(filepath.Join(directory, pattern))
		if err != nil {
			return nil, err
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("binary directory matches for %s/%s = %d, want 1", target.GOOS, target.GOARCH, len(matches))
		}
		name := "inboxgate"
		if target.GOOS == "windows" {
			name += ".exe"
		}
		path := filepath.Join(matches[0], name)
		if err := releasebuild.ValidateBinary(path, target.GOOS, target.GOARCH); err != nil {
			return nil, err
		}
		result = append(result, releasebuild.Binary{Path: path, GOOS: target.GOOS, GOARCH: target.GOARCH})
	}
	return result, nil
}

func payloadFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Name() == "SHA256SUMS" {
			continue
		}
		result = append(result, filepath.Join(directory, entry.Name()))
	}
	sort.Strings(result)
	return result, nil
}
