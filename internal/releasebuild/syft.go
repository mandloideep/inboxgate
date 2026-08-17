package releasebuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

const (
	SyftVersion = "1.51.0"
	SyftURL     = "https://github.com/anchore/syft/releases/download/v1.51.0/syft_1.51.0_linux_amd64.tar.gz"
	SyftSHA256  = "2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f"

	maxSyftArchiveSize = 64 << 20
	maxSyftBinarySize  = 128 << 20
	maxSyftEntries     = 64
)

// AcquireSyft downloads, authenticates, safely extracts, and version-checks Syft.
// No downloaded byte is extracted or executed before the complete archive digest matches.
func AcquireSyft(ctx context.Context, client *http.Client, sourceURL, expectedDigest, output string) error {
	if client == nil {
		return errors.New("HTTP client is required")
	}
	if len(expectedDigest) != sha256.Size*2 || strings.ToLower(expectedDigest) != expectedDigest {
		return errors.New("expected Syft digest must be 64 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(expectedDigest); err != nil {
		return fmt.Errorf("decode expected Syft digest: %w", err)
	}
	if sourceURL == "" || output == "" {
		return errors.New("Syft source URL and output path are required")
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("Syft output %q already exists", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Syft output: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return fmt.Errorf("create Syft request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("download Syft: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download Syft: unexpected HTTP status %s", response.Status)
	}
	if response.ContentLength > maxSyftArchiveSize {
		return fmt.Errorf("Syft archive exceeds %d bytes", maxSyftArchiveSize)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxSyftArchiveSize+1))
	if err != nil {
		return fmt.Errorf("read Syft archive: %w", err)
	}
	if len(archive) > maxSyftArchiveSize {
		return fmt.Errorf("Syft archive exceeds %d bytes", maxSyftArchiveSize)
	}
	digest := sha256.Sum256(archive)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return errors.New("Syft archive SHA-256 does not match the committed digest")
	}

	binary, err := syftBinaryFromArchive(archive)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return fmt.Errorf("create Syft output directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(output), ".syft-verified-*")
	if err != nil {
		return fmt.Errorf("create temporary Syft executable: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(binary); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary Syft executable: %w", err)
	}
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return fmt.Errorf("set Syft executable mode: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary Syft executable: %w", err)
	}
	if err := validateSyftVersion(ctx, temporaryPath); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, output); err != nil {
		return fmt.Errorf("install verified Syft executable without replacement: %w", err)
	}
	return nil
}

func syftBinaryFromArchive(archive []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open Syft gzip archive: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var binary []byte
	entries := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read Syft tar archive: %w", err)
		}
		entries++
		if entries > maxSyftEntries {
			return nil, fmt.Errorf("Syft archive contains more than %d entries", maxSyftEntries)
		}
		cleanName := path.Clean(header.Name)
		if cleanName == "." || path.IsAbs(header.Name) || cleanName != header.Name || strings.HasPrefix(cleanName, "../") {
			return nil, fmt.Errorf("Syft archive contains unsafe path %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeDir:
			continue
		default:
			return nil, fmt.Errorf("Syft archive entry %q has forbidden type %d", header.Name, header.Typeflag)
		}
		if header.Size < 0 || header.Size > maxSyftBinarySize {
			return nil, fmt.Errorf("Syft archive entry %q has unsafe size %d", header.Name, header.Size)
		}
		if cleanName != "syft" {
			continue
		}
		if binary != nil {
			return nil, errors.New("Syft archive contains duplicate executables")
		}
		if header.FileInfo().Mode().Perm()&0o111 == 0 {
			return nil, errors.New("Syft archive executable is not marked executable")
		}
		binary, err = io.ReadAll(io.LimitReader(tarReader, maxSyftBinarySize+1))
		if err != nil {
			return nil, fmt.Errorf("read Syft executable: %w", err)
		}
		if int64(len(binary)) != header.Size {
			return nil, errors.New("Syft archive executable size does not match its header")
		}
	}
	if len(binary) == 0 {
		return nil, errors.New("Syft archive does not contain the root syft executable")
	}
	return binary, nil
}

func validateSyftVersion(ctx context.Context, executable string) error {
	command := exec.CommandContext(ctx, executable, "version")
	command.Env = append(filteredEnvironment(os.Environ(), "SYFT_CHECK_FOR_APP_UPDATE"), "SYFT_CHECK_FOR_APP_UPDATE=false")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("execute authenticated Syft version check: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Version:" {
			if fields[1] != SyftVersion {
				return fmt.Errorf("Syft version = %q, want %q", fields[1], SyftVersion)
			}
			return nil
		}
	}
	return errors.New("Syft version output does not contain an exact version")
}
