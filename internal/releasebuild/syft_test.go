package releasebuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireSyftVerifiesBeforeExtractionAndExecution(t *testing.T) {
	t.Parallel()

	archive := syntheticSyftArchive(t, "syft", "#!/bin/sh\nprintf 'Version:       1.51.0\\n'\n")
	digest := sha256.Sum256(archive)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(archive)
	}))
	t.Cleanup(server.Close)
	output := filepath.Join(t.TempDir(), "bin", "syft")

	if err := AcquireSyft(context.Background(), server.Client(), server.URL, hex.EncodeToString(digest[:]), output); err != nil {
		t.Fatalf("AcquireSyft() error = %v", err)
	}
	if info, err := os.Stat(output); err != nil {
		t.Fatalf("stat acquired Syft: %v", err)
	} else if info.Mode().Perm() != 0o755 {
		t.Errorf("acquired Syft mode = %o, want 755", info.Mode().Perm())
	}
}

func TestPinnedSyftArtifact(t *testing.T) {
	t.Parallel()

	if SyftVersion != "1.51.0" {
		t.Errorf("SyftVersion = %q, want 1.51.0", SyftVersion)
	}
	if SyftURL != "https://github.com/anchore/syft/releases/download/v1.51.0/syft_1.51.0_linux_amd64.tar.gz" {
		t.Errorf("SyftURL = %q, want exact official Linux amd64 release URL", SyftURL)
	}
	if SyftSHA256 != "2a2e837a2c8d59ec9af5472ee22d3b04ee463c4e44476ecf993fd1e5ab6ebc7f" {
		t.Errorf("SyftSHA256 = %q, want reviewed official checksum", SyftSHA256)
	}
}

func TestAcquireSyftRejectsDigestMismatch(t *testing.T) {
	t.Parallel()

	marker := filepath.Join(t.TempDir(), "executed")
	archive := syntheticSyftArchive(t, "syft", fmt.Sprintf("#!/bin/sh\ntouch '%s'\nprintf 'Version:       1.51.0\\n'\n", marker))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write(archive)
	}))
	t.Cleanup(server.Close)
	output := filepath.Join(t.TempDir(), "syft")

	err := AcquireSyft(context.Background(), server.Client(), server.URL, strings.Repeat("0", sha256.Size*2), output)
	if err == nil {
		t.Fatal("AcquireSyft() accepted a digest mismatch")
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("unverified output exists: %v", statErr)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("digest-mismatched executable ran before verification: %v", statErr)
	}
}

func TestAcquireSyftRejectsUnsafeOrCorruptArchive(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"path traversal": syntheticSyftArchive(t, "../syft", "unsafe"),
		"corrupt gzip":   []byte("not a gzip archive"),
	}
	for name, archive := range tests {
		name := name
		archive := archive
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			digest := sha256.Sum256(archive)
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				_, _ = response.Write(archive)
			}))
			t.Cleanup(server.Close)
			output := filepath.Join(t.TempDir(), "syft")

			err := AcquireSyft(context.Background(), server.Client(), server.URL, hex.EncodeToString(digest[:]), output)
			if err == nil {
				t.Fatal("AcquireSyft() accepted an unsafe archive")
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Fatalf("unsafe output exists: %v", statErr)
			}
		})
	}
}

func TestAcquireSyftRejectsWrongExecutableVersion(t *testing.T) {
	t.Parallel()

	archive := syntheticSyftArchive(t, "syft", "#!/bin/sh\nprintf 'Version:       1.50.0\\n'\n")
	digest := sha256.Sum256(archive)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write(archive)
	}))
	t.Cleanup(server.Close)
	output := filepath.Join(t.TempDir(), "syft")

	err := AcquireSyft(context.Background(), server.Client(), server.URL, hex.EncodeToString(digest[:]), output)
	if err == nil {
		t.Fatal("AcquireSyft() accepted the wrong executable version")
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("wrong-version output exists: %v", statErr)
	}
}

func syntheticSyftArchive(t *testing.T, name, contents string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	tarWriter := tar.NewWriter(gzipWriter)
	header := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(contents)), Typeflag: tar.TypeReg}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
