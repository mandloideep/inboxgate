//go:build unix

package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadRejectsFIFODeviceAndSocket(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "inboxgate-config-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	fifo := filepath.Join(directory, "config.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	assertNonRegular(t, fifo)
	assertNonRegular(t, "/dev/null")

	socket := filepath.Join(directory, "config.socket")
	listener, err := net.Listen("unix", socket)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox does not permit creating a Unix-domain socket")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	assertNonRegular(t, socket)
}

func assertNonRegular(t *testing.T, path string) {
	t.Helper()
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load(non-regular target) error = %v", err)
	}
}
