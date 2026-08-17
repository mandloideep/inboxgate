package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run(version) exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "inboxgate dev\n"; got != want {
		t.Errorf("run(version) stdout = %q, want %q", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("run(version) stderr = %q, want empty", got)
	}
}

func TestVersionCommandProcess(t *testing.T) {
	t.Parallel()

	binaryName := "inboxgate"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)

	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build InboxGate binary: %v\n%s", err, output)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.Command(binaryPath, "version")
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		t.Fatalf("run InboxGate version process: %v; stderr = %q", err, stderr.String())
	}
	if got, want := stdout.String(), "inboxgate dev\n"; got != want {
		t.Errorf("InboxGate version stdout = %q, want %q", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("InboxGate version stderr = %q, want empty", got)
	}
}

func TestHelpCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run(help) exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	for _, expected := range []string{"Usage:", "inboxgate <command>", "version", "help"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("run(help) stdout does not contain %q; stdout = %q", expected, stdout.String())
		}
	}
	if got := stderr.String(); got != "" {
		t.Errorf("run(help) stderr = %q, want empty", got)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"unknown"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("run(unknown) exit code = %d, want 2", exitCode)
	}
	if got := stdout.String(); got != "" {
		t.Errorf("run(unknown) stdout = %q, want empty", got)
	}
	if got := stderr.String(); !strings.Contains(got, "unknown command") || !strings.Contains(got, "Usage:") {
		t.Errorf("run(unknown) stderr = %q, want error and help", got)
	}
}
