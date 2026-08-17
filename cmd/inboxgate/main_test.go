package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/config"
)

func TestConfigValidatePathPrecedenceAndSecretBoundary(t *testing.T) {
	directory := t.TempDir()
	explicitPath := filepath.Join(directory, "explicit.yaml")
	environmentPath := filepath.Join(directory, "environment.yaml")
	if err := os.WriteFile(explicitPath, []byte("version: 1\nencryption: {master_key_env: SYNTHETIC_MASTER_KEY}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(environmentPath, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INBOXGATE_CONFIG", environmentPath)
	t.Setenv("SYNTHETIC_MASTER_KEY", "must-never-be-read-or-printed")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config=" + explicitPath, "config", "validate"}, &stdout, &stderr)
	if exitCode != 0 || stdout.String() != "configuration valid\n" || stderr.String() != "" {
		t.Fatalf("explicit validation exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = run([]string{"config", "validate"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), "configuration invalid: version") {
		t.Fatalf("environment validation exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "must-never-be-read-or-printed") {
		t.Errorf("validation revealed a named secret value: %q", stderr.String())
	}
}

func TestConfigValidateEmptyEnvironmentPathIsInvalid(t *testing.T) {
	t.Setenv("INBOXGATE_CONFIG", " \t")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"config", "validate"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" || stderr.String() != "configuration invalid: INBOXGATE_CONFIG: path must not be empty\n" {
		t.Fatalf("run() exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestConfigValidateDiagnosticsAreStableAndRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	secret := "private-database-token"
	data := "version: 1\nlogging: {format: invalid, level: invalid}\ndatabase: {auth_token_env: " + secret + "}\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config", path, "config", "validate"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" {
		t.Fatalf("run() exit = %d, stdout = %q", exitCode, stdout.String())
	}
	output := stderr.String()
	if strings.Contains(output, secret) {
		t.Errorf("diagnostic contains rejected value: %q", output)
	}
	paths := []string{"database.auth_token_env", "logging.format", "logging.level"}
	previous := -1
	for _, field := range paths {
		index := strings.Index(output, field)
		if index <= previous {
			t.Errorf("diagnostics are not in stable field order: %q", output)
		}
		previous = index
	}
}

func TestConfigValidateUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing flag value", args: []string{"--config"}, want: "requires a path"},
		{name: "empty flag value", args: []string{"--config=", "config", "validate"}, want: "non-empty path"},
		{name: "repeated flag", args: []string{"--config=a", "--config=b", "config", "validate"}, want: "only once"},
		{name: "unknown global flag", args: []string{"--unknown", "config", "validate"}, want: "unknown global flag"},
		{name: "missing subcommand", args: []string{"config"}, want: "requires a subcommand"},
		{name: "unknown subcommand", args: []string{"config", "unknown"}, want: "unknown config subcommand"},
		{name: "positional path", args: []string{"config", "validate", "config.yaml"}, want: "does not accept arguments"},
		{name: "flag after command", args: []string{"config", "validate", "--config=x"}, want: "does not accept arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(test.args, &stdout, &stderr)
			if exitCode != 2 || stdout.String() != "" || !strings.Contains(stderr.String(), test.want) || !strings.Contains(stderr.String(), "Usage:") {
				t.Fatalf("run(%q) exit = %d, stdout = %q, stderr = %q", test.args, exitCode, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConfigValidateHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"config", "validate", "--help"}, &stdout, &stderr)
	if exitCode != 0 || stderr.String() != "" || !strings.Contains(stdout.String(), "inboxgate [--config PATH] config validate") {
		t.Fatalf("run(help) exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestConfigValidateCommandProcess(t *testing.T) {
	binaryName := "inboxgate"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)

	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build InboxGate binary: %v\n%s", err, output)
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	configPath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "config.example.yaml")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.Command(binaryPath, "--config", configPath, "config", "validate")
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		t.Fatalf("run InboxGate config validate process: %v; stdout = %q; stderr = %q", err, stdout.String(), stderr.String())
	}
	if got, want := stdout.String(), "configuration valid\n"; got != want {
		t.Errorf("InboxGate config validate stdout = %q, want %q", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("InboxGate config validate stderr = %q, want empty", got)
	}
}

func TestConfigEffectiveCommandProcess(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "minimal.yaml")
	if err := os.WriteFile(configPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryName := "inboxgate"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(directory, binaryName)

	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build InboxGate binary: %v\n%s", err, output)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.Command(binaryPath, "--config", configPath, "config", "effective")
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		t.Fatalf("run InboxGate config effective process: %v; stdout = %q; stderr = %q", err, stdout.String(), stderr.String())
	}
	want := readEffectiveGolden(t, "config-effective-minimal.json")
	if got := stdout.String(); got != string(want) {
		t.Errorf("InboxGate config effective stdout differs from exact normalized JSON:\n got %s\nwant %s", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("InboxGate config effective stderr = %q, want empty", got)
	}

	examplePath := filepath.Join(repositoryRoot(t), "config.example.yaml")
	stdout.Reset()
	stderr.Reset()
	command = exec.Command(binaryPath, "--config="+examplePath, "config", "effective")
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("run InboxGate config effective with example: %v; stdout = %q; stderr = %q", err, stdout.String(), stderr.String())
	}
	exampleWant := readEffectiveGolden(t, "config-effective-example.json")
	if got := stdout.String(); got != string(exampleWant) || stderr.String() != "" {
		t.Errorf("example process output differs: stdout = %q, stderr = %q", got, stderr.String())
	}
}

func readEffectiveGolden(t *testing.T, name string) []byte {
	t.Helper()
	// Golden changes alter the public byte contract and must be inspected rather than regenerated by this test.
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "testdata", name))
	if err != nil {
		t.Fatalf("read independently reviewed effective-output golden %s: %v", name, err)
	}
	return data
}

func TestConfigEffectivePathPrecedencePrivacyAndSecretBoundary(t *testing.T) {
	directory := t.TempDir()
	flagPath := filepath.Join(directory, "private-user-flag-path.yaml")
	environmentPath := filepath.Join(directory, "private-user-environment-path.yaml")
	document := "version: 1\nencryption: {master_key_env: SYNTHETIC_MASTER_KEY}\n"
	for _, path := range []string{flagPath, environmentPath} {
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "SYNTHETIC_SECRET_MUST_NOT_APPEAR"
	t.Setenv("INBOXGATE_CONFIG", environmentPath)
	t.Setenv("SYNTHETIC_MASTER_KEY", secret)

	for _, test := range []struct {
		name       string
		args       []string
		wantSource string
		forbidden  string
	}{
		{name: "flag", args: []string{"--config", flagPath, "config", "effective"}, wantSource: "flag", forbidden: flagPath},
		{name: "environment", args: []string{"config", "effective"}, wantSource: "environment", forbidden: environmentPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(test.args, &stdout, &stderr)
			if exitCode != 0 || stderr.String() != "" {
				t.Fatalf("run() exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), `"path_source": "`+test.wantSource+`"`) {
				t.Errorf("output does not identify %s source: %s", test.wantSource, stdout.String())
			}
			for _, forbidden := range []string{test.forbidden, directory, secret} {
				if strings.Contains(stdout.String()+stderr.String(), forbidden) {
					t.Errorf("output disclosed forbidden value %q", forbidden)
				}
			}
		})
	}

	t.Setenv("INBOXGATE_CONFIG", environmentPath)
	selection, selectionError := selectConfig("", false)
	if selectionError != "" || selection.path != environmentPath || selection.source != "environment" {
		t.Errorf("environment selection = %#v, %q", selection, selectionError)
	}
	if err := os.Unsetenv("INBOXGATE_CONFIG"); err != nil {
		t.Fatal(err)
	}
	selection, selectionError = selectConfig("", false)
	if selectionError != "" || selection.path != "/etc/inboxgate/config.yaml" || selection.source != "default" {
		t.Errorf("default selection = %#v, %q", selection, selectionError)
	}
}

func TestConfigEffectiveHelpAndUsageErrors(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"config", "effective", "--help"}, &stdout, &stderr)
	if exitCode != 0 || stderr.String() != "" || !strings.Contains(stdout.String(), "inboxgate [--config PATH] config effective") || !strings.Contains(stdout.String(), "policy") || !strings.Contains(stdout.String(), "sensitive") {
		t.Fatalf("effective help exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "positional path", args: []string{"config", "effective", "config.yaml"}, want: "does not accept arguments"},
		{name: "flag after command", args: []string{"config", "effective", "--config=x"}, want: "does not accept arguments"},
		{name: "unknown flag after command", args: []string{"config", "effective", "--json"}, want: "does not accept arguments"},
		{name: "extra argument", args: []string{"config", "effective", "extra"}, want: "does not accept arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			exitCode := run(test.args, &stdout, &stderr)
			if exitCode != 2 || stdout.String() != "" || !strings.Contains(stderr.String(), test.want) || !strings.Contains(stderr.String(), "Usage:") {
				t.Fatalf("run(%q) exit = %d, stdout = %q, stderr = %q", test.args, exitCode, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConfigEffectiveInvalidInputHasNoPartialOutput(t *testing.T) {
	directory := t.TempDir()
	invalidPath := filepath.Join(directory, "invalid.yaml")
	secret := "private-invalid-environment-name"
	if err := os.WriteFile(invalidPath, []byte("version: 1\nencryption: {master_key_env: "+secret+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformedPath := filepath.Join(directory, "malformed.yaml")
	if err := os.WriteFile(malformedPath, []byte("version: [private-malformed-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(directory, "oversized.yaml")
	oversized := append([]byte("version: 1\n#"), bytes.Repeat([]byte{'x'}, config.MaxFileBytes)...)
	if err := os.WriteFile(oversizedPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{invalidPath, malformedPath, oversizedPath, filepath.Join(directory, "missing.yaml"), directory} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"--config", path, "config", "effective"}, &stdout, &stderr)
		if exitCode != 1 || stdout.String() != "" || !strings.HasPrefix(stderr.String(), "configuration invalid: ") {
			t.Errorf("path %q exit = %d, stdout = %q, stderr = %q", path, exitCode, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), path) {
			t.Errorf("invalid diagnostic disclosed value or path: %q", stderr.String())
		}
	}

	t.Setenv("INBOXGATE_CONFIG", " \t")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := run([]string{"config", "effective"}, &stdout, &stderr); exitCode != 1 || stdout.String() != "" || stderr.String() != "configuration invalid: INBOXGATE_CONFIG: path must not be empty\n" {
		t.Errorf("empty environment path exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestConfigEffectiveRejectsExplicitEmptyStringWithoutOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-string.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nlogging: {level: ''}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config", path, "config", "effective"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), "configuration invalid: logging.level") {
		t.Errorf("explicit empty string exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestConfigEffectiveWriteFailureIsGeneric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "valid.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &failingWriter{}
	var stderr bytes.Buffer
	exitCode := run([]string{"--config", path, "config", "effective"}, writer, &stderr)
	if exitCode != 1 || writer.attempts != 1 || stderr.String() != "cannot write effective configuration\n" {
		t.Errorf("write failure exit = %d, attempts = %d, stderr = %q", exitCode, writer.attempts, stderr.String())
	}
}

type failingWriter struct {
	attempts int
}

func (writer *failingWriter) Write([]byte) (int, error) {
	writer.attempts++
	return 0, errors.New("synthetic write failure with private details")
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
}

func TestVersionCommand(t *testing.T) {
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

func TestReleaseVersionCommand(t *testing.T) {
	originalVersion := version
	originalCommit := commit
	t.Cleanup(func() {
		version = originalVersion
		commit = originalCommit
	})
	version = "v0.1.0"
	commit = "0123456789abcdef0123456789abcdef01234567"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run(version) exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "inboxgate v0.1.0 (0123456789abcdef0123456789abcdef01234567)\n"; got != want {
		t.Errorf("run(version) stdout = %q, want %q", got, want)
	}
	if got := stderr.String(); got != "" {
		t.Errorf("run(version) stderr = %q, want empty", got)
	}
}

func TestVersionCommandRejectsIncompleteReleaseMetadata(t *testing.T) {
	originalVersion := version
	originalCommit := commit
	t.Cleanup(func() {
		version = originalVersion
		commit = originalCommit
	})
	version = "v0.1.0"
	commit = ""

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"version"}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("run(version) exit code = %d, want 1", exitCode)
	}
	if got := stdout.String(); got != "" {
		t.Errorf("run(version) stdout = %q, want empty", got)
	}
	if got := stderr.String(); !strings.Contains(got, "invalid release metadata") {
		t.Errorf("run(version) stderr = %q, want invalid release metadata error", got)
	}
}

func TestVersionCommandProcess(t *testing.T) {
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
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run(help) exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	for _, expected := range []string{"Usage:", "inboxgate [--config PATH] <command>", "config", "version", "help"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("run(help) stdout does not contain %q; stdout = %q", expected, stdout.String())
		}
	}
	if got := stderr.String(); got != "" {
		t.Errorf("run(help) stderr = %q, want empty", got)
	}
}

func TestUnknownCommand(t *testing.T) {
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
