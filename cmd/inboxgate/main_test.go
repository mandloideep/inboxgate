package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func TestCapabilitiesCommandProcess(t *testing.T) {
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

	runCommand := func() ([]byte, []byte) {
		t.Helper()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		command := exec.Command(binaryPath, "--config", configPath, "capabilities")
		command.Stdout = &stdout
		command.Stderr = &stderr
		if err := command.Run(); err != nil {
			t.Fatalf("run InboxGate capabilities process: %v; stdout = %q; stderr = %q", err, stdout.String(), stderr.String())
		}
		return stdout.Bytes(), stderr.Bytes()
	}
	first, firstStderr := runCommand()
	second, secondStderr := runCommand()
	want, err := os.ReadFile(filepath.Join(repositoryRoot(t), "testdata", "capabilities-default.json"))
	if err != nil {
		t.Fatalf("read independently reviewed capabilities golden: %v", err)
	}
	if !bytes.Equal(first, want) || !bytes.Equal(second, want) {
		t.Errorf("capabilities process output differs from exact golden:\nfirst:\n%s\nsecond:\n%s\nwant:\n%s", first, second, want)
	}
	if len(firstStderr) != 0 || len(secondStderr) != 0 {
		t.Errorf("capabilities stderr must be empty: first=%q second=%q", firstStderr, secondStderr)
	}
}

func TestCapabilitiesPathPrecedencePrivacyAndSecretBoundary(t *testing.T) {
	directory := t.TempDir()
	flagPath := filepath.Join(directory, "private-flag-path.yaml")
	environmentPath := filepath.Join(directory, "private-environment-path.yaml")
	flagDocument := "version: 1\ngmail: {oauth_client_id_env: FLAG_CLIENT_ID}\n"
	environmentDocument := "version: 1\ngmail: {oauth_client_id_env: ENVIRONMENT_CLIENT_ID}\n"
	if err := os.WriteFile(flagPath, []byte(flagDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(environmentPath, []byte(environmentDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	const secret = "SYNTHETIC_SECRET_VALUE_MUST_NOT_APPEAR"
	t.Setenv("INBOXGATE_CONFIG", environmentPath)
	t.Setenv("FLAG_CLIENT_ID", secret+"FLAG")
	t.Setenv("ENVIRONMENT_CLIENT_ID", secret+"ENVIRONMENT")

	for _, test := range []struct {
		name     string
		args     []string
		wantName string
	}{
		{name: "flag", args: []string{"--config", flagPath, "capabilities"}, wantName: "FLAG_CLIENT_ID"},
		{name: "environment", args: []string{"capabilities"}, wantName: "ENVIRONMENT_CLIENT_ID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(test.args, &stdout, &stderr)
			if exitCode != 0 || stderr.String() != "" || !strings.Contains(stdout.String(), `"`+test.wantName+`"`) {
				t.Fatalf("run() exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
			}
			for _, forbidden := range []string{directory, flagPath, environmentPath, secret} {
				if strings.Contains(stdout.String()+stderr.String(), forbidden) {
					t.Errorf("output disclosed forbidden value %q", forbidden)
				}
			}
		})
	}
}

func TestCapabilitiesCommandDoesNotLookUpYAMLDerivedEnvironmentNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	document := `version: 1
database: {url_env: COMMAND_DATABASE_URL, auth_token_env: COMMAND_DATABASE_TOKEN}
gmail: {oauth_client_id_env: COMMAND_CLIENT_ID, oauth_client_secret_env: COMMAND_CLIENT_SECRET, oauth_redirect_url_env: COMMAND_REDIRECT_URL}
encryption: {master_key_env: COMMAND_MASTER_KEY}
`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{"COMMAND_DATABASE_URL", "COMMAND_DATABASE_TOKEN", "COMMAND_CLIENT_ID", "COMMAND_CLIENT_SECRET", "COMMAND_REDIRECT_URL", "COMMAND_MASTER_KEY"}
	for _, name := range names {
		previous, existed := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		name := name
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, previous)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
	render := func() []byte {
		t.Helper()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exitCode := run([]string{"--config", path, "capabilities"}, &stdout, &stderr); exitCode != 0 || stderr.String() != "" {
			t.Fatalf("capabilities exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
		}
		return append([]byte(nil), stdout.Bytes()...)
	}
	withoutValues := render()
	for index, name := range names {
		if err := os.Setenv(name, fmt.Sprintf("SYNTHETIC_COMMAND_VALUE_%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	withValues := render()
	if !bytes.Equal(withoutValues, withValues) {
		t.Fatalf("command output changed after setting YAML-derived environment names:\nunset:\n%s\nset:\n%s", withoutValues, withValues)
	}
	if strings.Contains(string(withValues), "SYNTHETIC_COMMAND_VALUE") {
		t.Fatalf("command output disclosed a YAML-derived environment value: %s", withValues)
	}
}

func TestCapabilitiesUnreadableRegularFileHasNoPartialOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission enforcement is unavailable")
	}
	path := filepath.Join(t.TempDir(), "private-unreadable.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat unreadable regular file: %v", err)
	}
	if file, err := os.Open(path); err == nil {
		_ = file.Close()
		t.Skip("current user can bypass file permission bits")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config", path, "capabilities"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" || stderr.String() != "configuration invalid: file: cannot open configuration file\n" {
		t.Fatalf("unreadable file exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), path) || strings.Contains(stdout.String()+stderr.String(), filepath.Dir(path)) {
		t.Errorf("unreadable-file diagnostic disclosed path: %q", stderr.String())
	}
}

func TestCapabilitiesHelpAndUsageErrors(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"capabilities", "--help"}, &stdout, &stderr)
	if exitCode != 0 || stderr.String() != "" || !strings.Contains(stdout.String(), "inboxgate [--config PATH] capabilities") || !strings.Contains(stdout.String(), "environment-variable names") || !strings.Contains(stdout.String(), "sensitive") {
		t.Fatalf("help exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}

	for _, args := range [][]string{{"capabilities", "extra"}, {"capabilities", "--config=x"}, {"capabilities", "--json"}} {
		stdout.Reset()
		stderr.Reset()
		exitCode = run(args, &stdout, &stderr)
		if exitCode != 2 || stdout.String() != "" || !strings.Contains(stderr.String(), "capabilities does not accept arguments") || !strings.Contains(stderr.String(), "Usage:") {
			t.Errorf("run(%q) exit = %d, stdout = %q, stderr = %q", args, exitCode, stdout.String(), stderr.String())
		}
	}
}

func TestCapabilitiesInvalidInputHasNoPartialOutput(t *testing.T) {
	directory := t.TempDir()
	invalidPath := filepath.Join(directory, "private-invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte("version: 1\ncapabilities: {gmail.read: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformedPath := filepath.Join(directory, "private-malformed.yaml")
	if err := os.WriteFile(malformedPath, []byte("version: [SYNTHETIC_PRIVATE_VALUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(directory, "private-oversized.yaml")
	oversized := append([]byte("version: 1\n#"), bytes.Repeat([]byte{'x'}, config.MaxFileBytes)...)
	if err := os.WriteFile(oversizedPath, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{invalidPath, malformedPath, oversizedPath, filepath.Join(directory, "private-missing.yaml"), directory} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"--config", path, "capabilities"}, &stdout, &stderr)
		if exitCode != 1 || stdout.String() != "" || !strings.HasPrefix(stderr.String(), "configuration invalid: ") {
			t.Errorf("path %q exit = %d, stdout = %q, stderr = %q", path, exitCode, stdout.String(), stderr.String())
		}
		for _, forbidden := range []string{path, directory, "SYNTHETIC_PRIVATE_VALUE"} {
			if strings.Contains(stdout.String()+stderr.String(), forbidden) {
				t.Errorf("invalid diagnostic disclosed forbidden value %q: %q", forbidden, stderr.String())
			}
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config", invalidPath, "capabilities"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" || stderr.String() != "configuration invalid: capabilities.gmail.read: cannot enable a capability not implemented by this binary\n" {
		t.Errorf("unimplemented diagnostic exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestCapabilitiesWriteFailuresAreGeneric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "valid.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, writer := range []io.Writer{&failingWriter{}, shortWriter{}} {
		var stderr bytes.Buffer
		exitCode := run([]string{"--config", path, "capabilities"}, writer, &stderr)
		if exitCode != 1 || stderr.String() != "cannot write capabilities\n" || strings.Contains(stderr.String(), path) {
			t.Errorf("write failure exit = %d, stderr = %q", exitCode, stderr.String())
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) {
	return len(data) - 1, nil
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

func TestDoctorSuccessIsDeterministicAndDoesNotReadNamedSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doctor.yaml")
	document := `version: 1
database: {url_env: DOCTOR_DATABASE_URL, auth_token_env: DOCTOR_DATABASE_TOKEN}
gmail: {oauth_client_id_env: DOCTOR_CLIENT_ID, oauth_client_secret_env: DOCTOR_CLIENT_SECRET, oauth_redirect_url_env: DOCTOR_REDIRECT_URL}
encryption: {master_key_env: DOCTOR_MASTER_KEY}
logging: {format: text, level: error}
`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	const secret = "SYNTHETIC_DOCTOR_SECRET_MUST_NOT_APPEAR"
	for _, name := range []string{"DOCTOR_DATABASE_URL", "DOCTOR_DATABASE_TOKEN", "DOCTOR_CLIENT_ID", "DOCTOR_CLIENT_SECRET", "DOCTOR_REDIRECT_URL", "DOCTOR_MASTER_KEY"} {
		t.Setenv(name, secret+name)
	}

	want := "{\n  \"output_version\": 1,\n  \"status\": \"ok\",\n  \"checks\": [\n    {\n      \"name\": \"configuration\",\n      \"status\": \"pass\"\n    },\n    {\n      \"name\": \"service_runtime\",\n      \"status\": \"pass\"\n    }\n  ]\n}\n"
	for iteration := 0; iteration < 2; iteration++ {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		exitCode := run([]string{"--config", path, "doctor"}, &stdout, &stderr)
		if exitCode != 0 || stdout.String() != want || stderr.String() != "" {
			t.Fatalf("doctor iteration %d exit = %d, stdout = %q, stderr = %q", iteration, exitCode, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), secret) || strings.Contains(stdout.String()+stderr.String(), path) {
			t.Errorf("doctor disclosed sensitive input")
		}
	}
}

func TestDoctorInvalidConfigurationAndWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-private-config.yaml")
	if err := os.WriteFile(path, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := run([]string{"--config", path, "doctor"}, &stdout, &stderr); exitCode != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), "configuration invalid: version") || strings.Contains(stderr.String(), path) {
		t.Fatalf("invalid doctor exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}

	validPath := filepath.Join(t.TempDir(), "valid.yaml")
	if err := os.WriteFile(validPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := &failingWriter{}
	stderr.Reset()
	if exitCode := run([]string{"--config", validPath, "doctor"}, writer, &stderr); exitCode != 1 || writer.attempts != 1 || stderr.String() != "cannot write doctor result\n" {
		t.Errorf("doctor write failure exit = %d, attempts = %d, stderr = %q", exitCode, writer.attempts, stderr.String())
	}
}

func TestServeAndDoctorHelpAndMisuse(t *testing.T) {
	for _, command := range []string{"serve", "doctor"} {
		t.Run(command+" help", func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run([]string{"--config", "/path/that/must/not/be/loaded", command, "--help"}, &stdout, &stderr)
			if exitCode != 0 || stderr.String() != "" || !strings.Contains(stdout.String(), "inboxgate [--config PATH] "+command) {
				t.Fatalf("help exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
			}
		})
		for _, arguments := range [][]string{{command, "extra"}, {command, "--local-flag"}} {
			t.Run(strings.Join(arguments, " "), func(t *testing.T) {
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				exitCode := run(append([]string{"--config", "/path/that/must/not/be/loaded"}, arguments...), &stdout, &stderr)
				if exitCode != 2 || stdout.String() != "" || !strings.Contains(stderr.String(), command+" does not accept arguments") || !strings.Contains(stderr.String(), "Usage:") {
					t.Fatalf("misuse exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
				}
			})
		}
	}
}

func TestServeInvalidConfigurationStartsNoListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nserver: {listen: '127.0.0.1:1'}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := run([]string{"--config", path, "serve"}, &stdout, &stderr)
	if exitCode != 1 || stdout.String() != "" || !strings.Contains(stderr.String(), "configuration invalid: version") {
		t.Fatalf("serve invalid exit = %d, stdout = %q, stderr = %q", exitCode, stdout.String(), stderr.String())
	}
}

func TestServeAndDoctorHelpMisuseAndInvalidConfigurationProcesses(t *testing.T) {
	directory := t.TempDir()
	binaryName := "inboxgate"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(directory, binaryName)
	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build InboxGate binary: %v\n%s", err, output)
	}
	privateMissingPath := filepath.Join(directory, "private-missing-config.yaml")
	invalidPath := filepath.Join(directory, "private-invalid-config.yaml")
	if err := os.WriteFile(invalidPath, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	commands := []struct {
		name string
		help string
	}{
		{
			name: "serve",
			help: "Usage:\n  inboxgate [--config PATH] serve\n\nRuns bounded liveness and process-readiness endpoints until SIGINT or SIGTERM.\nBind only to an approved private interface or private reverse-proxy path.\n",
		},
		{
			name: "doctor",
			help: "Usage:\n  inboxgate [--config PATH] doctor\n\nValidates configuration and local service construction without binding a listener.\n",
		},
	}
	for _, command := range commands {
		t.Run(command.name+" help", func(t *testing.T) {
			exitCode, stdout, stderr := runBuiltProcess(t, binaryPath, "--config", privateMissingPath, command.name, "--help")
			if exitCode != 0 || stdout != command.help || stderr != "" {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", exitCode, stdout, stderr)
			}
		})
		t.Run(command.name+" misuse", func(t *testing.T) {
			exitCode, stdout, stderr := runBuiltProcess(t, binaryPath, "--config", privateMissingPath, command.name, "--unsupported")
			wantStderr := command.name + " does not accept arguments\n\n" + command.help
			if exitCode != 2 || stdout != "" || stderr != wantStderr {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", exitCode, stdout, stderr)
			}
		})
		t.Run(command.name+" invalid configuration", func(t *testing.T) {
			exitCode, stdout, stderr := runBuiltProcess(t, binaryPath, "--config", invalidPath, command.name)
			if exitCode != 1 || stdout != "" || stderr != "configuration invalid: version: unsupported schema version\n" {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", exitCode, stdout, stderr)
			}
			for _, forbidden := range []string{directory, invalidPath, privateMissingPath, "server_started", "listen_failed"} {
				if strings.Contains(stderr, forbidden) {
					t.Errorf("invalid configuration diagnostic contains %q: %q", forbidden, stderr)
				}
			}
		})
	}
}

func TestServeAndDoctorCommandProcesses(t *testing.T) {
	directory := t.TempDir()
	binaryName := "inboxgate"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(directory, binaryName)
	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build InboxGate binary: %v\n%s", err, output)
	}

	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reservation.Close() })
	address := reservation.Addr().String()
	configPath := filepath.Join(directory, "synthetic-process-config.yaml")
	document := "version: 1\nserver: {listen: '" + address + "'}\nlogging: {level: info, format: json}\n"
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}

	var doctorStdout bytes.Buffer
	var doctorStderr bytes.Buffer
	doctor := exec.Command(binaryPath, "--config", configPath, "doctor")
	doctor.Stdout = &doctorStdout
	doctor.Stderr = &doctorStderr
	if err := doctor.Run(); err != nil {
		t.Fatalf("run doctor process: %v; stdout = %q; stderr = %q", err, doctorStdout.String(), doctorStderr.String())
	}
	if !bytes.Equal(doctorStdout.Bytes(), doctorResult) || doctorStderr.Len() != 0 {
		t.Fatalf("doctor process stdout = %q, stderr = %q", doctorStdout.String(), doctorStderr.String())
	}
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS == "windows" {
		t.Skip("portable signal delivery is unavailable on Windows")
	}
	var serveStdout bytes.Buffer
	var serveStderr bytes.Buffer
	serve := exec.Command(binaryPath, "--config", configPath, "serve")
	serve.Stdout = &serveStdout
	serve.Stderr = &serveStderr
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	processExited := false
	t.Cleanup(func() {
		if !processExited {
			_ = serve.Process.Kill()
			_ = serve.Wait()
		}
	})

	client := &http.Client{
		Timeout: 200 * time.Millisecond,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()
	for _, probe := range []struct {
		path string
		body string
	}{
		{path: "/health/live", body: "{\"status\":\"live\"}\n"},
		{path: "/health/ready", body: "{\"status\":\"ready\"}\n"},
	} {
		deadline := time.Now().Add(3 * time.Second)
		for {
			response, requestErr := client.Get("http://" + address + probe.path)
			if requestErr == nil {
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if response.StatusCode != http.StatusOK || string(body) != probe.body {
					t.Fatalf("probe %s status = %d, body = %q", probe.path, response.StatusCode, body)
				}
				for name, want := range map[string]string{
					"Content-Type":           "application/json; charset=utf-8",
					"Cache-Control":          "no-store",
					"X-Content-Type-Options": "nosniff",
					"Content-Length":         fmt.Sprint(len(probe.body)),
				} {
					if got := response.Header.Get(name); got != want {
						t.Errorf("probe %s header %s = %q, want %q", probe.path, name, got, want)
					}
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("probe %s did not become available: %v; stderr = %q", probe.path, requestErr, serveStderr.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	encodedResponse, err := client.Get("http://" + address + "/health%2Flive?private=wire-query")
	if err != nil {
		t.Fatal(err)
	}
	encodedBody, err := io.ReadAll(encodedResponse.Body)
	_ = encodedResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if encodedResponse.StatusCode != http.StatusNotFound || string(encodedBody) != "{\"error\":\"not_found\"}\n" {
		t.Errorf("encoded GET status = %d, body = %q", encodedResponse.StatusCode, encodedBody)
	}
	for name, want := range map[string]string{
		"Content-Type":           "application/json; charset=utf-8",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Length":         "22",
	} {
		if got := encodedResponse.Header.Get(name); got != want {
			t.Errorf("encoded GET header %s = %q, want %q", name, got, want)
		}
	}
	encodedHead, err := http.NewRequest(http.MethodHead, "http://"+address+"/%68ealth/live?private=head-query", nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeadResponse, err := client.Do(encodedHead)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeadBody, err := io.ReadAll(encodedHeadResponse.Body)
	_ = encodedHeadResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if encodedHeadResponse.StatusCode != http.StatusNotFound || len(encodedHeadBody) != 0 || encodedHeadResponse.Header.Get("Content-Length") != "22" {
		t.Errorf("encoded HEAD status = %d, body = %q, Content-Length = %q", encodedHeadResponse.StatusCode, encodedHeadBody, encodedHeadResponse.Header.Get("Content-Length"))
	}
	for name, want := range map[string]string{
		"Content-Type":           "application/json; charset=utf-8",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Length":         "22",
	} {
		if got := encodedHeadResponse.Header.Get(name); got != want {
			t.Errorf("encoded HEAD header %s = %q, want %q", name, got, want)
		}
	}
	if err := serve.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- serve.Wait() }()
	select {
	case err := <-wait:
		processExited = true
		if err != nil {
			t.Fatalf("serve process shutdown: %v; stderr = %q", err, serveStderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve process did not stop after SIGINT")
	}
	if serveStdout.Len() != 0 {
		t.Errorf("serve stdout = %q, want empty", serveStdout.String())
	}
	logs := serveStderr.String()
	for _, forbidden := range []string{configPath, directory, address, "127.0.0.1"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("serve logs disclosed %q: %s", forbidden, logs)
		}
	}
	for _, forbidden := range []string{"health%2Flive", "%68ealth", "wire-query", "head-query", "/health/live"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("serve logs disclosed raw encoded path data %q: %s", forbidden, logs)
		}
	}
	for _, event := range []string{"server_started", "health.live", "health.ready", "shutdown_started", "shutdown_completed"} {
		if !strings.Contains(logs, event) {
			t.Errorf("serve logs missing %q: %s", event, logs)
		}
	}
	if !strings.Contains(logs, `"operation":"unmatched","method":"GET","status":404`) || !strings.Contains(logs, `"operation":"unmatched","method":"HEAD","status":404`) {
		t.Errorf("serve logs missing bounded unmatched encoded-path records: %s", logs)
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("serve emitted invalid JSON log: %q", line)
		}
	}
}

func runBuiltProcess(t *testing.T, binaryPath string, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := exec.Command(binaryPath, arguments...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run built process: %v", err)
	}
	return exitError.ExitCode(), stdout.String(), stderr.String()
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
