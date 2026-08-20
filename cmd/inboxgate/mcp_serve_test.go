package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func generatedMCPToken(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		t.Fatal("generate synthetic MCP token")
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	return token
}

func writeMCPConfig(t *testing.T, address string, enabled bool, tokenName string) string {
	t.Helper()
	document := "version: 1\nserver: {listen: '" + address + "'}\nmcp: {enabled: " + map[bool]string{false: "false", true: "true"}[enabled] + ", path: /private-mcp, bearer_token_env: " + tokenName + "}\nlogging: {level: info, format: json}\n"
	path := filepath.Join(t.TempDir(), "mcp-config.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOnlyEnabledServeResolvesSelectedMCPToken(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().String()

	originalLookup := lookupMCPEnvironment
	var lookups atomic.Int64
	var lookedUpName string
	lookupMCPEnvironment = func(name string) (string, bool) {
		lookups.Add(1)
		lookedUpName = name
		return generatedMCPToken(t), true
	}
	t.Cleanup(func() { lookupMCPEnvironment = originalLookup })

	disabledPath := writeMCPConfig(t, address, false, "SYNTHETIC_DISABLED_MCP_TOKEN")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"--config", disabledPath, "serve"}, &stdout, &stderr); exit != 1 {
		t.Fatalf("disabled serve exit = %d", exit)
	}
	if lookups.Load() != 0 || lookedUpName != "" {
		t.Fatalf("disabled serve token lookups = %d", lookups.Load())
	}

	enabledPath := writeMCPConfig(t, address, true, "SYNTHETIC_SELECTED_MCP_TOKEN")
	stdout.Reset()
	stderr.Reset()
	if exit := run([]string{"--config", enabledPath, "serve"}, &stdout, &stderr); exit != 1 {
		t.Fatalf("enabled serve exit = %d", exit)
	}
	if lookups.Load() != 1 || lookedUpName != "SYNTHETIC_SELECTED_MCP_TOKEN" {
		t.Fatalf("enabled serve selected lookup count = %d, name = %q", lookups.Load(), lookedUpName)
	}
	for _, forbidden := range []string{"SYNTHETIC_SELECTED_MCP_TOKEN", "SYNTHETIC_DISABLED_MCP_TOKEN"} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Errorf("serve disclosed environment name %q", forbidden)
		}
	}
}

func TestMCPTokenValidationFailsBeforeBindWithOneDiagnostic(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	path := writeMCPConfig(t, address, true, "SYNTHETIC_MCP_TOKEN")
	valid := generatedMCPToken(t)
	invalid := []struct {
		value string
		set   bool
	}{
		{set: false},
		{value: "", set: true},
		{value: valid[:42], set: true},
		{value: valid + "A", set: true},
		{value: valid + "=", set: true},
		{value: " " + valid, set: true},
		{value: valid + " ", set: true},
		{value: valid[:20] + "\n" + valid[21:], set: true},
	}
	originalLookup := lookupMCPEnvironment
	t.Cleanup(func() { lookupMCPEnvironment = originalLookup })
	for index, test := range invalid {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			lookupMCPEnvironment = func(name string) (string, bool) {
				if name != "SYNTHETIC_MCP_TOKEN" {
					t.Fatal("serve looked up an unselected environment name")
				}
				return test.value, test.set
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exit := run([]string{"--config", path, "serve"}, &stdout, &stderr)
			if exit != 1 || stdout.Len() != 0 || stderr.String() != "cannot construct MCP runtime\n" {
				t.Fatalf("exit = %d, stdout bytes = %d, stderr category = %q", exit, stdout.Len(), stderr.String())
			}
		})
	}
	clear([]byte(valid))
}

func TestNonServeCommandsDoNotResolveMCPToken(t *testing.T) {
	path := writeMCPConfig(t, "127.0.0.1:1", true, "SYNTHETIC_UNUSED_MCP_TOKEN")
	originalLookup := lookupMCPEnvironment
	var lookups atomic.Int64
	lookupMCPEnvironment = func(string) (string, bool) {
		lookups.Add(1)
		return "must-not-be-read", true
	}
	t.Cleanup(func() { lookupMCPEnvironment = originalLookup })
	commands := [][]string{
		{"--config", path, "config", "validate"},
		{"--config", path, "config", "effective"},
		{"--config", path, "capabilities"},
		{"--config", path, "doctor"},
		{"version"},
	}
	for _, args := range commands {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if exit := run(args, &stdout, &stderr); exit != 0 {
			t.Fatalf("command %q exit = %d, stderr = %q", args, exit, stderr.String())
		}
	}
	if lookups.Load() != 0 {
		t.Fatalf("non-serve token lookups = %d", lookups.Load())
	}
}

func TestRealProcessSyntheticLoopbackMCPAndHealth(t *testing.T) {
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
	address := reservation.Addr().String()
	reservation.Close()
	const tokenName = "SYNTHETIC_PROCESS_MCP_TOKEN"
	configPath := writeMCPConfig(t, address, true, tokenName)
	token := generatedMCPToken(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	process := exec.Command(binaryPath, "--config", configPath, "serve")
	process.Stdout = &stdout
	process.Stderr = &stderr
	process.Env = append(os.Environ(), tokenName+"="+token)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.ProcessState == nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	})

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, requestErr := client.Get("http://" + address + "/health/live")
		if requestErr == nil && response.StatusCode == http.StatusOK {
			_ = response.Body.Close()
			break
		}
		if response != nil {
			_ = response.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("synthetic MCP process did not become live")
		}
		time.Sleep(10 * time.Millisecond)
	}

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"system_capabilities","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic-client","version":"1.0.0"}}}}`
	request, err := http.NewRequest(http.MethodPost, "http://"+address+"/private-mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", "system_capabilities")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("synthetic MCP request failed")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 65_537))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("synthetic MCP status = %d, read error = %v", response.StatusCode, err)
	}
	var envelope struct {
		Result struct {
			StructuredContent struct {
				ProtocolVersion string `json:"protocol_version"`
				Capabilities    []any  `json:"capabilities"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(responseBody, &envelope); err != nil || envelope.Result.StructuredContent.ProtocolVersion != "2026-07-28" || len(envelope.Result.StructuredContent.Capabilities) != 10 {
		t.Fatalf("synthetic MCP response contract failed")
	}
	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), token) || strings.Contains(stderr.String(), tokenName) || strings.Contains(stderr.String(), body) {
		t.Fatal("synthetic MCP process output disclosed request or credential data")
	}
	clear([]byte(token))
}
