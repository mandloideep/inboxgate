package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const syntheticProcessAccountID = "0000000000000000000000000000000a"

func writeOperatorMCPConfig(t *testing.T, address string, mcpEnabled, operatorEnabled bool) string {
	t.Helper()
	document := "version: 1\n" +
		"server: {listen: '" + address + "'}\n" +
		"database: {url_env: SYNTHETIC_OPERATOR_DATABASE_URL, auth_token_env: SYNTHETIC_OPERATOR_DATABASE_TOKEN}\n" +
		"mcp: {enabled: " + map[bool]string{false: "false", true: "true"}[mcpEnabled] + ", path: /private-mcp, bearer_token_env: SYNTHETIC_OPERATOR_MCP_TOKEN, enable_operator_tools: " + map[bool]string{false: "false", true: "true"}[operatorEnabled] + "}\n" +
		"logging: {level: info, format: json}\n"
	path := filepath.Join(t.TempDir(), "operator-mcp-config.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOperatorServeResolvesNoDatabaseWhenEitherGateIsDisabled(t *testing.T) {
	for _, gates := range []struct {
		name          string
		mcp, operator bool
	}{{name: "mcp disabled", mcp: false, operator: true}, {name: "operator disabled", mcp: true, operator: false}} {
		t.Run(gates.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			path := writeOperatorMCPConfig(t, listener.Addr().String(), gates.mcp, gates.operator)
			originalLookup := lookupMCPEnvironment
			lookupMCPEnvironment = func(name string) (string, bool) {
				if name != "SYNTHETIC_OPERATOR_MCP_TOKEN" {
					t.Fatalf("unexpected MCP selector %q", name)
				}
				return generatedMCPToken(t), true
			}
			t.Cleanup(func() { lookupMCPEnvironment = originalLookup })
			t.Setenv("SYNTHETIC_OPERATOR_DATABASE_URL", "")
			t.Setenv("SYNTHETIC_OPERATOR_DATABASE_TOKEN", "must-not-be-read")
			var stdout, stderr bytes.Buffer
			if exit := run([]string{"--config", path, "serve"}, &stdout, &stderr); exit != 1 {
				t.Fatalf("serve exit = %d", exit)
			}
			if strings.Contains(stderr.String(), "cannot construct MCP runtime") || strings.Contains(stdout.String()+stderr.String(), "must-not-be-read") {
				t.Fatalf("disabled gate resolved database: %q", stderr.String())
			}
		})
	}
}

func TestOperatorServeRequiresCredentialFreeLiteralLoopbackStorageBeforeBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	defer listener.Close()
	path := writeOperatorMCPConfig(t, address, true, true)
	originalLookup := lookupMCPEnvironment
	lookupMCPEnvironment = func(string) (string, bool) { return generatedMCPToken(t), true }
	t.Cleanup(func() { lookupMCPEnvironment = originalLookup })

	invalid := []struct {
		url, token string
		setURL     bool
	}{
		{setURL: false},
		{url: "https://db.invalid", setURL: true},
		{url: "http://127.0.0.1:8080", token: "synthetic-token", setURL: true},
		{url: "http://localhost:8080", setURL: true},
		{url: "http://192.0.2.10:8080", setURL: true},
	}
	for index, test := range invalid {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			if test.setURL {
				t.Setenv("SYNTHETIC_OPERATOR_DATABASE_URL", test.url)
			} else {
				_ = os.Unsetenv("SYNTHETIC_OPERATOR_DATABASE_URL")
			}
			if test.token == "" {
				_ = os.Unsetenv("SYNTHETIC_OPERATOR_DATABASE_TOKEN")
			} else {
				t.Setenv("SYNTHETIC_OPERATOR_DATABASE_TOKEN", test.token)
			}
			var stdout, stderr bytes.Buffer
			exit := run([]string{"--config", path, "serve"}, &stdout, &stderr)
			if exit != 1 || stdout.Len() != 0 || stderr.String() != "cannot construct MCP runtime\n" {
				t.Fatalf("invalid storage = exit %d stdout %q stderr %q", exit, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRealProcessCredentialFreeAccountStatusTools(t *testing.T) {
	storageServer := syntheticAccountListServer(t, nil)
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
	configPath := writeOperatorMCPConfig(t, address, true, true)
	token := generatedMCPToken(t)

	var stdout, stderr bytes.Buffer
	process := exec.Command(binaryPath, "--config", configPath, "serve")
	process.Stdout = &stdout
	process.Stderr = &stderr
	process.Env = append(os.Environ(), "SYNTHETIC_OPERATOR_MCP_TOKEN="+token, "SYNTHETIC_OPERATOR_DATABASE_URL="+storageServer.URL)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.ProcessState == nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	})

	waitForProcessHealth(t, address)
	for _, name := range []string{"accounts_list", "mail_sync_status"} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic-client","version":"1.0.0"}}}}`
		request, err := http.NewRequest(http.MethodPost, "http://"+address+"/private-mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("MCP-Protocol-Version", "2026-07-28")
		request.Header.Set("Mcp-Method", "tools/call")
		request.Header.Set("Mcp-Name", name)
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 65_537))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(syntheticProcessAccountID)) {
			t.Fatalf("tool %q status=%d read=%v body=%s", name, response.StatusCode, readErr, responseBody)
		}
		if bytes.Contains(responseBody, []byte("synthetic-provider-subject")) || bytes.Contains(responseBody, []byte("9001")) {
			t.Fatalf("tool %q exposed provider subject or cursor: %s", name, responseBody)
		}
	}
	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), token) || strings.Contains(stderr.String(), syntheticProcessAccountID) || strings.Contains(stderr.String(), storageServer.URL) {
		t.Fatalf("process output disclosed sensitive data: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func waitForProcessHealth(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get("http://" + address + "/health/live")
		if err == nil && response.StatusCode == http.StatusOK {
			_ = response.Body.Close()
			return
		}
		if response != nil {
			_ = response.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("synthetic process did not become live")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func syntheticAccountListServer(t *testing.T, closeBlock <-chan struct{}) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free storage request carried authorization")
		}
		switch request.URL.Path {
		case "/v3/cursor":
			response.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(response)
			_ = encoder.Encode(map[string]any{"baton": "synthetic-baton", "base_url": nil})
			columns := []any{
				map[string]any{"name": "account_id", "decltype": "TEXT"}, map[string]any{"name": "provider", "decltype": "TEXT"},
				map[string]any{"name": "state", "decltype": "TEXT"}, map[string]any{"name": "state_version", "decltype": "INTEGER"},
				map[string]any{"name": "reauthorization_reason", "decltype": "TEXT"}, map[string]any{"name": "revocation_status", "decltype": "TEXT"},
				map[string]any{"name": "cursor_present", "decltype": "INTEGER"}, map[string]any{"name": "credential_present", "decltype": "INTEGER"},
			}
			_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": columns})
			row := []any{textProtocolValue(syntheticProcessAccountID), textProtocolValue("gmail"), textProtocolValue("active"), integerProtocolValue(2), map[string]any{"type": "null"}, textProtocolValue("none"), integerProtocolValue(1), integerProtocolValue(1)}
			_ = encoder.Encode(map[string]any{"type": "row", "row": row})
			_ = encoder.Encode(map[string]any{"type": "step_end", "step": 0, "affected_row_count": 0})
			_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 1, "cols": []any{}})
			_ = encoder.Encode(map[string]any{"type": "step_end", "step": 1})
		case "/v3/pipeline":
			if closeBlock != nil {
				select {
				case <-closeBlock:
				case <-request.Context().Done():
					return
				}
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"baton": nil, "base_url": nil, "results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}}})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func textProtocolValue(value string) map[string]any {
	return map[string]any{"type": "text", "value": value}
}

func integerProtocolValue(value int64) map[string]any {
	return map[string]any{"type": "integer", "value": strconv.FormatInt(value, 10)}
}
