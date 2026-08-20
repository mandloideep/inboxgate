package main

import (
	"bytes"
	"context"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
	inboxmcp "github.com/mandloideep/inboxgate/internal/mcp"
	"github.com/mandloideep/inboxgate/internal/storage"
)

const syntheticProcessAccountID = "0000000000000000000000000000000a"

func writeOperatorMCPConfig(t *testing.T, address string, mcpEnabled, operatorEnabled bool) string {
	return writeOperatorMCPConfigWithSelectors(t, address, mcpEnabled, operatorEnabled, "SYNTHETIC_OPERATOR_DATABASE_URL", "SYNTHETIC_OPERATOR_DATABASE_TOKEN", "SYNTHETIC_OPERATOR_MCP_TOKEN")
}

func writeOperatorMCPConfigWithSelectors(t *testing.T, address string, mcpEnabled, operatorEnabled bool, databaseURLName, databaseTokenName, mcpTokenName string) string {
	t.Helper()
	document := "version: 1\n" +
		"server: {listen: '" + address + "'}\n" +
		"database: {url_env: " + databaseURLName + ", auth_token_env: " + databaseTokenName + "}\n" +
		"mcp: {enabled: " + map[bool]string{false: "false", true: "true"}[mcpEnabled] + ", path: /private-mcp, bearer_token_env: " + mcpTokenName + ", enable_operator_tools: " + map[bool]string{false: "false", true: "true"}[operatorEnabled] + "}\n" +
		"logging: {level: info, format: json}\n"
	path := filepath.Join(t.TempDir(), "operator-mcp-config.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOperatorDatabaseLookupIsExactAndRequiresBothGatesAndDistinctSelectors(t *testing.T) {
	originalDatabaseLookup := lookupOperatorDatabaseEnvironment
	originalMCPLookup := lookupMCPEnvironment
	t.Cleanup(func() {
		lookupOperatorDatabaseEnvironment = originalDatabaseLookup
		lookupMCPEnvironment = originalMCPLookup
	})
	lookupMCPEnvironment = func(string) (string, bool) { return generatedMCPToken(t), true }

	for _, gates := range []struct {
		name          string
		mcp, operator bool
	}{{name: "mcp disabled", operator: true}, {name: "operator disabled", mcp: true}} {
		t.Run(gates.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var lookups atomic.Int64
			lookupOperatorDatabaseEnvironment = func(string) (string, bool) {
				lookups.Add(1)
				return "must-not-be-read", true
			}
			path := writeOperatorMCPConfig(t, listener.Addr().String(), gates.mcp, gates.operator)
			var stdout, stderr bytes.Buffer
			if exit := run([]string{"--config", path, "serve"}, &stdout, &stderr); exit != 1 || lookups.Load() != 0 || strings.Contains(stdout.String()+stderr.String(), "must-not-be-read") {
				t.Fatalf("disabled gates exit=%d lookups=%d stdout=%q stderr=%q", exit, lookups.Load(), stdout.String(), stderr.String())
			}
		})
	}

	server := syntheticAccountListServer(t, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	counts := map[string]int{}
	lookupOperatorDatabaseEnvironment = func(name string) (string, bool) {
		counts[name]++
		if name == "SYNTHETIC_OPERATOR_DATABASE_URL" {
			return server.URL, true
		}
		if name == "SYNTHETIC_OPERATOR_DATABASE_TOKEN" {
			return "", false
		}
		t.Fatalf("unexpected database selector %q", name)
		return "", false
	}
	path := writeOperatorMCPConfig(t, listener.Addr().String(), true, true)
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--config", path, "serve"}, &stdout, &stderr); exit != 1 || counts["SYNTHETIC_OPERATOR_DATABASE_URL"] != 1 || counts["SYNTHETIC_OPERATOR_DATABASE_TOKEN"] != 1 || strings.Contains(stdout.String()+stderr.String(), server.URL) {
		t.Fatalf("enabled gates exit=%d counts=%v stdout=%q stderr=%q", exit, counts, stdout.String(), stderr.String())
	}

	for _, aliases := range []struct {
		name                           string
		databaseURL, dbToken, mcpToken string
	}{
		{name: "database pair", databaseURL: "SHARED", dbToken: "SHARED", mcpToken: "MCP_TOKEN"},
		{name: "url and mcp", databaseURL: "SHARED", dbToken: "DB_TOKEN", mcpToken: "SHARED"},
		{name: "token and mcp", databaseURL: "DB_URL", dbToken: "SHARED", mcpToken: "SHARED"},
	} {
		t.Run(aliases.name, func(t *testing.T) {
			var lookups atomic.Int64
			lookupOperatorDatabaseEnvironment = func(string) (string, bool) {
				lookups.Add(1)
				return "must-not-be-read", true
			}
			path := writeOperatorMCPConfigWithSelectors(t, "127.0.0.1:1", true, true, aliases.databaseURL, aliases.dbToken, aliases.mcpToken)
			var stdout, stderr bytes.Buffer
			if exit := run([]string{"--config", path, "serve"}, &stdout, &stderr); exit != 1 || lookups.Load() != 0 || stdout.Len() != 0 || stderr.String() != "cannot construct MCP runtime\n" {
				t.Fatalf("aliases exit=%d lookups=%d stdout=%q stderr=%q", exit, lookups.Load(), stdout.String(), stderr.String())
			}
		})
	}
}

func environmentWithoutNames(environment []string, names ...string) []string {
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
		url, token    string
		setURL        bool
		setEmptyToken bool
	}{
		{setURL: false},
		{url: "https://db.invalid", setURL: true},
		{url: "http://127.0.0.1:8080", token: "synthetic-token", setURL: true},
		{url: "http://127.0.0.1:8080", setURL: true, setEmptyToken: true},
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
			if test.token == "" && !test.setEmptyToken {
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
	for _, test := range []struct {
		name, cursor string
		present      bool
	}{{name: "uninitialized", cursor: "uninitialized"}, {name: "initialized", cursor: "initialized", present: true}} {
		t.Run(test.name, func(t *testing.T) {
			runRealProcessAccountStatus(t, binaryPath, test.present, test.cursor)
		})
	}
}

func runRealProcessAccountStatus(t *testing.T, binaryPath string, cursorPresent bool, cursorLiteral string) {
	t.Helper()
	storageServer := syntheticAccountListServerWithCursor(t, cursorPresent, nil)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	configPath := writeOperatorMCPConfig(t, address, true, true)
	token := generatedMCPToken(t)
	t.Setenv("SYNTHETIC_OPERATOR_DATABASE_URL", "ambient-database-url-must-be-filtered")
	t.Setenv("SYNTHETIC_OPERATOR_DATABASE_TOKEN", "ambient-database-token-must-be-filtered")

	var stdout, stderr bytes.Buffer
	process := exec.Command(binaryPath, "--config", configPath, "serve")
	process.Stdout = &stdout
	process.Stderr = &stderr
	process.Env = append(environmentWithoutNames(os.Environ(), "SYNTHETIC_OPERATOR_MCP_TOKEN", "SYNTHETIC_OPERATOR_DATABASE_URL", "SYNTHETIC_OPERATOR_DATABASE_TOKEN"), "SYNTHETIC_OPERATOR_MCP_TOKEN="+token, "SYNTHETIC_OPERATOR_DATABASE_URL="+storageServer.URL)
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
		request, err := newOperatorProcessRequest(address, token, name, body)
		if err != nil {
			t.Fatal(err)
		}
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 65_537))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(syntheticProcessAccountID)) {
			t.Fatalf("tool %q status=%d read=%v body=%s", name, response.StatusCode, readErr, responseBody)
		}
		if bytes.Contains(responseBody, []byte("synthetic-provider-subject")) || bytes.Contains(responseBody, []byte("9001")) || bytes.Contains(responseBody, []byte("cursor_present")) {
			t.Fatalf("tool %q exposed provider subject or cursor: %s", name, responseBody)
		}
		if name == "mail_sync_status" {
			for _, required := range [][]byte{[]byte(`"cursor_status":"` + cursorLiteral + `"`), []byte(`"last_success_at":null`), []byte(`"last_error_category":null`), []byte(`"progress":null`)} {
				if !bytes.Contains(responseBody, required) {
					t.Fatalf("tool %q missing %s: %s", name, required, responseBody)
				}
			}
		}
	}
	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{token, syntheticProcessAccountID, storageServer.URL, "ambient-database-url-must-be-filtered", "ambient-database-token-must-be-filtered"} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatalf("process output disclosed sensitive data: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}

func newOperatorProcessRequest(address, token, name, body string) (*http.Request, error) {
	request, err := http.NewRequest(http.MethodPost, "http://"+address+"/private-mcp", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", name)
	return request, nil
}

type shutdownStorageProbe struct {
	server        *httptest.Server
	queryStarted  chan struct{}
	queryDone     chan struct{}
	releaseQuery  chan struct{}
	closeStarted  chan struct{}
	queryOnce     sync.Once
	queryDoneOnce sync.Once
	releaseOnce   sync.Once
	closeOnce     sync.Once
	queryCount    atomic.Int64
	closeCount    atomic.Int64
	sequence      atomic.Int64
	queryOrder    atomic.Int64
	closeOrder    atomic.Int64
}

func newShutdownStorageProbe(t *testing.T) *shutdownStorageProbe {
	t.Helper()
	probe := &shutdownStorageProbe{queryStarted: make(chan struct{}), queryDone: make(chan struct{}), releaseQuery: make(chan struct{}), closeStarted: make(chan struct{})}
	probe.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("credential-free storage request carried authorization")
		}
		switch request.URL.Path {
		case "/v3/cursor":
			probe.queryCount.Add(1)
			probe.queryOnce.Do(func() { close(probe.queryStarted) })
			response.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(response)
			_ = encoder.Encode(map[string]any{"baton": "synthetic-shutdown-baton", "base_url": nil})
			_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{
				map[string]any{"name": "account_id", "decltype": "TEXT"}, map[string]any{"name": "provider", "decltype": "TEXT"},
				map[string]any{"name": "state", "decltype": "TEXT"}, map[string]any{"name": "state_version", "decltype": "INTEGER"},
				map[string]any{"name": "reauthorization_reason", "decltype": "TEXT"}, map[string]any{"name": "revocation_status", "decltype": "TEXT"},
				map[string]any{"name": "cursor_present", "decltype": "INTEGER"}, map[string]any{"name": "credential_present", "decltype": "INTEGER"},
			}})
			if flusher, ok := response.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
			probe.queryOrder.Store(probe.sequence.Add(1))
			probe.queryDoneOnce.Do(func() { close(probe.queryDone) })
			<-probe.releaseQuery
		case "/v3/pipeline":
			probe.closeCount.Add(1)
			probe.closeOrder.Store(probe.sequence.Add(1))
			select {
			case <-probe.queryDone:
			default:
				t.Error("stream close started before stalled query completed")
			}
			probe.closeOnce.Do(func() { close(probe.closeStarted) })
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"baton": nil, "base_url": nil, "results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}}})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(probe.server.Close)
	t.Cleanup(probe.release)
	return probe
}

func (probe *shutdownStorageProbe) release() {
	probe.releaseOnce.Do(func() { close(probe.releaseQuery) })
}

func TestRealProcessShutdownDrainsStalledAccountReadBeforeSourceClose(t *testing.T) {
	probe := newShutdownStorageProbe(t)
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "inboxgate")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
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
	process.Env = append(environmentWithoutNames(os.Environ(), "SYNTHETIC_OPERATOR_MCP_TOKEN", "SYNTHETIC_OPERATOR_DATABASE_URL", "SYNTHETIC_OPERATOR_DATABASE_TOKEN"), "SYNTHETIC_OPERATOR_MCP_TOKEN="+token, "SYNTHETIC_OPERATOR_DATABASE_URL="+probe.server.URL)
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
	body := `{"jsonrpc":"2.0","id":"shutdown-id","method":"tools/call","params":{"name":"accounts_list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic-client","version":"1.0.0"}}}}`
	request, err := newOperatorProcessRequest(address, token, "accounts_list", body)
	if err != nil {
		t.Fatal(err)
	}
	type requestResult struct {
		status int
		body   []byte
		err    error
	}
	requestDone := make(chan requestResult, 1)
	go func() {
		response, requestErr := (&http.Client{Timeout: 5 * time.Second}).Do(request)
		if requestErr != nil {
			requestDone <- requestResult{err: requestErr}
			return
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 65_537))
		_ = response.Body.Close()
		requestDone <- requestResult{status: response.StatusCode, body: responseBody, err: readErr}
	}()
	select {
	case <-probe.queryStarted:
	case <-time.After(time.Second):
		t.Fatal("stalled query did not start")
	}
	started := time.Now()
	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-requestDone:
		want := `{"jsonrpc":"2.0","id":"shutdown-id","error":{"code":-32603,"message":"internal error"}}`
		if result.err != nil || result.status != http.StatusOK || string(result.body) != want {
			t.Fatalf("stalled request = status %d err %v body %q", result.status, result.err, result.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled request did not drain")
	}
	select {
	case <-probe.queryDone:
	case <-time.After(time.Second):
		t.Fatal("stalled cursor request did not observe cancellation")
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("process shutdown = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("process shutdown was not bounded")
	}
	probe.release()
	if elapsed := time.Since(started); elapsed >= 3*time.Second || probe.queryCount.Load() != 1 || probe.closeCount.Load() != 0 || probe.queryOrder.Load() < 1 || probe.closeOrder.Load() != 0 {
		t.Fatalf("shutdown elapsed=%v query=%d close=%d order=(%d,%d)", elapsed, probe.queryCount.Load(), probe.closeCount.Load(), probe.queryOrder.Load(), probe.closeOrder.Load())
	}
	for _, forbidden := range []string{token, syntheticProcessAccountID, probe.server.URL, "shutdown-id"} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatalf("shutdown output disclosed %q: stdout=%q stderr=%q", forbidden, stdout.String(), stderr.String())
		}
	}
}

func TestPostSourceMCPConstructionFailureClosesSourceOnce(t *testing.T) {
	var closeCount atomic.Int64
	originalOpen := openOperatorAccountStatusSource
	openOperatorAccountStatusSource = func(context.Context, storage.Endpoint) (storage.Handle, error) {
		return &closeCountingStorageHandle{closeCount: &closeCount}, nil
	}
	t.Cleanup(func() { openOperatorAccountStatusSource = originalOpen })
	path := writeOperatorMCPConfig(t, "127.0.0.1:1", true, true)
	t.Setenv("SYNTHETIC_OPERATOR_MCP_TOKEN", generatedMCPToken(t))
	t.Setenv("SYNTHETIC_OPERATOR_DATABASE_URL", "http://127.0.0.1:1")
	_ = os.Unsetenv("SYNTHETIC_OPERATOR_DATABASE_TOKEN")
	originalVersion, originalCommit := version, commit
	version, commit = "v0.1.0", "invalid"
	t.Cleanup(func() { version, commit = originalVersion, originalCommit })
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"--config", path, "serve"}, &stdout, &stderr); exit != 1 || stdout.Len() != 0 || stderr.String() != "cannot construct MCP runtime\n" || closeCount.Load() != 1 {
		t.Fatalf("construction failure exit=%d close=%d stdout=%q stderr=%q", exit, closeCount.Load(), stdout.String(), stderr.String())
	}
}

func TestAccountStatusMCPCloserCallsSourceCloseOnceAndWaitsForCompletion(t *testing.T) {
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	handler, err := inboxmcp.New(inboxmcp.Options{
		Configuration: configuration,
		BinaryVersion: "dev",
		BearerToken:   []byte(generatedMCPToken(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	source := newBlockingCloseStorageHandle()
	t.Cleanup(source.release)
	closer := &accountStatusMCPCloser{handler: handler, source: source}
	result := make(chan error, 1)
	go func() { result <- closer.Close() }()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("source close did not start")
	}
	if source.count.Load() != 1 {
		t.Fatalf("source close calls = %d, want 1", source.count.Load())
	}
	select {
	case err := <-result:
		t.Fatalf("composite close returned before source completion: %v", err)
	default:
	}
	source.release()
	select {
	case err := <-result:
		if err != nil || source.count.Load() != 1 {
			t.Fatalf("composite close error=%v source calls=%d", err, source.count.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("composite close did not return after source completion")
	}
}

type closeCountingStorageHandle struct {
	storage.Handle
	closeCount *atomic.Int64
}

type blockingCloseStorageHandle struct {
	storage.Handle
	started      chan struct{}
	releaseClose chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
	count        atomic.Int64
}

func newBlockingCloseStorageHandle() *blockingCloseStorageHandle {
	return &blockingCloseStorageHandle{started: make(chan struct{}), releaseClose: make(chan struct{})}
}

func (handle *blockingCloseStorageHandle) Close() error {
	handle.count.Add(1)
	handle.startOnce.Do(func() { close(handle.started) })
	<-handle.releaseClose
	return nil
}

func (handle *blockingCloseStorageHandle) release() {
	handle.releaseOnce.Do(func() { close(handle.releaseClose) })
}

func (handle *closeCountingStorageHandle) Close() error {
	handle.closeCount.Add(1)
	return nil
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
	return syntheticAccountListServerWithCursor(t, true, closeBlock)
}

func syntheticAccountListServerWithCursor(t *testing.T, cursorPresent bool, closeBlock <-chan struct{}) *httptest.Server {
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
			cursorValue := int64(0)
			if cursorPresent {
				cursorValue = 1
			}
			row := []any{textProtocolValue(syntheticProcessAccountID), textProtocolValue("gmail"), textProtocolValue("active"), integerProtocolValue(2), map[string]any{"type": "null"}, textProtocolValue("none"), integerProtocolValue(cursorValue), integerProtocolValue(1)}
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
