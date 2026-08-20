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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type reviewShutdownProbe struct {
	server        *httptest.Server
	queryStarted  chan struct{}
	queryDone     chan struct{}
	queryOnce     sync.Once
	queryDoneOnce sync.Once
	queryCount    atomic.Int64
	closeCount    atomic.Int64
	sequence      atomic.Int64
	queryOrder    atomic.Int64
	closeOrder    atomic.Int64
}

func newReviewShutdownProbe(t *testing.T) *reviewShutdownProbe {
	t.Helper()
	probe := &reviewShutdownProbe{queryStarted: make(chan struct{}), queryDone: make(chan struct{})}
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
			_ = encoder.Encode(map[string]any{"baton": "synthetic-review-shutdown-baton", "base_url": nil})
			_ = encoder.Encode(map[string]any{"type": "step_begin", "step": 0, "cols": []any{
				map[string]any{"name": "account_id", "decltype": "TEXT"}, map[string]any{"name": "gmail_message_id", "decltype": "TEXT"},
				map[string]any{"name": "gmail_thread_id", "decltype": "TEXT"}, map[string]any{"name": "metadata_version", "decltype": "INTEGER"},
				map[string]any{"name": "metadata_json", "decltype": "TEXT"}, map[string]any{"name": "metadata_hash", "decltype": "TEXT"},
				map[string]any{"name": "gate_version", "decltype": "INTEGER"}, map[string]any{"name": "source_metadata_hash", "decltype": "TEXT"},
				map[string]any{"name": "input_hash", "decltype": "TEXT"}, map[string]any{"name": "outcome", "decltype": "TEXT"},
				map[string]any{"name": "reason_codes", "decltype": "TEXT"}, map[string]any{"name": "evaluated_at_unix_ms", "decltype": "INTEGER"},
			}})
			if flusher, ok := response.(http.Flusher); ok {
				flusher.Flush()
			}
			<-request.Context().Done()
			probe.queryOrder.Store(probe.sequence.Add(1))
			probe.queryDoneOnce.Do(func() { close(probe.queryDone) })
		case "/v3/pipeline":
			probe.closeCount.Add(1)
			probe.closeOrder.Store(probe.sequence.Add(1))
			select {
			case <-probe.queryDone:
			default:
				t.Error("review stream close started before the canceled cursor drained")
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"baton": nil, "base_url": nil, "results": []any{map[string]any{"type": "ok", "response": map[string]any{"type": "close"}}}})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(probe.server.Close)
	return probe
}

func writeReviewShutdownConfig(t *testing.T, address string) string {
	t.Helper()
	document := "version: 1\n" +
		"capabilities: {mail.review_read: true}\n" +
		"server: {listen: '" + address + "'}\n" +
		"database: {url_env: SYNTHETIC_REVIEW_DATABASE_URL, auth_token_env: SYNTHETIC_REVIEW_DATABASE_TOKEN}\n" +
		"mcp: {enabled: true, path: /private-mcp, bearer_token_env: SYNTHETIC_REVIEW_MCP_TOKEN, enable_operator_tools: false}\n" +
		"logging: {level: info, format: json}\n"
	path := filepath.Join(t.TempDir(), "review-shutdown.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRealProcessShutdownDrainsStalledReviewCursorWithoutCloseReplay(t *testing.T) {
	probe := newReviewShutdownProbe(t)
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
	_ = reservation.Close()
	configPath := writeReviewShutdownConfig(t, address)
	token := generatedMCPToken(t)
	var stdout, stderr bytes.Buffer
	process := exec.Command(binaryPath, "--config", configPath, "serve")
	process.Stdout = &stdout
	process.Stderr = &stderr
	process.Env = append(environmentWithoutNames(os.Environ(), "SYNTHETIC_REVIEW_MCP_TOKEN", "SYNTHETIC_REVIEW_DATABASE_URL", "SYNTHETIC_REVIEW_DATABASE_TOKEN"), "SYNTHETIC_REVIEW_MCP_TOKEN="+token, "SYNTHETIC_REVIEW_DATABASE_URL="+probe.server.URL)
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
	body := `{"jsonrpc":"2.0","id":"review-shutdown-id","method":"tools/call","params":{"name":"mail_list_review_candidates","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"synthetic-client","version":"1.0.0"}}}}`
	request, err := newOperatorProcessRequest(address, token, "mail_list_review_candidates", body)
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
		t.Fatal("stalled review cursor did not start")
	}
	started := time.Now()
	if err := process.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-requestDone:
		want := `{"jsonrpc":"2.0","id":"review-shutdown-id","error":{"code":-32603,"message":"internal error"}}`
		if result.err != nil || result.status != http.StatusOK || string(result.body) != want {
			t.Fatalf("stalled review request = status %d err %v body %q", result.status, result.err, result.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled review request did not drain")
	}
	select {
	case <-probe.queryDone:
	case <-time.After(time.Second):
		t.Fatal("stalled review cursor did not observe cancellation")
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.Wait() }()
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("process shutdown = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("review process shutdown was not bounded")
	}
	// The canceled cursor has already lost its baton, so ADR 0016 requires the
	// one local source Close call to send no protocol close replay.
	// The injected combined-runtime test separately counts that local Close call.
	if elapsed := time.Since(started); elapsed >= 3*time.Second || probe.queryCount.Load() != 1 || probe.closeCount.Load() != 0 || probe.queryOrder.Load() != 1 || probe.closeOrder.Load() != 0 {
		t.Fatalf("shutdown elapsed=%v query=%d close=%d order=(%d,%d)", elapsed, probe.queryCount.Load(), probe.closeCount.Load(), probe.queryOrder.Load(), probe.closeOrder.Load())
	}
	for _, forbidden := range []string{token, syntheticProcessAccountID, probe.server.URL, "review-shutdown-id", "synthetic-review-shutdown-baton"} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatalf("shutdown output disclosed %q: stdout=%q stderr=%q", forbidden, stdout.String(), stderr.String())
		}
	}
}
