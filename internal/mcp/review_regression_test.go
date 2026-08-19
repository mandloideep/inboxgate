package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

func TestApplicationDeadlineAndCancellationCloseBlockingRequestBody(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		timeout time.Duration
	}{
		{name: "deadline", context: func() (context.Context, context.CancelFunc) { return context.Background(), func() {} }, timeout: 20 * time.Millisecond},
		{name: "client cancellation", context: func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }, timeout: time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newContractHandler(t, config.Defaults(), withApplicationTimeout(test.timeout))
			body := newBlockingBody()
			request := validRequest(t, "tools/list", requestBody("tools/list"))
			request.Body = body
			request.ContentLength = -1
			ctx, cancel := test.context()
			request = request.WithContext(ctx)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- perform(t, handler, request) }()
			select {
			case <-body.started:
			case <-time.After(time.Second):
				t.Fatal("blocking body read did not start")
			}
			if test.name == "client cancellation" {
				cancel()
			} else {
				defer cancel()
			}
			select {
			case response := <-result:
				if response.Code != http.StatusInternalServerError || response.Body.String() != "internal_error\n" {
					t.Fatalf("context-completed body response = %d %q", response.Code, response.Body.String())
				}
			case <-time.After(250 * time.Millisecond):
				_ = handler.Close()
				t.Fatal("context completion did not close the blocking request body")
			}
		})
	}
}

func TestRequestBodyReadFailureIsNotClassifiedAsTooLarge(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	request := validRequest(t, "tools/list", requestBody("tools/list"))
	request.Body = io.NopCloser(errorReader{})
	request.ContentLength = -1
	response := perform(t, handler, request)
	if response.Code != http.StatusInternalServerError || response.Body.String() != "internal_error\n" {
		t.Fatalf("read failure response = %d %q, want fixed internal error", response.Code, response.Body.String())
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}

func TestOwnedJSONRPCResponseNeverCommitsBeyondLiteral65536Bytes(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	id := strings.Repeat("&", 12_000)
	body := `{"jsonrpc":"2.0","id":"` + id + `","method":"unknown/method","params":{` + validMeta() + `}}`
	request := validRequest(t, "unknown/method", body)
	response := perform(t, handler, request)
	if response.Code != http.StatusInternalServerError || response.Body.String() != "internal_error\n" {
		t.Fatalf("oversized owned JSON-RPC response = %d bytes, status %d", response.Body.Len(), response.Code)
	}
	if response.Body.Len() > 65_536 || strings.Contains(response.Body.String(), `"jsonrpc"`) {
		t.Fatalf("oversized owned JSON-RPC response was partially committed")
	}
}

func TestLiteralIssueContractBoundaries(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())

	base := requestBody("tools/list")
	for _, size := range []int{65_536, 65_537} {
		body := base + strings.Repeat(" ", size-len(base))
		response := perform(t, handler, validRequest(t, "tools/list", body))
		want := http.StatusOK
		if size == 65_537 {
			want = http.StatusRequestEntityTooLarge
		}
		if response.Code != want {
			t.Errorf("literal request size %d status = %d, want %d", size, response.Code, want)
		}
	}

	for _, size := range []int{256, 257} {
		method := strings.Repeat("x", size)
		response := perform(t, handler, validRequest(t, method, requestBody(method)))
		want := http.StatusOK
		if size == 257 {
			want = http.StatusBadRequest
		}
		if response.Code != want {
			t.Errorf("literal routing size %d status = %d, want %d", size, response.Code, want)
		}
	}

	for _, test := range []struct {
		containers int
		want       structuralError
	}{{containers: 16, want: structuralOK}, {containers: 17, want: structuralInvalid}} {
		decoder := json.NewDecoder(strings.NewReader(strings.Repeat("[", test.containers) + "0" + strings.Repeat("]", test.containers)))
		state := structuralState{}
		_, got := decodeJSONValue(decoder, &state, 1)
		if got != test.want {
			t.Errorf("literal container depth %d result = %d, want %d", test.containers, got, test.want)
		}
	}

	for _, test := range []struct {
		nodes int
		want  structuralError
	}{{nodes: 2_048, want: structuralOK}, {nodes: 2_049, want: structuralInvalid}} {
		elements := test.nodes - 1
		body := "[" + strings.TrimSuffix(strings.Repeat("0,", elements), ",") + "]"
		decoder := json.NewDecoder(strings.NewReader(body))
		state := structuralState{}
		_, got := decodeJSONValue(decoder, &state, 1)
		if got != test.want {
			t.Errorf("literal node count %d result = %d, want %d", test.nodes, got, test.want)
		}
	}

	buffer := newResponseBuffer(65_536)
	if _, err := buffer.Write(bytes.Repeat([]byte{'x'}, 65_536)); err != nil || buffer.exceeded || buffer.body.Len() != 65_536 {
		t.Fatalf("literal 65,536-byte response was not accepted")
	}
	buffer = newResponseBuffer(65_536)
	_, _ = buffer.Write(bytes.Repeat([]byte{'x'}, 65_537))
	if !buffer.exceeded || buffer.body.Len() != 65_536 {
		t.Fatalf("literal 65,537-byte response was not capped before commit")
	}
}

func TestLiteralSixteenAdmittedAndSeventeenthRejected(t *testing.T) {
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	handler := newContractHandler(t, config.Defaults(), withDispatchHook(func(ctx context.Context) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}))
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
		}()
	}
	for index := 0; index < 16; index++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("literal admitted request did not enter")
		}
	}
	seventeenth := perform(t, handler, validRequest(t, "tools/call", requestBody("tools/call")))
	if seventeenth.Code != http.StatusTooManyRequests || seventeenth.Body.String() != "too_many_requests\n" {
		t.Fatalf("literal seventeenth response = %d %q", seventeenth.Code, seventeenth.Body.String())
	}
	close(release)
	wait.Wait()
}

func TestAuditEventSurvivesConfiguredLevelAndClassifiesSemanticFailure(t *testing.T) {
	type scenario struct {
		name    string
		request func(*testing.T) *http.Request
		outcome string
	}
	scenarios := []scenario{
		{name: "success", request: func(t *testing.T) *http.Request { return validRequest(t, "tools/list", requestBody("tools/list")) }, outcome: "success"},
		{name: "unauthorized", request: func(t *testing.T) *http.Request {
			request := validRequest(t, "tools/list", requestBody("tools/list"))
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
			return request
		}, outcome: "rejected"},
		{name: "unknown method", request: func(t *testing.T) *http.Request {
			return validRequest(t, "unknown/method", requestBody("unknown/method"))
		}, outcome: "failure"},
		{name: "unknown tool", request: func(t *testing.T) *http.Request {
			request := validRequest(t, "tools/call", strings.Replace(requestBody("tools/call"), `"system_capabilities"`, `"unknown_tool"`, 1))
			request.Header.Set("Mcp-Name", "unknown_tool")
			return request
		}, outcome: "failure"},
		{name: "invalid params", request: func(t *testing.T) *http.Request {
			return validRequest(t, "tools/call", strings.Replace(requestBody("tools/call"), `"arguments":{}`, `"arguments":{"extra":true}`, 1))
		}, outcome: "failure"},
		{name: "protocol mismatch", request: func(t *testing.T) *http.Request {
			request := validRequest(t, "tools/list", requestBody("tools/call"))
			request.Header.Set("Mcp-Name", "system_capabilities")
			return request
		}, outcome: "failure"},
	}
	for _, format := range []string{"json", "text"} {
		for _, level := range []string{"debug", "info", "warn", "error"} {
			for _, scenario := range scenarios {
				t.Run(format+"/"+level+"/"+scenario.name, func(t *testing.T) {
					configuration := config.Defaults()
					configuration.Logging.Format = format
					configuration.Logging.Level = level
					var audit bytes.Buffer
					handler, err := New(Options{Configuration: configuration, BinaryVersion: "dev", BearerToken: []byte(canonicalToken()), AuditOutput: &audit})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = handler.Close() })
					perform(t, handler, scenario.request(t))
					line := strings.TrimSpace(audit.String())
					if line == "" || strings.Count(line, "\n") != 0 {
						t.Fatalf("audit event count is not exactly one: %q", line)
					}
					fields := decodeAuditFields(t, format, line)
					if fields["outcome"] != scenario.outcome {
						t.Errorf("audit outcome = %v, want %s", fields["outcome"], scenario.outcome)
					}
				})
			}
		}
	}
}

func TestHTTP2TLSLoopbackEnforcesLiteralBodyBoundary(t *testing.T) {
	handler := newContractHandler(t, config.Defaults())
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	base := requestBody("tools/list")
	for _, size := range []int{65_536, 65_537} {
		body := base + strings.Repeat(" ", size-len(base))
		request, err := http.NewRequest(http.MethodPost, server.URL+mcpPath, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+canonicalToken())
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Mcp-Protocol-Version", protocolVersion)
		request.Header.Set("Mcp-Method", "tools/list")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.ProtoMajor != 2 {
			t.Fatalf("transport protocol = %s, want HTTP/2", response.Proto)
		}
		if size == 65_536 && response.StatusCode != http.StatusOK {
			t.Fatalf("HTTP/2 exact-limit status = %d, body = %q", response.StatusCode, data)
		}
		if size == 65_537 && (response.StatusCode != http.StatusRequestEntityTooLarge || string(data) != "request_too_large\n" || bytes.Contains(data, []byte(`"jsonrpc"`))) {
			t.Fatalf("HTTP/2 over-limit response = %d %q", response.StatusCode, data)
		}
	}
}
