package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

type contractMCPHandler struct {
	requests atomic.Int64
	closed   atomic.Int64
	cancel   context.CancelFunc
	started  chan struct{}
	done     chan struct{}
}

func (handler *contractMCPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.requests.Add(1)
	if handler.started == nil {
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, "{\"jsonrpc\":\"2.0\"}\n")
		return
	}
	close(handler.started)
	select {
	case <-request.Context().Done():
	case <-handler.done:
	}
}

func (handler *contractMCPHandler) Close() error {
	handler.closed.Add(1)
	if handler.cancel != nil {
		handler.cancel()
	}
	if handler.done != nil {
		select {
		case <-handler.done:
		default:
			close(handler.done)
		}
	}
	return nil
}

func TestMCPRouteRegistersOnlyWhenEnabledAndRemainsExact(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			configuration := config.Defaults()
			configuration.MCP.Enabled = enabled
			configuration.MCP.Path = "/private-mcp"
			handler := &contractMCPHandler{}
			runtime, err := New(configuration, io.Discard, WithMCP(handler, handler))
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{"/private-mcp", "/private-mcp/", "/private-mcp?private=query", "/%70rivate-mcp"} {
				request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+target, bytes.NewReader([]byte("{}")))
				response := httptest.NewRecorder()
				runtime.Handler().ServeHTTP(response, request)
				want := http.StatusNotFound
				if enabled && target == "/private-mcp" {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Errorf("target %q status = %d, want %d", target, response.Code, want)
				}
			}
			wantRequests := int64(0)
			if enabled {
				wantRequests = 1
			}
			if handler.requests.Load() != wantRequests {
				t.Errorf("MCP requests = %d, want %d", handler.requests.Load(), wantRequests)
			}
			for _, healthPath := range []string{"/health/live", "/health/ready"} {
				request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+healthPath, nil)
				response := httptest.NewRecorder()
				runtime.Handler().ServeHTTP(response, request)
				if healthPath == "/health/live" && response.Body.String() != liveBody {
					t.Errorf("liveness changed: %q", response.Body.String())
				}
				if healthPath == "/health/ready" && response.Body.String() != notReadyBody {
					t.Errorf("pre-serve readiness changed: %q", response.Body.String())
				}
			}
		})
	}
}

func TestMCPShutdownStopsAdmissionCancelsWorkAndClosesOnce(t *testing.T) {
	listener := loopbackListener(t)
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	configuration.MCP.Path = "/mcp"
	handler := &contractMCPHandler{started: make(chan struct{}), done: make(chan struct{})}
	runtime, err := New(configuration, io.Discard, WithListen(returnListener(listener)), WithShutdownTimeout(time.Second), WithMCP(handler, handler))
	if err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	exit := make(chan int, 1)
	go func() { exit <- runtime.ListenAndServe("ignored", signals) }()
	waitReady(t, runtime)

	request, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/mcp", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan struct{})
	go func() {
		response, _ := http.DefaultClient.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		close(requestDone)
	}()
	select {
	case <-handler.started:
	case <-time.After(time.Second):
		t.Fatal("MCP request did not start")
	}
	signals <- os.Interrupt
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
	case <-time.After(time.Second):
		t.Fatal("MCP shutdown did not complete")
	}
	<-requestDone
	if handler.closed.Load() != 1 || runtime.Ready() {
		t.Fatalf("close calls = %d, ready = %t", handler.closed.Load(), runtime.Ready())
	}
	response, requestErr := http.Post("http://"+listener.Addr().String()+"/mcp", "application/json", bytes.NewReader([]byte("{}")))
	if response != nil {
		_ = response.Body.Close()
	}
	if requestErr == nil {
		t.Fatal("shutdown admitted a new request")
	}
}

func TestDisabledMCPDoesNotCloseUnusedHandler(t *testing.T) {
	configuration := config.Defaults()
	configuration.MCP.Enabled = false
	handler := &contractMCPHandler{}
	runtime, err := New(configuration, io.Discard, WithMCP(handler, handler))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.closeMCP(); err != nil {
		t.Fatal(err)
	}
	if handler.closed.Load() != 0 {
		t.Fatal("disabled MCP took ownership of a handler")
	}
}
