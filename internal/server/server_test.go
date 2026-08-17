package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

func TestHealthHandlerContract(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		ready       bool
		body        io.Reader
		contentSize int64
		transfer    []string
		wantStatus  int
		wantBody    string
		wantAllow   string
	}{
		{name: "live get", method: http.MethodGet, path: "/health/live", wantStatus: http.StatusOK, wantBody: "{\"status\":\"live\"}\n"},
		{name: "live head", method: http.MethodHead, path: "/health/live", wantStatus: http.StatusOK},
		{name: "ready get", method: http.MethodGet, path: "/health/ready", ready: true, wantStatus: http.StatusOK, wantBody: "{\"status\":\"ready\"}\n"},
		{name: "ready head", method: http.MethodHead, path: "/health/ready", ready: true, wantStatus: http.StatusOK},
		{name: "not ready get", method: http.MethodGet, path: "/health/ready", wantStatus: http.StatusServiceUnavailable, wantBody: "{\"status\":\"not_ready\"}\n"},
		{name: "not ready head", method: http.MethodHead, path: "/health/ready", wantStatus: http.StatusServiceUnavailable},
		{name: "method rejected", method: http.MethodPost, path: "/health/live", wantStatus: http.StatusMethodNotAllowed, wantBody: "{\"error\":\"method_not_allowed\"}\n", wantAllow: "GET, HEAD"},
		{name: "unknown path", method: http.MethodGet, path: "/health/live/extra?private=query", wantStatus: http.StatusNotFound, wantBody: "{\"error\":\"not_found\"}\n"},
		{name: "declared body", method: http.MethodGet, path: "/health/live", body: strings.NewReader("x"), contentSize: 1, wantStatus: http.StatusBadRequest, wantBody: "{\"error\":\"request_body_not_allowed\"}\n"},
		{name: "oversized body", method: http.MethodGet, path: "/health/live", body: strings.NewReader("oversized"), contentSize: 1025, wantStatus: http.StatusRequestEntityTooLarge, wantBody: "{\"error\":\"request_too_large\"}\n"},
		{name: "transfer encoded body", method: http.MethodGet, path: "/health/live", body: strings.NewReader("x"), contentSize: -1, transfer: []string{"chunked"}, wantStatus: http.StatusBadRequest, wantBody: "{\"error\":\"request_body_not_allowed\"}\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := config.Defaults()
			configuration.Server.MaxRequestBytes = 1024
			var logs bytes.Buffer
			runtime, err := New(configuration, &logs)
			if err != nil {
				t.Fatal(err)
			}
			runtime.readiness.Store(test.ready)

			request, err := http.NewRequest(test.method, "http://synthetic.invalid"+test.path, test.body)
			if err != nil {
				t.Fatal(err)
			}
			request.ContentLength = test.contentSize
			request.TransferEncoding = test.transfer
			response := newCaptureResponse()
			runtime.Handler().ServeHTTP(response, request)

			if response.status != test.wantStatus {
				t.Errorf("status = %d, want %d", response.status, test.wantStatus)
			}
			if got := response.body.String(); got != test.wantBody {
				t.Errorf("body = %q, want %q", got, test.wantBody)
			}
			wantRepresentation := test.wantBody
			if test.method == http.MethodHead {
				switch test.path {
				case "/health/live":
					wantRepresentation = "{\"status\":\"live\"}\n"
				case "/health/ready":
					if test.ready {
						wantRepresentation = "{\"status\":\"ready\"}\n"
					} else {
						wantRepresentation = "{\"status\":\"not_ready\"}\n"
					}
				}
			}
			assertResponseHeaders(t, response.header, len(wantRepresentation), test.wantAllow)
		})
	}
}

func TestHealthHandlerLogsOnlyAllowlistedFieldsAndRedactsCanaries(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			configuration := config.Defaults()
			configuration.Logging.Format = format
			configuration.Logging.Level = "debug"
			var output bytes.Buffer
			runtime, err := New(configuration, &output)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodGet, "http://private-host.invalid/secret-path?secret-query", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "sensitive-host.invalid"
			request.RemoteAddr = "192.0.2.99:4321"
			request.Header.Set("User-Agent", "secret-agent-value")
			request.Header.Set("X-Canary", "secret-header-value")
			runtime.Handler().ServeHTTP(newCaptureResponse(), request)

			logText := output.String()
			for _, forbidden := range []string{"private-host", "secret-path", "secret-query", "sensitive-host", "192.0.2.99", "secret-agent-value", "secret-header-value"} {
				if strings.Contains(logText, forbidden) {
					t.Errorf("log contains forbidden canary %q: %s", forbidden, logText)
				}
			}
			fields := decodeLogFields(t, format, logText)
			assertExactKeys(t, fields, "time", "level", "msg", "event", "operation", "method", "status", "duration_ms", "outcome")
			if fields["event"] != "http_request" || fields["operation"] != "unmatched" || fields["method"] != "GET" || number(t, fields["status"]) != http.StatusNotFound || number(t, fields["duration_ms"]) < 0 || fields["outcome"] != "not_found" {
				t.Errorf("unexpected request record: %#v", fields)
			}
		})
	}
}

func TestEscapedHealthPathsAreUnmatchedAndRedacted(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "encoded slash get", method: http.MethodGet, path: "/health%2Flive"},
		{name: "encoded slash head", method: http.MethodHead, path: "/health%2Flive"},
		{name: "encoded letter get", method: http.MethodGet, path: "/%68ealth/live"},
		{name: "encoded letter head", method: http.MethodHead, path: "/%68ealth/live"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := config.Defaults()
			var logs bytes.Buffer
			runtime, err := New(configuration, &logs)
			if err != nil {
				t.Fatal(err)
			}
			runtime.readiness.Store(true)
			request, err := http.NewRequest(test.method, "http://synthetic.invalid"+test.path+"?private=query", nil)
			if err != nil {
				t.Fatal(err)
			}
			response := newCaptureResponse()
			runtime.Handler().ServeHTTP(response, request)
			if response.status != http.StatusNotFound {
				t.Errorf("status = %d, want %d", response.status, http.StatusNotFound)
			}
			wantBody := notFoundBody
			if test.method == http.MethodHead {
				wantBody = ""
			}
			if response.body.String() != wantBody {
				t.Errorf("body = %q, want %q", response.body.String(), wantBody)
			}
			assertResponseHeaders(t, response.header, len(notFoundBody), "")
			fields := decodeLogFields(t, "json", logs.String())
			assertExactKeys(t, fields, "time", "level", "msg", "event", "operation", "method", "status", "duration_ms", "outcome")
			if fields["operation"] != "unmatched" || number(t, fields["status"]) != http.StatusNotFound || fields["outcome"] != "not_found" {
				t.Errorf("unexpected request record: %#v", fields)
			}
			for _, forbidden := range []string{test.path, "/health/live", "private=query"} {
				if strings.Contains(logs.String(), forbidden) {
					t.Errorf("log contains raw path or query %q: %s", forbidden, logs.String())
				}
			}
		})
	}
}

func TestLoggerHonorsMinimumLevelAndFormats(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			configuration := config.Defaults()
			configuration.Logging.Format = format
			configuration.Logging.Level = "error"
			var output bytes.Buffer
			runtime, err := New(configuration, &output)
			if err != nil {
				t.Fatal(err)
			}
			runtime.logLifecycle("server_started")
			runtime.logFailure("listen_failed")
			lines := nonemptyLines(output.String())
			if len(lines) != 1 {
				t.Fatalf("log lines = %d, want 1: %q", len(lines), output.String())
			}
			fields := decodeLogFields(t, format, lines[0])
			assertExactKeys(t, fields, "time", "level", "msg", "event", "reason")
			if fields["level"] != "ERROR" || fields["event"] != "server_failure" || fields["reason"] != "listen_failed" {
				t.Errorf("unexpected failure record: %#v", fields)
			}
		})
	}
}

func TestLifecycleLogsContainOnlyBoundedFields(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			configuration := config.Defaults()
			configuration.Logging.Format = format
			var output bytes.Buffer
			runtime, err := New(configuration, &output)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range []string{"server_started", "shutdown_started", "shutdown_completed"} {
				runtime.logLifecycle(event)
			}
			lines := nonemptyLines(output.String())
			if len(lines) != 3 {
				t.Fatalf("log lines = %d, want 3: %q", len(lines), output.String())
			}
			for index, line := range lines {
				fields := decodeLogFields(t, format, line)
				assertExactKeys(t, fields, "time", "level", "msg", "event")
				if fields["level"] != "INFO" || fields["event"] != []string{"server_started", "shutdown_started", "shutdown_completed"}[index] {
					t.Errorf("unexpected lifecycle record: %#v", fields)
				}
			}
		})
	}
}

func TestRuntimeAppliesHTTPBounds(t *testing.T) {
	configuration := config.Defaults()
	configuration.Server.ReadHeaderTimeout = 2 * time.Second
	configuration.Server.ReadTimeout = 3 * time.Second
	configuration.Server.WriteTimeout = 4 * time.Second
	configuration.Server.IdleTimeout = 5 * time.Second
	runtime, err := New(configuration, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	server := runtime.httpServer
	if server.ReadHeaderTimeout != 2*time.Second || server.ReadTimeout != 3*time.Second || server.WriteTimeout != 4*time.Second || server.IdleTimeout != 5*time.Second || server.MaxHeaderBytes != MaxHeaderBytes {
		t.Errorf("HTTP bounds were not applied: %#v", server)
	}
	if server.ErrorLog == nil {
		t.Error("standard-library HTTP error logger is not adapted")
	}
}

func TestRuntimeReadinessAndUnexpectedServeFailure(t *testing.T) {
	configuration := config.Defaults()
	var logs bytes.Buffer
	runtime, err := New(configuration, &logs, WithListen(func(string, string) (net.Listener, error) {
		return &failingListener{err: errors.New("sensitive listener failure at 192.0.2.55")}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Ready() {
		t.Fatal("runtime is ready before serving")
	}
	exitCode := runtime.ListenAndServe("private.invalid:1234", make(chan os.Signal))
	if exitCode != 1 || runtime.Ready() {
		t.Fatalf("exit = %d, ready = %t", exitCode, runtime.Ready())
	}
	if !strings.Contains(logs.String(), "serve_failed") || strings.Contains(logs.String(), "192.0.2.55") || strings.Contains(logs.String(), "private.invalid") {
		t.Errorf("unexpected serve failure log: %s", logs.String())
	}
}

func TestRuntimeBindFailureIsRedacted(t *testing.T) {
	configuration := config.Defaults()
	var logs bytes.Buffer
	runtime, err := New(configuration, &logs, WithListen(func(_, _ string) (net.Listener, error) {
		return nil, errors.New("listen tcp 192.0.2.44:9090: sensitive bind failure")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if exitCode := runtime.ListenAndServe("private.invalid:9090", make(chan os.Signal)); exitCode != 1 {
		t.Fatalf("exit = %d, want 1", exitCode)
	}
	if !strings.Contains(logs.String(), "listen_failed") {
		t.Errorf("missing bounded failure: %s", logs.String())
	}
	for _, forbidden := range []string{"192.0.2.44", "private.invalid", "sensitive bind failure", "9090"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Errorf("bind log contains %q: %s", forbidden, logs.String())
		}
	}
}

func TestRuntimeGracefulShutdownDrainsInflightRequest(t *testing.T) {
	listener := loopbackListener(t)
	configuration := config.Defaults()
	started := make(chan struct{})
	release := make(chan struct{})
	runtime, err := New(configuration, io.Discard, WithListen(returnListener(listener)), WithShutdownTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	runtime.httpServer.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		response.WriteHeader(http.StatusNoContent)
	})
	signals := make(chan os.Signal, 2)
	exit := make(chan int, 1)
	go func() { exit <- runtime.ListenAndServe("ignored", signals) }()
	waitReady(t, runtime)

	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	signals <- os.Interrupt
	signals <- os.Interrupt
	readinessDeadline := time.Now().Add(time.Second)
	for runtime.Ready() && time.Now().Before(readinessDeadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Ready() {
		t.Fatal("runtime did not become unready before shutdown draining")
	}
	close(release)
	if err := <-requestDone; err != nil {
		t.Fatalf("in-flight request did not drain: %v", err)
	}
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
	case <-time.After(time.Second):
		t.Fatal("graceful shutdown did not complete")
	}
}

func TestRuntimeShutdownDeadlineForcesClose(t *testing.T) {
	listener := loopbackListener(t)
	configuration := config.Defaults()
	started := make(chan struct{})
	block := make(chan struct{})
	var logs bytes.Buffer
	runtime, err := New(configuration, &logs, WithListen(returnListener(listener)), WithShutdownTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	runtime.httpServer.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-block
	})
	signals := make(chan os.Signal, 1)
	exit := make(chan int, 1)
	go func() { exit <- runtime.ListenAndServe("ignored", signals) }()
	waitReady(t, runtime)
	requestDone := make(chan struct{})
	go func() {
		response, _ := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		close(requestDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	signals <- os.Interrupt
	select {
	case code := <-exit:
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown deadline did not force close")
	}
	close(block)
	<-requestDone
	if !strings.Contains(logs.String(), "shutdown_timeout") {
		t.Errorf("missing shutdown timeout log: %s", logs.String())
	}
}

func TestSecondSignalDoesNotExtendShutdownDeadline(t *testing.T) {
	listener := loopbackListener(t)
	configuration := config.Defaults()
	started := make(chan struct{})
	block := make(chan struct{})
	const shutdownTimeout = 150 * time.Millisecond
	runtime, err := New(configuration, io.Discard, WithListen(returnListener(listener)), WithShutdownTimeout(shutdownTimeout))
	if err != nil {
		t.Fatal(err)
	}
	runtime.httpServer.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-block
	})
	signals := make(chan os.Signal, 2)
	exit := make(chan int, 1)
	go func() { exit <- runtime.ListenAndServe("ignored", signals) }()
	waitReady(t, runtime)
	requestDone := make(chan struct{})
	go func() {
		response, _ := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		close(requestDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}

	shutdownStarted := time.Now()
	signals <- os.Interrupt
	time.Sleep(100 * time.Millisecond)
	signals <- os.Interrupt
	select {
	case code := <-exit:
		elapsed := time.Since(shutdownStarted)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if elapsed < 120*time.Millisecond || elapsed > 225*time.Millisecond {
			t.Fatalf("shutdown elapsed = %s, want original %s deadline without restart", elapsed, shutdownTimeout)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("second signal extended the original shutdown deadline")
	}
	close(block)
	<-requestDone
}

func TestRuntimeConcurrentHealthAndShutdown(t *testing.T) {
	configuration := config.Defaults()
	runtime, err := New(configuration, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for requestIndex := 0; requestIndex < 100; requestIndex++ {
				runtime.readiness.Store(requestIndex%2 == 0)
				request, requestErr := http.NewRequest(http.MethodGet, "http://synthetic.invalid/health/ready", nil)
				if requestErr != nil {
					t.Error(requestErr)
					return
				}
				runtime.Handler().ServeHTTP(newCaptureResponse(), request)
			}
		}()
	}
	group.Wait()
}

type captureResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newCaptureResponse() *captureResponse {
	return &captureResponse{header: make(http.Header)}
}

func (r *captureResponse) Header() http.Header { return r.header }

func (r *captureResponse) WriteHeader(status int) { r.status = status }

func (r *captureResponse) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(data)
}

func assertResponseHeaders(t *testing.T, header http.Header, contentLength int, allow string) {
	t.Helper()
	if got := header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := header.Get("Content-Length"); got != intString(contentLength) {
		t.Errorf("Content-Length = %q, want %d", got, contentLength)
	}
	if got := header.Get("Allow"); got != allow {
		t.Errorf("Allow = %q, want %q", got, allow)
	}
}

func decodeLogFields(t *testing.T, format, line string) map[string]any {
	t.Helper()
	fields := make(map[string]any)
	if format == "json" {
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &fields); err != nil {
			t.Fatalf("decode JSON log: %v: %q", err, line)
		}
		return fields
	}
	scanner := bufio.NewScanner(strings.NewReader(line))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found {
			fields[key] = strings.Trim(value, `"`)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return fields
}

func assertExactKeys(t *testing.T, fields map[string]any, keys ...string) {
	t.Helper()
	want := make(map[string]bool, len(keys))
	for _, key := range keys {
		want[key] = true
	}
	for key := range fields {
		if !want[key] {
			t.Errorf("unexpected log field %q in %#v", key, fields)
		}
	}
	for key := range want {
		if _, found := fields[key]; !found {
			t.Errorf("missing log field %q in %#v", key, fields)
		}
	}
}

func number(t *testing.T, value any) int {
	t.Helper()
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case string:
		var result int
		if _, err := fmt.Sscan(typed, &result); err != nil {
			t.Fatalf("parse number %q: %v", typed, err)
		}
		return result
	default:
		t.Fatalf("unexpected number type %T", value)
		return 0
	}
}

func intString(value int) string { return fmt.Sprint(value) }

func nonemptyLines(value string) []string {
	var result []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result
}

type failingListener struct{ err error }

func (l *failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *failingListener) Close() error              { return nil }
func (l *failingListener) Addr() net.Addr            { return syntheticAddr("synthetic") }

type syntheticAddr string

func (a syntheticAddr) Network() string { return "synthetic" }
func (a syntheticAddr) String() string  { return string(a) }

func loopbackListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func returnListener(listener net.Listener) ListenFunc {
	return func(string, string) (net.Listener, error) { return listener, nil }
}

func waitReady(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !runtime.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !runtime.Ready() {
		t.Fatal("runtime did not become ready")
	}
}

func TestNoRawServerErrorsReachStandardLogger(t *testing.T) {
	configuration := config.Defaults()
	var logs bytes.Buffer
	runtime, err := New(configuration, &logs)
	if err != nil {
		t.Fatal(err)
	}
	runtime.httpServer.ErrorLog.Print("secret raw server error")
	if strings.Contains(logs.String(), "secret raw server error") {
		t.Errorf("standard server logger bypassed redaction: %s", logs.String())
	}
}

func TestShutdownContextIsBounded(t *testing.T) {
	configuration := config.Defaults()
	runtime, err := New(configuration, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtime.shutdownContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > ShutdownTimeout || time.Until(deadline) <= 0 {
		t.Errorf("shutdown deadline is not bounded: %v, %t", deadline, ok)
	}
}
