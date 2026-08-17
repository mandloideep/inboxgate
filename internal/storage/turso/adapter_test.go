package turso

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/storage"
)

func TestOpenSeparatesURLAndTokenAtDriverBoundary(t *testing.T) {
	t.Parallel()

	database := &fakeDatabase{}
	var gotURL string
	var gotToken string
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(url, token string) databaseHandle {
		gotURL = url
		gotToken = token
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}

	handle, err := adapter.Open(context.Background(), storage.Endpoint{
		URL:   "turso://database.example",
		Token: "synthetic-token",
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	if gotURL != "https://database.example" {
		t.Fatalf("driver URL = %q, want normalized URL", gotURL)
	}
	if gotToken != "synthetic-token" {
		t.Fatalf("driver token = %q, want separate token", gotToken)
	}
	if strings.Contains(gotURL, gotToken) {
		t.Fatal("driver URL contains token")
	}
}

func TestOpenRejectsUnsafeEndpointsWithoutCallingDriver(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint storage.Endpoint
	}{
		{name: "empty", endpoint: storage.Endpoint{}},
		{name: "userinfo", endpoint: storage.Endpoint{URL: "https://user:pass@database.example"}},
		{name: "query", endpoint: storage.Endpoint{URL: "https://database.example?auth_token=secret"}},
		{name: "fragment", endpoint: storage.Endpoint{URL: "https://database.example/#secret"}},
		{name: "path", endpoint: storage.Endpoint{URL: "https://database.example/database"}},
		{name: "unsupported scheme", endpoint: storage.Endpoint{URL: "ftp://database.example"}},
		{name: "remote cleartext", endpoint: storage.Endpoint{URL: "http://database.example"}},
		{name: "loopback token", endpoint: storage.Endpoint{URL: "http://127.0.0.1:8080", Token: "synthetic-token"}},
		{name: "localhost name", endpoint: storage.Endpoint{URL: "http://localhost:8080"}},
		{name: "missing host", endpoint: storage.Endpoint{URL: "https:///database"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
				calls.Add(1)
				return &fakeDatabase{}
			})
			if err != nil {
				t.Fatalf("newAdapter() error = %v", err)
			}

			_, err = adapter.Open(context.Background(), tt.endpoint)
			if !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("Open() error = %v, want ErrInvalidEndpoint", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("driver called %d times, want 0", calls.Load())
			}
			for _, secret := range []string{tt.endpoint.URL, tt.endpoint.Token} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q reflects endpoint input", err)
				}
			}
		})
	}
}

func TestNewRejectsUnboundedOptions(t *testing.T) {
	t.Parallel()

	tests := []Options{
		{PingTimeout: -time.Second},
		{PingTimeout: maximumPingTimeout + time.Second},
		{MigrationTimeout: -time.Second},
		{MigrationTimeout: maximumMigrationTimeout + time.Second},
		{CleanupTimeout: -time.Second},
		{CleanupTimeout: maximumCleanupTimeout + time.Second},
	}
	for _, options := range tests {
		if _, err := New(options); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("New(%#v) error = %v, want ErrInvalidOptions", options, err)
		}
	}
}

func TestOpenAcceptsSupportedEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		endpoint   storage.Endpoint
		wantDriver string
	}{
		{name: "turso", endpoint: storage.Endpoint{URL: "turso://database.example", Token: "synthetic-token"}, wantDriver: "https://database.example"},
		{name: "https", endpoint: storage.Endpoint{URL: "https://database.example", Token: "synthetic-token"}, wantDriver: "https://database.example"},
		{name: "ipv4 loopback", endpoint: storage.Endpoint{URL: "http://127.0.0.1:8080"}, wantDriver: "http://127.0.0.1:8080"},
		{name: "ipv6 loopback", endpoint: storage.Endpoint{URL: "http://[::1]:8080"}, wantDriver: "http://[::1]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotURL string
			adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(url, _ string) databaseHandle {
				gotURL = url
				return &fakeDatabase{}
			})
			if err != nil {
				t.Fatalf("newAdapter() error = %v", err)
			}

			handle, err := adapter.Open(context.Background(), tt.endpoint)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			t.Cleanup(func() { _ = handle.Close() })
			if gotURL != tt.wantDriver {
				t.Fatalf("driver URL = %q, want %q", gotURL, tt.wantDriver)
			}
		})
	}
}

func TestOpenCanceledContextDoesNotCallDriver(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
		calls.Add(1)
		return &fakeDatabase{}
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = adapter.Open(ctx, storage.Endpoint{
		URL:   "https://private.example/path",
		Token: "synthetic-token",
	})
	if !errors.Is(err, ErrOpenFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want safe cancellation", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("driver called %d times, want 0", calls.Load())
	}
	for _, raw := range []string{"https://private.example/path", "synthetic-token"} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("Open() error %q reflects caller input", err)
		}
	}
}

func TestPingUsesAdapterDeadlineAndReturnsSafeDiagnostic(t *testing.T) {
	t.Parallel()

	raw := "raw-upstream-error synthetic-token https://private.example/path"
	database := &fakeDatabase{ping: func(ctx context.Context) error {
		<-ctx.Done()
		return errors.New(raw)
	}}
	adapter, err := newAdapter(Options{PingTimeout: 20 * time.Millisecond}, func(string, string) databaseHandle {
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "https://database.example", Token: "synthetic-token"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	started := time.Now()
	err = handle.Ping(context.Background())
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Ping() elapsed = %v, want bounded call", elapsed)
	}
	if !errors.Is(err, ErrPingFailed) {
		t.Fatalf("Ping() error = %v, want ErrPingFailed", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping() error = %v, want context deadline", err)
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("Ping() error %q reflects upstream diagnostic", err)
	}
}

func TestPingPreservesShorterCallerCancellation(t *testing.T) {
	t.Parallel()

	database := &fakeDatabase{ping: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "https://database.example"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = handle.Ping(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Ping() error = %v, want context.Canceled", err)
	}
}

func TestPingCancellationAfterRequestStartsReturnsPromptlyAndSafely(t *testing.T) {
	t.Parallel()

	raw := "raw cancellation diagnostic synthetic-token https://private.example/path"
	started := make(chan struct{})
	database := &fakeDatabase{ping: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return errors.New(raw)
	}}
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "https://database.example"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- handle.Ping(ctx)
	}()
	<-started
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, ErrPingFailed) || !errors.Is(err, context.Canceled) {
			t.Fatalf("Ping() error = %v, want safe caller cancellation", err)
		}
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("Ping() error %q reflects upstream diagnostic", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Ping() did not return promptly after caller cancellation")
	}
}

func TestPingSanitizesRemoteFailure(t *testing.T) {
	t.Parallel()

	raw := "remote marker synthetic-token /private/path SELECT secret"
	database := &fakeDatabase{ping: func(context.Context) error { return errors.New(raw) }}
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "https://database.example", Token: "synthetic-token"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	err = handle.Ping(context.Background())
	if !errors.Is(err, ErrPingFailed) {
		t.Fatalf("Ping() error = %v, want ErrPingFailed", err)
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("Ping() error %q reflects upstream diagnostic", err)
	}
}

func TestCloseIsIdempotentAndSanitizesFailure(t *testing.T) {
	t.Parallel()

	database := &fakeDatabase{closeErr: errors.New("raw close marker synthetic-token")}
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "https://database.example", Token: "synthetic-token"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	first := handle.Close()
	second := handle.Close()
	if !errors.Is(first, ErrCloseFailed) || !errors.Is(second, ErrCloseFailed) {
		t.Fatalf("Close() errors = (%v, %v), want ErrCloseFailed", first, second)
	}
	if first.Error() != second.Error() {
		t.Fatalf("Close() errors differ: %q != %q", first, second)
	}
	if strings.Contains(first.Error(), "raw close marker") {
		t.Fatalf("Close() error %q reflects upstream diagnostic", first)
	}
	if database.closeCalls.Load() != 1 {
		t.Fatalf("database Close() calls = %d, want 1", database.closeCalls.Load())
	}
}

func TestConcurrentCloseCallsUnderlyingOnceAndReturnsSameSafeResult(t *testing.T) {
	t.Parallel()

	const callers = 32
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	database := &fakeDatabase{close: func() error {
		close(closeStarted)
		<-releaseClose
		return errors.New("raw concurrent close diagnostic synthetic-token")
	}}
	adapter, err := newAdapter(Options{PingTimeout: time.Second}, func(string, string) databaseHandle {
		return database
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: "https://database.example"})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	start := make(chan struct{})
	entered := make(chan struct{}, callers)
	results := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			entered <- struct{}{}
			results <- handle.Close()
		}()
	}
	ready.Wait()
	close(start)
	<-closeStarted
	for range callers {
		<-entered
	}
	close(releaseClose)

	for range callers {
		err := <-results
		if !errors.Is(err, ErrCloseFailed) {
			t.Fatalf("Close() error = %v, want ErrCloseFailed", err)
		}
		if err.Error() != ErrCloseFailed.Error() {
			t.Fatalf("Close() error = %q, want %q", err, ErrCloseFailed)
		}
		if strings.Contains(err.Error(), "raw concurrent close diagnostic") {
			t.Fatalf("Close() error %q reflects upstream diagnostic", err)
		}
	}
	if database.closeCalls.Load() != 1 {
		t.Fatalf("database Close() calls = %d, want 1", database.closeCalls.Load())
	}
}

func TestCredentialFreeLoopbackProtocol(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header = %q, want empty", got)
		}
		if r.URL.RawQuery != "" || r.URL.User != nil {
			t.Errorf("request URL = %q, want no credentials or query", r.URL.String())
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		if len(body) == 16<<10 {
			t.Error("request exceeded test bound")
			return
		}

		switch r.URL.Path {
		case "/v3/cursor":
			if !strings.Contains(string(body), `"sql":"SELECT 1"`) {
				t.Errorf("ping request body = %s, want fixed SELECT 1", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{\"baton\":\"synthetic-baton\"}\n")
			_, _ = io.WriteString(w, "{\"type\":\"step_begin\",\"step\":0}\n")
			_, _ = io.WriteString(w, "{\"type\":\"step_end\",\"step\":0}\n")
			_, _ = io.WriteString(w, "{\"type\":\"step_begin\",\"step\":1}\n")
			_, _ = io.WriteString(w, "{\"type\":\"step_end\",\"step\":1}\n")
		case "/v3/pipeline":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, "{\"results\":[{\"type\":\"ok\",\"response\":{\"type\":\"close\"}}]}")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	adapter, err := New(Options{PingTimeout: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := handle.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want ping and stream close", requests.Load())
	}
}

func TestCredentialFreeLoopbackRemoteErrorIsSanitized(t *testing.T) {
	t.Parallel()

	raw := "raw remote marker synthetic-token /private/path SELECT secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"message":"`+raw+`"}`)
	}))
	t.Cleanup(server.Close)

	adapter, err := New(Options{PingTimeout: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	err = handle.Ping(context.Background())
	if !errors.Is(err, ErrPingFailed) {
		t.Fatalf("Ping() error = %v, want ErrPingFailed", err)
	}
	if strings.Contains(err.Error(), raw) {
		t.Fatalf("Ping() error %q reflects upstream diagnostic", err)
	}
}

func TestCredentialFreeLoopbackPingIsBounded(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		http.Error(w, "released after client deadline", http.StatusGatewayTimeout)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	adapter, err := New(Options{PingTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: server.URL})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	started := time.Now()
	err = handle.Ping(context.Background())
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Ping() elapsed = %v, want bounded call", elapsed)
	}
	if !errors.Is(err, ErrPingFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping() error = %v, want safe deadline failure", err)
	}
}

type fakeDatabase struct {
	ping       func(context.Context) error
	conn       func(context.Context) (*sql.Conn, error)
	close      func() error
	closeErr   error
	connCalls  atomic.Int32
	closeCalls atomic.Int32
}

func (d *fakeDatabase) PingContext(ctx context.Context) error {
	if d.ping == nil {
		return nil
	}
	return d.ping(ctx)
}

func (d *fakeDatabase) Conn(ctx context.Context) (*sql.Conn, error) {
	d.connCalls.Add(1)
	if d.conn != nil {
		return d.conn(ctx)
	}
	return nil, errors.New("synthetic connection unavailable")
}

func (d *fakeDatabase) Close() error {
	d.closeCalls.Add(1)
	if d.close != nil {
		return d.close()
	}
	return d.closeErr
}
