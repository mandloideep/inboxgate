package turso

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const ambientCredentialText = "turso fork tests refuse ambient live configuration"

func TestMain(m *testing.M) {
	_, databaseURLSet := os.LookupEnv("TURSO_DATABASE_URL")
	_, authTokenSet := os.LookupEnv("TURSO_AUTH_TOKEN")
	if databaseURLSet || authTokenSet {
		_, _ = fmt.Fprintln(os.Stderr, ambientCredentialText)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

type stalledCloseHarness struct {
	server        *httptest.Server
	closeStarted  chan struct{}
	requestDone   chan struct{}
	contextDone   chan struct{}
	release       chan struct{}
	releaseOnce   sync.Once
	closeRequests atomic.Int32
	badRequest    atomic.Bool
}

func newStalledCloseHarness(t *testing.T) *stalledCloseHarness {
	t.Helper()
	harness := &stalledCloseHarness{
		closeStarted: make(chan struct{}, 1),
		requestDone:  make(chan struct{}, 1),
		contextDone:  make(chan struct{}, 1),
		release:      make(chan struct{}),
	}
	harness.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v3/cursor":
			_, _ = io.WriteString(response, "{\"baton\":\"synthetic-baton\"}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_begin\",\"step\":0}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_end\",\"step\":0}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_begin\",\"step\":1}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_end\",\"step\":1}\n")
		case "/v3/pipeline":
			body, err := io.ReadAll(io.LimitReader(request.Body, 4097))
			if err != nil || len(body) > 4096 || !bytes.Equal(body, []byte(`{"baton":"synthetic-baton","requests":[{"type":"close"}]}`)) {
				harness.badRequest.Store(true)
				http.Error(response, "invalid synthetic close request", http.StatusBadRequest)
				return
			}
			harness.closeRequests.Add(1)
			harness.closeStarted <- struct{}{}
			select {
			case <-request.Context().Done():
				harness.contextDone <- struct{}{}
			case <-harness.release:
			}
			harness.requestDone <- struct{}{}
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(harness.server.Close)
	t.Cleanup(func() {
		harness.releaseAll()
		harness.server.CloseClientConnections()
	})
	return harness
}

func (h *stalledCloseHarness) releaseAll() {
	h.releaseOnce.Do(func() { close(h.release) })
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("did not observe %s within the scheduler allowance", description)
	}
}

func openStalledConnector(t *testing.T, harness *stalledCloseHarness) (*Connector, *sql.DB) {
	t.Helper()
	connector, err := NewConnectorWithCloseTimeout(harness.server.URL, "", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectorWithCloseTimeout() error = %v", err)
	}
	database := sql.OpenDB(connector)
	database.SetMaxIdleConns(2)
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() error = %v", err)
	}
	return connector, database
}

func TestConnectorCloseContextCancelsJoinsAndRejectsAdmission(t *testing.T) {
	harness := newStalledCloseHarness(t)
	connector, database := openStalledConnector(t, harness)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := connector.CloseContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want deadline", err)
	}
	waitForSignal(t, harness.contextDone, "close request Context.Done")
	waitForSignal(t, harness.requestDone, "close request completion")
	if harness.badRequest.Load() {
		t.Fatal("close request did not match the fixed bounded pipeline body")
	}
	if got := harness.closeRequests.Load(); got != 1 {
		t.Fatalf("close requests = %d, want 1", got)
	}
	connector.mu.Lock()
	connections := len(connector.connections)
	connector.mu.Unlock()
	if connections != 0 {
		t.Fatalf("registered connections at return = %d, want 0", connections)
	}
	if closeErr := database.Close(); closeErr != err || !errors.Is(closeErr, context.DeadlineExceeded) {
		t.Fatalf("database.Close() error = %v, want exact saved deadline %v", closeErr, err)
	}
	if got := harness.closeRequests.Load(); got != 1 {
		t.Fatalf("database.Close() repeated close request: %d", got)
	}
	connection, err := connector.Connect(context.Background())
	if connection != nil || !errors.Is(err, ErrTursoConnClosed) {
		t.Fatalf("Connect() after shutdown = (%T, %v), want ErrTursoConnClosed", connection, err)
	}
}

func TestConnectorRejectsInvalidCloseTimeout(t *testing.T) {
	for _, duration := range []time.Duration{0, -time.Nanosecond, maximumCloseTimeout + time.Nanosecond} {
		connector, err := NewConnectorWithCloseTimeout("http://127.0.0.1:1", "", duration)
		if connector != nil || !errors.Is(err, ErrInvalidCloseTimeout) {
			t.Fatalf("NewConnectorWithCloseTimeout(%v) = (%T, %v), want ErrInvalidCloseTimeout", duration, connector, err)
		}
	}
	connector, err := NewConnectorWithCloseTimeout("http://127.0.0.1:1", "", 10*time.Second)
	if err != nil || connector == nil || connector.closeTimeout != 10*time.Second {
		t.Fatalf("NewConnectorWithCloseTimeout(10s) = (%T, %v), want exact accepted maximum", connector, err)
	}
}

func TestConcurrentConnectorCloseContextCallersShareOneTerminalResult(t *testing.T) {
	const callers = 32
	harness := newStalledCloseHarness(t)
	connector, database := openStalledConnector(t, harness)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			results <- connector.CloseContext(ctx)
		}()
	}
	close(start)
	waitForSignal(t, harness.closeStarted, "one close request start")
	cancel()

	var terminal error
	for range callers {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("concurrent CloseContext() error = %v, want caller cancellation", err)
			}
			if terminal == nil {
				terminal = err
			} else if err != terminal {
				t.Fatalf("concurrent CloseContext() error = %v, want identical terminal error %v", err, terminal)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent CloseContext() caller did not join")
		}
	}
	waitForSignal(t, harness.contextDone, "close request Context.Done")
	waitForSignal(t, harness.requestDone, "close request completion")
	if err := connector.CloseContext(context.Background()); err != terminal {
		t.Fatalf("sequential CloseContext() error = %v, want identical terminal error %v", err, terminal)
	}
	if err := database.Close(); err != terminal {
		t.Fatalf("database.Close() error = %v, want identical terminal error %v", err, terminal)
	}
	if got := harness.closeRequests.Load(); got != 1 {
		t.Fatalf("close requests = %d, want exactly 1 without replay", got)
	}
	connector.mu.Lock()
	connections := len(connector.connections)
	connector.mu.Unlock()
	if connections != 0 {
		t.Fatalf("registered connections = %d, want 0", connections)
	}
	connection, err := connector.Connect(context.Background())
	if connection != nil || !errors.Is(err, ErrTursoConnClosed) {
		t.Fatalf("Connect() after concurrent shutdown = (%T, %v), want ErrTursoConnClosed", connection, err)
	}
}

type observedGlobalTransport struct {
	transport     *http.Transport
	closeIdleCall atomic.Int32
}

func (t *observedGlobalTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(request)
}

func (t *observedGlobalTransport) CloseIdleConnections() {
	t.closeIdleCall.Add(1)
	t.transport.CloseIdleConnections()
}

func TestSessionCloseOwnsTransportAndReleasesItsIdleConnection(t *testing.T) {
	connectionClosed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 4097))
		if err != nil || len(body) > 4096 || !bytes.Equal(body, []byte(`{"baton":"synthetic-baton","requests":[{"type":"close"}]}`)) {
			http.Error(response, "invalid synthetic close request", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(response, `{"baton":null,"base_url":null,"results":[{"type":"ok","response":{"type":"close"}}]}`)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case connectionClosed <- struct{}{}:
			default:
			}
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	originalDefaultTransport := http.DefaultTransport
	global := &observedGlobalTransport{transport: &http.Transport{}}
	http.DefaultTransport = global
	t.Cleanup(func() {
		http.DefaultTransport = originalDefaultTransport
		global.transport.CloseIdleConnections()
	})

	session := newSession(server.URL, "", "")
	baton := "synthetic-baton"
	session.baton = &baton
	if err := session.close(context.Background()); err != nil {
		t.Fatalf("session.close() error = %v", err)
	}
	owned, ok := session.client.Transport.(*http.Transport)
	if !ok || owned == nil {
		t.Fatalf("session transport = %T, want an owned standard-library transport", session.client.Transport)
	}
	if got := global.closeIdleCall.Load(); got != 0 {
		t.Fatalf("global transport CloseIdleConnections calls = %d, want 0", got)
	}
	waitForSignal(t, connectionClosed, "owned idle connection close")
}
