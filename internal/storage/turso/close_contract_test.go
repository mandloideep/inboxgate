package turso

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
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
	tursodriver "turso.tech/database/tursogo-serverless"
)

const closeContractTimeout = 20 * time.Millisecond

type closeResponseMode int

const (
	closeResponseSuccess closeResponseMode = iota
	closeResponseStall
	closeResponseHTTPError
	closeResponseMalformed
	closeResponseProtocolError
	closeResponseDroppedBody
)

type closeContractServer struct {
	testing      *testing.T
	server       *httptest.Server
	mode         closeResponseMode
	release      chan struct{}
	releaseOnce  sync.Once
	closeStarted chan struct{}
	requestDone  chan struct{}
	cursorCount  atomic.Int32
	closeCount   atomic.Int32
	activeClose  atomic.Int32
	badRequest   atomic.Bool
}

func newCloseContractServer(t *testing.T, mode closeResponseMode) *closeContractServer {
	t.Helper()
	harness := &closeContractServer{
		testing:      t,
		mode:         mode,
		release:      make(chan struct{}),
		closeStarted: make(chan struct{}, 16),
		requestDone:  make(chan struct{}, 16),
	}
	harness.server = httptest.NewServer(http.HandlerFunc(harness.serveHTTP))
	t.Cleanup(func() {
		harness.releaseAll()
		harness.server.Close()
	})
	return harness
}

func (h *closeContractServer) releaseAll() {
	h.releaseOnce.Do(func() { close(h.release) })
}

func (h *closeContractServer) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "" {
		h.badRequest.Store(true)
	}
	if request.URL.RawQuery != "" || request.URL.User != nil {
		h.badRequest.Store(true)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 16<<10))
	if err != nil || len(body) == 16<<10 {
		h.badRequest.Store(true)
		http.Error(w, "invalid synthetic request", http.StatusBadRequest)
		return
	}

	switch request.URL.Path {
	case "/v3/cursor":
		id := h.cursorCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"baton":"synthetic-baton-`+string(rune('a'+id-1))+`"}`+"\n")
		_, _ = io.WriteString(w, "{\"type\":\"step_begin\",\"step\":0}\n")
		_, _ = io.WriteString(w, "{\"type\":\"step_end\",\"step\":0}\n")
		_, _ = io.WriteString(w, "{\"type\":\"step_begin\",\"step\":1}\n")
		_, _ = io.WriteString(w, "{\"type\":\"step_end\",\"step\":1}\n")
	case "/v3/pipeline":
		var payload struct {
			Requests []struct {
				Type string `json:"type"`
				SQL  string `json:"sql"`
			} `json:"requests"`
		}
		if json.Unmarshal(body, &payload) != nil || len(payload.Requests) != 1 ||
			payload.Requests[0].Type != "close" || payload.Requests[0].SQL != "" {
			h.badRequest.Store(true)
		}
		h.closeCount.Add(1)
		h.activeClose.Add(1)
		h.closeStarted <- struct{}{}
		defer func() {
			h.activeClose.Add(-1)
			h.requestDone <- struct{}{}
		}()

		switch h.mode {
		case closeResponseStall:
			select {
			case <-request.Context().Done():
				return
			case <-h.release:
			}
		case closeResponseHTTPError:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"message":"remote-close-marker synthetic-token /private/path SELECT secret"}`)
			return
		case closeResponseMalformed:
			_, _ = io.WriteString(w, `{"results":`)
			return
		case closeResponseProtocolError:
			_, _ = io.WriteString(w, `{"results":[{"type":"error","error":{"message":"remote-close-marker synthetic-token"}}]}`)
			return
		case closeResponseDroppedBody:
			_, _ = io.WriteString(w, `{"results":[`)
			panic(http.ErrAbortHandler)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"results":[{"type":"ok","response":{"type":"close"}}]}`)
	default:
		http.NotFound(w, request)
	}
}

func openCloseContractHandle(t *testing.T, harness *closeContractServer) storage.Handle {
	t.Helper()
	adapter, err := New(Options{
		PingTimeout:    time.Second,
		CleanupTimeout: closeContractTimeout,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: harness.server.URL})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return handle
}

func physicalDatabase(t *testing.T, value storage.Handle) *sql.DB {
	t.Helper()
	handle, ok := value.(*handle)
	if !ok {
		t.Fatalf("handle type = %T, want package handle", value)
	}
	switch database := handle.database.(type) {
	case *sql.DB:
		return database
	case interface{ sqlDatabase() *sql.DB }:
		return database.sqlDatabase()
	default:
		t.Fatalf("database type = %T, want bounded SQL database", handle.database)
		return nil
	}
}

func initializePhysicalConnections(t *testing.T, database *sql.DB, count int) []*sql.Conn {
	t.Helper()
	connections := make([]*sql.Conn, 0, count)
	for range count {
		connection, err := database.Conn(context.Background())
		if err != nil {
			t.Fatalf("database.Conn() error = %v", err)
		}
		connections = append(connections, connection)
	}
	for _, connection := range connections {
		if err := connection.PingContext(context.Background()); err != nil {
			t.Fatalf("connection PingContext() error = %v", err)
		}
	}
	return connections
}

func waitForCloseStarts(t *testing.T, harness *closeContractServer, count int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for range count {
		select {
		case <-harness.closeStarted:
		case <-deadline.C:
			harness.releaseAll()
			t.Fatalf("observed %d close starts, want %d", harness.closeCount.Load(), count)
		}
	}
}

func waitForCloseRequestDone(t *testing.T, harness *closeContractServer, count int) {
	t.Helper()
	allowance := time.NewTimer(time.Second)
	defer allowance.Stop()
	for range count {
		select {
		case <-harness.requestDone:
		case <-allowance.C:
			t.Fatalf("observed %d completed close requests, want %d", count-int(harness.activeClose.Load()), count)
		}
	}
}

func awaitBoundedHandleClose(t *testing.T, harness *closeContractServer, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		harness.releaseAll()
		err := <-result
		t.Fatalf("Handle.Close() exceeded its owned deadline and returned after release with %v", err)
		return nil
	}
}

func TestHandleCloseCancelsStalledStreamWithinOwnedDeadlineAndJoinsRequest(t *testing.T) {
	harness := newCloseContractServer(t, closeResponseStall)
	handle := openCloseContractHandle(t, harness)
	if err := handle.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	result := make(chan error, 1)
	go func() { result <- handle.Close() }()
	waitForCloseStarts(t, harness, 1)
	err := awaitBoundedHandleClose(t, harness, result)
	if !errors.Is(err, ErrCloseFailed) || err.Error() != ErrCloseFailed.Error() {
		t.Fatalf("Close() error = %v, want fixed ErrCloseFailed", err)
	}
	waitForCloseRequestDone(t, harness, 1)
	if got := harness.activeClose.Load(); got != 0 {
		t.Fatalf("active close requests at return = %d, want 0", got)
	}
	if got := harness.closeCount.Load(); got != 1 {
		t.Fatalf("close requests = %d, want 1 without replay", got)
	}
}

func TestTwoIdleStreamsCloseConcurrentlyUnderOneSharedDeadline(t *testing.T) {
	harness := newCloseContractServer(t, closeResponseStall)
	handle := openCloseContractHandle(t, harness)
	database := physicalDatabase(t, handle)
	connections := initializePhysicalConnections(t, database, 2)
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Fatalf("return connection to idle pool: %v", err)
		}
	}

	result := make(chan error, 1)
	go func() { result <- handle.Close() }()
	waitForCloseStarts(t, harness, 2)
	err := awaitBoundedHandleClose(t, harness, result)
	if !errors.Is(err, ErrCloseFailed) || err.Error() != ErrCloseFailed.Error() {
		t.Fatalf("Close() error = %v, want fixed ErrCloseFailed", err)
	}
	waitForCloseRequestDone(t, harness, 2)
	if got := harness.activeClose.Load(); got != 0 {
		t.Fatalf("active close requests at return = %d, want 0", got)
	}
	if got := harness.closeCount.Load(); got != 2 {
		t.Fatalf("close requests = %d, want one per stream", got)
	}
}

func TestSuccessfulCloseSendsExactlyOneRequestPerStream(t *testing.T) {
	harness := newCloseContractServer(t, closeResponseSuccess)
	handle := openCloseContractHandle(t, harness)
	database := physicalDatabase(t, handle)
	connections := initializePhysicalConnections(t, database, 2)
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Fatalf("return connection to idle pool: %v", err)
		}
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
	if got := harness.closeCount.Load(); got != 2 {
		t.Fatalf("close requests = %d, want one per stream", got)
	}
	if harness.badRequest.Load() {
		t.Fatal("close crossed the credential-free fixed-request boundary")
	}
}

func TestNoBatonAndNeverConnectedHandlesSendNoCloseRequest(t *testing.T) {
	t.Run("never connected", func(t *testing.T) {
		harness := newCloseContractServer(t, closeResponseSuccess)
		handle := openCloseContractHandle(t, harness)
		if err := handle.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if got := harness.closeCount.Load(); got != 0 {
			t.Fatalf("close requests = %d, want 0", got)
		}
	})

	t.Run("connected without baton", func(t *testing.T) {
		harness := newCloseContractServer(t, closeResponseSuccess)
		handle := openCloseContractHandle(t, harness)
		connection, err := physicalDatabase(t, handle).Conn(context.Background())
		if err != nil {
			t.Fatalf("database.Conn() error = %v", err)
		}
		if err := connection.Close(); err != nil {
			t.Fatalf("connection.Close() error = %v", err)
		}
		if err := handle.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if got := harness.closeCount.Load(); got != 0 {
			t.Fatalf("close requests = %d, want 0", got)
		}
	})
}

func TestCloseFailuresAreFixedSensitiveAndNeverReplayed(t *testing.T) {
	tests := []struct {
		name string
		mode closeResponseMode
	}{
		{name: "non-2xx remote text", mode: closeResponseHTTPError},
		{name: "malformed response", mode: closeResponseMalformed},
		{name: "protocol error", mode: closeResponseProtocolError},
		{name: "dropped response body", mode: closeResponseDroppedBody},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newCloseContractServer(t, test.mode)
			handle := openCloseContractHandle(t, harness)
			if err := handle.Ping(context.Background()); err != nil {
				t.Fatalf("Ping() error = %v", err)
			}
			first := handle.Close()
			second := handle.Close()
			if !errors.Is(first, ErrCloseFailed) || first.Error() != ErrCloseFailed.Error() {
				t.Fatalf("first Close() error = %v, want fixed ErrCloseFailed", first)
			}
			if !errors.Is(second, ErrCloseFailed) || second.Error() != ErrCloseFailed.Error() {
				t.Fatalf("second Close() error = %v, want fixed ErrCloseFailed", second)
			}
			for _, sensitive := range []string{"remote-close-marker", "synthetic-token", "/private/path", "SELECT secret", harness.server.URL} {
				if strings.Contains(first.Error(), sensitive) {
					t.Fatalf("Close() error %q reflects sensitive remote input", first)
				}
			}
			if got := harness.closeCount.Load(); got != 1 {
				t.Fatalf("close requests = %d, want 1 without retry", got)
			}
		})
	}
}

func TestConcurrentHandleCloseWaitsForOneTerminalResult(t *testing.T) {
	const callers = 32
	harness := newCloseContractServer(t, closeResponseStall)
	handle := openCloseContractHandle(t, harness)
	if err := handle.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			results <- handle.Close()
		}()
	}
	close(start)
	waitForCloseStarts(t, harness, 1)
	for range callers {
		err := awaitBoundedHandleClose(t, harness, results)
		if !errors.Is(err, ErrCloseFailed) || err.Error() != ErrCloseFailed.Error() {
			t.Fatalf("concurrent Close() error = %v, want fixed ErrCloseFailed", err)
		}
	}
	if got := harness.closeCount.Load(); got != 1 {
		t.Fatalf("close requests = %d, want 1", got)
	}
}

func TestConnectorShutdownRejectsNewConnectionsAndDatabaseCloseDoesNotReplay(t *testing.T) {
	harness := newCloseContractServer(t, closeResponseSuccess)
	connector := tursodriver.NewConnector(harness.server.URL, "")
	closer, ok := any(connector).(interface{ CloseContext(context.Context) error })
	if !ok {
		t.Fatal("selected connector does not expose context-aware shutdown")
	}
	database := sql.OpenDB(connector)
	database.SetMaxIdleConns(2)
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() error = %v", err)
	}
	if err := closer.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if got := harness.closeCount.Load(); got != 1 {
		t.Fatalf("close requests after connector shutdown = %d, want 1", got)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("database.Close() error = %v", err)
	}
	if got := harness.closeCount.Load(); got != 1 {
		t.Fatalf("database.Close() sent a second close request: %d", got)
	}
	connection, err := connector.Connect(context.Background())
	if connection != nil || !errors.Is(err, tursodriver.ErrTursoConnClosed) {
		t.Fatalf("Connect() after shutdown = (%T, %v), want ErrTursoConnClosed", connection, err)
	}
}

func TestConnectorCloseContextPreservesCallerCancellationAndJoins(t *testing.T) {
	harness := newCloseContractServer(t, closeResponseStall)
	connector := tursodriver.NewConnector(harness.server.URL, "")
	closer, ok := any(connector).(interface{ CloseContext(context.Context) error })
	if !ok {
		t.Fatal("selected connector does not expose context-aware shutdown")
	}
	database := sql.OpenDB(connector)
	database.SetMaxIdleConns(2)
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- closer.CloseContext(ctx) }()
	waitForCloseStarts(t, harness, 1)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CloseContext() error = %v, want caller cancellation", err)
		}
	case <-time.After(time.Second):
		harness.releaseAll()
		<-result
		t.Fatal("CloseContext() did not return after caller cancellation")
	}
	waitForCloseRequestDone(t, harness, 1)
	if got := harness.activeClose.Load(); got != 0 {
		t.Fatalf("active close requests at return = %d, want 0", got)
	}
	if err := database.Close(); !errors.Is(err, context.Canceled) {
		t.Fatalf("database.Close() error = %v, want reused terminal cancellation", err)
	}
}

func TestPoolEvictionConnCloseUsesConfiguredFallbackDeadline(t *testing.T) {
	harness := newCloseContractServer(t, closeResponseStall)
	handleValue := openCloseContractHandle(t, harness)
	concrete := handleValue.(*handle)
	database, ok := concrete.database.(*connectorDatabase)
	if !ok {
		t.Fatalf("database type = %T, want connector database", concrete.database)
	}
	connection, err := database.connector.Connect(context.Background())
	if err != nil {
		t.Fatalf("connector.Connect() error = %v", err)
	}
	pinger, ok := connection.(driver.Pinger)
	if !ok {
		t.Fatalf("driver connection type = %T, want driver.Pinger", connection)
	}
	if err := pinger.Ping(context.Background()); err != nil {
		t.Fatalf("driver Ping() error = %v", err)
	}

	result := make(chan error, 1)
	go func() { result <- connection.Close() }()
	waitForCloseStarts(t, harness, 1)
	select {
	case closeErr := <-result:
		if !errors.Is(closeErr, context.DeadlineExceeded) {
			t.Fatalf("pool-eviction driver.Conn.Close() error = %v, want configured deadline", closeErr)
		}
	case <-time.After(time.Second):
		harness.releaseAll()
		<-result
		t.Fatal("pool-eviction driver.Conn.Close() exceeded its configured fallback deadline")
	}
	waitForCloseRequestDone(t, harness, 1)
	if got := harness.activeClose.Load(); got != 0 {
		t.Fatalf("active close requests at return = %d, want 0", got)
	}
	if err := handleValue.Close(); !errors.Is(err, ErrCloseFailed) {
		t.Fatalf("Handle.Close() after failed eviction = %v, want fixed ErrCloseFailed", err)
	}
}

func TestConnectorCloseContextInterfaceIsNarrow(t *testing.T) {
	type boundedConnector interface {
		driver.Connector
		CloseContext(context.Context) error
	}
	var connector driver.Connector = tursodriver.NewConnector("http://127.0.0.1:1", "")
	if _, ok := connector.(boundedConnector); !ok {
		t.Fatal("selected connector does not implement the narrow context-aware close contract")
	}
}
