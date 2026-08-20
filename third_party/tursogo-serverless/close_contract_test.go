package turso

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectorCloseContextCancelsJoinsAndRejectsAdmission(t *testing.T) {
	requestDone := make(chan struct{})
	var closeRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v3/cursor":
			_, _ = io.WriteString(response, "{\"baton\":\"synthetic-baton\"}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_begin\",\"step\":0}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_end\",\"step\":0}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_begin\",\"step\":1}\n")
			_, _ = io.WriteString(response, "{\"type\":\"step_end\",\"step\":1}\n")
		case "/v3/pipeline":
			closeRequests.Add(1)
			<-request.Context().Done()
			close(requestDone)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	connector, err := NewConnectorWithCloseTimeout(server.URL, "", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConnectorWithCloseTimeout() error = %v", err)
	}
	database := sql.OpenDB(connector)
	database.SetMaxIdleConns(2)
	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = connector.CloseContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want deadline", err)
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("close request did not propagate cancellation within the scheduler allowance")
	}
	if got := closeRequests.Load(); got != 1 {
		t.Fatalf("close requests = %d, want 1", got)
	}
	connector.mu.Lock()
	connections := len(connector.connections)
	connector.mu.Unlock()
	if connections != 0 {
		t.Fatalf("registered connections at return = %d, want 0", connections)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("database.Close() error = %v", err)
	}
	if got := closeRequests.Load(); got != 1 {
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
}
