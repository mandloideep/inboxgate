package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

func TestServerRejectsReservedMCPHealthPathWithoutChangingProbes(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, path := range []string{"/health/live", "/health/ready"} {
			configuration := config.Defaults()
			configuration.MCP.Enabled = enabled
			configuration.MCP.Path = path
			handler := &contractMCPHandler{}
			if _, err := New(configuration, io.Discard, WithMCP(handler, handler)); err == nil {
				t.Errorf("enabled=%t reserved path %q constructed runtime", enabled, path)
			}
		}
	}

	configuration := config.Defaults()
	configuration.MCP.Enabled = false
	runtime, err := New(configuration, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		body string
	}{{path: "/health/live", body: liveBody}, {path: "/health/ready", body: notReadyBody}} {
		request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1"+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response := newResponseRecorder()
		runtime.Handler().ServeHTTP(response, request)
		if response.body.String() != test.body {
			t.Errorf("probe %s body = %q, want unchanged %q", test.path, response.body.String(), test.body)
		}
	}
}

type reviewResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newResponseRecorder() *reviewResponseRecorder {
	return &reviewResponseRecorder{header: make(http.Header)}
}

func (recorder *reviewResponseRecorder) Header() http.Header { return recorder.header }

func (recorder *reviewResponseRecorder) WriteHeader(status int) { recorder.status = status }

func (recorder *reviewResponseRecorder) Write(data []byte) (int, error) {
	return recorder.body.Write(data)
}

type blockingMCPShutdown struct {
	requestStarted chan struct{}
	requestDone    chan struct{}
	closeStarted   chan struct{}
	releaseClose   chan struct{}
	requestOnce    sync.Once
	closeOnce      sync.Once
	releaseOnce    sync.Once
}

func newBlockingMCPShutdown() *blockingMCPShutdown {
	return &blockingMCPShutdown{
		requestStarted: make(chan struct{}),
		requestDone:    make(chan struct{}),
		closeStarted:   make(chan struct{}),
		releaseClose:   make(chan struct{}),
	}
}

func (handler *blockingMCPShutdown) ServeHTTP(_ http.ResponseWriter, request *http.Request) {
	handler.requestOnce.Do(func() { close(handler.requestStarted) })
	<-request.Context().Done()
	close(handler.requestDone)
}

func (handler *blockingMCPShutdown) Close() error {
	handler.closeOnce.Do(func() { close(handler.closeStarted) })
	<-handler.releaseClose
	return nil
}

func (handler *blockingMCPShutdown) release() {
	handler.releaseOnce.Do(func() { close(handler.releaseClose) })
}

func TestShutdownDeadlineStartsBeforeMCPDrainAndBoundsWholeShutdown(t *testing.T) {
	listener := loopbackListener(t)
	configuration := config.Defaults()
	configuration.MCP.Enabled = true
	handler := newBlockingMCPShutdown()
	defer handler.release()
	runtime, err := New(configuration, io.Discard, WithListen(returnListener(listener)), WithShutdownTimeout(25*time.Millisecond), WithMCP(handler, handler))
	if err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	exit := make(chan int, 1)
	go func() { exit <- runtime.ListenAndServe("ignored", signals) }()
	waitReady(t, runtime)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+listener.Addr().String()+configuration.MCP.Path, bytes.NewReader([]byte("{}")))
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
	case <-handler.requestStarted:
	case <-time.After(time.Second):
		t.Fatal("active MCP request did not start")
	}

	started := time.Now()
	signals <- os.Interrupt
	select {
	case <-handler.closeStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("MCP close did not start")
	}
	select {
	case code := <-exit:
		if code != 1 {
			t.Fatalf("bounded shutdown exit = %d, want 1 after deadline", code)
		}
		if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
			t.Fatalf("shutdown elapsed %s, want one 25ms deadline", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		handler.release()
		<-exit
		t.Fatal("blocking MCP close escaped the server shutdown deadline")
	}
	select {
	case <-handler.requestDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("server deadline did not cancel active MCP request")
	}
	<-requestDone
}
