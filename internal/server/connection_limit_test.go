package server

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

func TestBoundedListenerCompiledLimitAndPermitReuse(t *testing.T) {
	if MaxConnections != 128 {
		t.Fatalf("MaxConnections = %d, want 128", MaxConnections)
	}
	underlying := newScriptedListener(MaxConnections + 1)
	for index := 0; index < MaxConnections+1; index++ {
		underlying.enqueue(&trackedConn{}, nil)
	}
	listener := newBoundedListener(underlying, MaxConnections)
	connections := make([]net.Conn, MaxConnections)
	for index := range connections {
		connection, err := listener.Accept()
		if err != nil {
			t.Fatalf("accept %d: %v", index, err)
		}
		connections[index] = connection
	}
	if got := underlying.acceptCalls.Load(); got != MaxConnections {
		t.Fatalf("underlying Accept calls = %d, want %d", got, MaxConnections)
	}

	type acceptResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan acceptResult, 1)
	go func() {
		connection, err := listener.Accept()
		result <- acceptResult{connection: connection, err: err}
	}()
	select {
	case unexpected := <-result:
		t.Fatalf("accepted beyond compiled limit: %#v", unexpected)
	case <-time.After(25 * time.Millisecond):
	}
	if got := underlying.acceptCalls.Load(); got != MaxConnections {
		t.Fatalf("underlying accepted beyond limit: calls = %d", got)
	}

	if err := connections[0].Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case accepted := <-result:
		if accepted.err != nil || accepted.connection == nil {
			t.Fatalf("accept after permit reuse: %#v", accepted)
		}
		_ = accepted.connection.Close()
	case <-time.After(time.Second):
		t.Fatal("released permit was not reused")
	}
	for _, connection := range connections[1:] {
		_ = connection.Close()
	}
	_ = listener.Close()
}

func TestBoundedConnectionDoubleCloseReleasesExactlyOnce(t *testing.T) {
	first := &trackedConn{}
	second := &trackedConn{}
	underlying := newScriptedListener(2)
	underlying.enqueue(first, nil)
	underlying.enqueue(second, nil)
	listener := newBoundedListener(underlying, 1)
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		next, _ := listener.Accept()
		accepted <- next
	}()
	select {
	case <-accepted:
		t.Fatal("second connection bypassed the permit")
	case <-time.After(25 * time.Millisecond):
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if got := first.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	select {
	case next := <-accepted:
		if next == nil {
			t.Fatal("second connection was not accepted after release")
		}
		_ = next.Close()
	case <-time.After(time.Second):
		t.Fatal("double-close test did not reuse permit")
	}
	if got := underlying.acceptCalls.Load(); got != 2 {
		t.Fatalf("underlying Accept calls = %d, want 2", got)
	}
	_ = listener.Close()
}

func TestBoundedListenerReleasesPermitAfterUnderlyingAcceptError(t *testing.T) {
	underlying := newScriptedListener(2)
	underlying.enqueue(nil, errors.New("synthetic accept failure"))
	underlying.enqueue(&trackedConn{}, nil)
	listener := newBoundedListener(underlying, 1)
	if connection, err := listener.Accept(); err == nil || connection != nil {
		t.Fatalf("first Accept = (%v, %v), want error", connection, err)
	}
	connection, err := listener.Accept()
	if err != nil || connection == nil {
		t.Fatalf("second Accept = (%v, %v), want connection", connection, err)
	}
	_ = connection.Close()
	_ = listener.Close()
}

func TestBoundedListenerCloseUnblocksPermitWaiters(t *testing.T) {
	underlying := newScriptedListener(1)
	underlying.enqueue(&trackedConn{}, nil)
	listener := newBoundedListener(underlying, 1)
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept()
		waiting <- acceptErr
	}()
	select {
	case <-waiting:
		t.Fatal("permit waiter returned before listener close")
	case <-time.After(25 * time.Millisecond):
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case acceptErr := <-waiting:
		if !errors.Is(acceptErr, net.ErrClosed) {
			t.Fatalf("waiting Accept error = %v, want net.ErrClosed", acceptErr)
		}
	case <-time.After(time.Second):
		t.Fatal("listener Close did not unblock permit waiter")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if got := underlying.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}
	_ = connection.Close()
}

func TestBoundedListenerConcurrentAcceptCloseIsRaceSafe(t *testing.T) {
	const (
		limit = 8
		total = 256
	)
	underlying := newScriptedListener(total)
	for index := 0; index < total; index++ {
		underlying.enqueue(&trackedConn{}, nil)
	}
	listener := newBoundedListener(underlying, limit)
	var active atomic.Int64
	var maximum atomic.Int64
	var group sync.WaitGroup
	for index := 0; index < total; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			connection, err := listener.Accept()
			if err != nil {
				t.Errorf("Accept: %v", err)
				return
			}
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			time.Sleep(time.Microsecond)
			active.Add(-1)
			if err := connection.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	group.Wait()
	if got := maximum.Load(); got > limit {
		t.Fatalf("maximum concurrent accepted connections = %d, want at most %d", got, limit)
	}
	if got := underlying.acceptCalls.Load(); got != total {
		t.Fatalf("underlying Accept calls = %d, want %d", got, total)
	}
	_ = listener.Close()
}

func TestRuntimeCompiledConnectionLimitOnLoopback(t *testing.T) {
	listener := loopbackListener(t)
	configuration := config.Defaults()
	configuration.Server.ReadHeaderTimeout = 5 * time.Second
	runtime, err := New(configuration, io.Discard, WithListen(returnListener(listener)), WithShutdownTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	runtime.httpServer.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	signals := make(chan os.Signal, 1)
	exit := make(chan int, 1)
	go func() { exit <- runtime.ListenAndServe("ignored", signals) }()
	waitReady(t, runtime)

	connections := make([]net.Conn, 0, MaxConnections+1)
	t.Cleanup(func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
	for index := 0; index < MaxConnections; index++ {
		connection, dialErr := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if dialErr != nil {
			t.Fatalf("dial %d: %v", index, dialErr)
		}
		connections = append(connections, connection)
	}
	waitForCount(t, &accepted, MaxConnections)

	overflow, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial queued overflow connection: %v", err)
	}
	connections = append(connections, overflow)
	time.Sleep(50 * time.Millisecond)
	if got := accepted.Load(); got != MaxConnections {
		t.Fatalf("accepted connections = %d, want bound %d before permit release", got, MaxConnections)
	}
	if err := connections[0].Close(); err != nil {
		t.Fatal(err)
	}
	waitForCount(t, &accepted, MaxConnections+1)

	for _, connection := range connections[1:] {
		_ = connection.Close()
	}
	signals <- os.Interrupt
	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("runtime exit = %d, want 0", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not stop after connection-bound smoke")
	}
}

func waitForCount(t *testing.T, value *atomic.Int64, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for value.Load() != int64(want) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := value.Load(); got != int64(want) {
		t.Fatalf("count = %d, want %d", got, want)
	}
}

type scriptedAccept struct {
	connection net.Conn
	err        error
}

type scriptedListener struct {
	results     chan scriptedAccept
	closed      chan struct{}
	closeOnce   sync.Once
	acceptCalls atomic.Int64
	closeCalls  atomic.Int64
}

func newScriptedListener(capacity int) *scriptedListener {
	return &scriptedListener{
		results: make(chan scriptedAccept, capacity),
		closed:  make(chan struct{}),
	}
}

func (listener *scriptedListener) enqueue(connection net.Conn, err error) {
	listener.results <- scriptedAccept{connection: connection, err: err}
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	listener.acceptCalls.Add(1)
	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	case result := <-listener.results:
		return result.connection, result.err
	}
}

func (listener *scriptedListener) Close() error {
	listener.closeOnce.Do(func() {
		listener.closeCalls.Add(1)
		close(listener.closed)
	})
	return nil
}

func (listener *scriptedListener) Addr() net.Addr { return syntheticAddr("scripted") }

type trackedConn struct {
	closeCalls atomic.Int64
}

func (connection *trackedConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (connection *trackedConn) Write(data []byte) (int, error)   { return len(data), nil }
func (connection *trackedConn) LocalAddr() net.Addr              { return syntheticAddr("local") }
func (connection *trackedConn) RemoteAddr() net.Addr             { return syntheticAddr("remote") }
func (connection *trackedConn) SetDeadline(time.Time) error      { return nil }
func (connection *trackedConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *trackedConn) SetWriteDeadline(time.Time) error { return nil }
func (connection *trackedConn) Close() error {
	connection.closeCalls.Add(1)
	return nil
}
