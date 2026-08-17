package server

import (
	"net"
	"sync"
)

const MaxConnections = 128

type boundedListener struct {
	net.Listener
	permits   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newBoundedListener(listener net.Listener, limit int) *boundedListener {
	if limit < 1 {
		panic("connection limit must be positive")
	}
	return &boundedListener{
		Listener: listener,
		permits:  make(chan struct{}, limit),
		closed:   make(chan struct{}),
	}
}

func (listener *boundedListener) Accept() (net.Conn, error) {
	select {
	case <-listener.closed:
		return nil, net.ErrClosed
	case listener.permits <- struct{}{}:
	}

	select {
	case <-listener.closed:
		listener.release()
		return nil, net.ErrClosed
	default:
	}

	connection, err := listener.Listener.Accept()
	if err != nil {
		listener.release()
		return nil, err
	}
	return &boundedConnection{Conn: connection, release: listener.release}, nil
}

func (listener *boundedListener) Close() error {
	listener.closeOnce.Do(func() {
		close(listener.closed)
		listener.closeErr = listener.Listener.Close()
	})
	return listener.closeErr
}

func (listener *boundedListener) release() {
	<-listener.permits
}

type boundedConnection struct {
	net.Conn
	release   func()
	closeOnce sync.Once
	closeErr  error
}

func (connection *boundedConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.closeErr = connection.Conn.Close()
		connection.release()
	})
	return connection.closeErr
}
