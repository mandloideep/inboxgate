// Package storage defines the replaceable connection boundary used by
// InboxGate persistence implementations.
package storage

import "context"

// Endpoint carries connection material acquired by a caller.
//
// URL and Token remain separate so implementations do not need to place a
// credential in a connection string.
type Endpoint struct {
	URL   string
	Token string
}

// Adapter opens a bounded storage handle without exposing driver-specific
// connector or database types to consumers.
type Adapter interface {
	Open(context.Context, Endpoint) (Handle, error)
}

// Handle is the minimum connection lifecycle needed by the storage
// feasibility boundary.
type Handle interface {
	Ping(context.Context) error
	Close() error
}
