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

// Handle exposes connection lifecycle and embedded schema reconciliation
// without exposing a database handle or caller-supplied SQL.
type Handle interface {
	Ping(context.Context) error
	Migrate(context.Context) (MigrationResult, error)
	EnsureAccount(context.Context, AccountSeed) (Account, error)
	GetSynchronizationCursor(context.Context, AccountID) (SynchronizationCursor, error)
	CommitSynchronization(context.Context, SynchronizationCommit) error
	Close() error
}

// MigrationResult is the bounded outcome of reconciling the embedded schema.
type MigrationResult struct {
	Applied uint16
	Current uint16
}
