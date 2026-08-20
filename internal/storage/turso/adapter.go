// Package turso implements the InboxGate storage adapter with the official
// remote Turso Database driver.
//
// The adapter is intentionally inert until a caller supplies an endpoint and
// invokes it. It does not read configuration or environment variables.
package turso

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mandloideep/inboxgate/internal/storage"
	tursodriver "turso.tech/database/tursogo-serverless"
)

const (
	defaultPingTimeout        = 5 * time.Second
	maximumPingTimeout        = 30 * time.Second
	defaultMigrationTimeout   = 30 * time.Second
	maximumMigrationTimeout   = 2 * time.Minute
	defaultCleanupTimeout     = 2 * time.Second
	maximumCleanupTimeout     = 10 * time.Second
	defaultPersistenceTimeout = 30 * time.Second
	maximumPersistenceTimeout = 2 * time.Minute
	maximumIdleConnections    = 2
)

var (
	// ErrInvalidOptions reports adapter policy that cannot provide a bounded
	// operation.
	ErrInvalidOptions = errors.New("turso storage: invalid options")
	// ErrInvalidEndpoint reports a rejected endpoint without reflecting any
	// caller-provided URL or token.
	ErrInvalidEndpoint = errors.New("turso storage: invalid endpoint")
	// ErrOpenFailed reports that a handle could not be opened safely.
	ErrOpenFailed = errors.New("turso storage: open failed")
	// ErrPingFailed reports a failed connectivity probe without exposing an
	// upstream diagnostic.
	ErrPingFailed = errors.New("turso storage: ping failed")
	// ErrCloseFailed reports a failed close without exposing an upstream
	// diagnostic.
	ErrCloseFailed = errors.New("turso storage: close failed")
)

// Options controls adapter-owned operation bounds.
type Options struct {
	PingTimeout        time.Duration
	MigrationTimeout   time.Duration
	CleanupTimeout     time.Duration
	PersistenceTimeout time.Duration
}

// Adapter opens remote Turso Database handles behind the repository-owned
// storage contract.
type Adapter struct {
	pingTimeout        time.Duration
	migrationTimeout   time.Duration
	cleanupTimeout     time.Duration
	persistenceTimeout time.Duration
	open               databaseFactory
}

// New creates an inert adapter.
//
// A zero ping timeout selects a five-second default. Negative durations and
// durations above thirty seconds are rejected so every ping has a short owned
// upper bound.
func New(options Options) (*Adapter, error) {
	cleanupTimeout := options.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultCleanupTimeout
	}
	return newAdapter(options, func(databaseURL, token string) databaseHandle {
		connector, err := tursodriver.NewConnectorWithCloseTimeout(databaseURL, token, cleanupTimeout)
		if err != nil {
			return nil
		}
		database := sql.OpenDB(connector)
		database.SetMaxIdleConns(maximumIdleConnections)
		return &connectorDatabase{DB: database, connector: connector}
	})
}

func newAdapter(options Options, open databaseFactory) (*Adapter, error) {
	pingTimeout := options.PingTimeout
	if pingTimeout == 0 {
		pingTimeout = defaultPingTimeout
	}
	migrationTimeout := options.MigrationTimeout
	if migrationTimeout == 0 {
		migrationTimeout = defaultMigrationTimeout
	}
	cleanupTimeout := options.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultCleanupTimeout
	}
	persistenceTimeout := options.PersistenceTimeout
	if persistenceTimeout == 0 {
		persistenceTimeout = defaultPersistenceTimeout
	}
	if pingTimeout < 0 || pingTimeout > maximumPingTimeout ||
		migrationTimeout < 0 || migrationTimeout > maximumMigrationTimeout ||
		cleanupTimeout < 0 || cleanupTimeout > maximumCleanupTimeout ||
		persistenceTimeout < 0 || persistenceTimeout > maximumPersistenceTimeout || open == nil {
		return nil, ErrInvalidOptions
	}
	return &Adapter{
		pingTimeout:        pingTimeout,
		migrationTimeout:   migrationTimeout,
		cleanupTimeout:     cleanupTimeout,
		persistenceTimeout: persistenceTimeout,
		open:               open,
	}, nil
}

// Open validates and normalizes the endpoint before constructing the driver.
//
// Remote endpoints require HTTPS. The turso scheme is normalized to HTTPS.
// Cleartext HTTP is accepted only for a literal loopback address with an empty
// token so credential-free protocol tests do not weaken production policy.
func (a *Adapter) Open(ctx context.Context, endpoint storage.Endpoint) (storage.Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrOpenFailed, err)
	}
	databaseURL, ok := normalizeEndpoint(endpoint)
	if !ok {
		return nil, ErrInvalidEndpoint
	}
	database := a.open(databaseURL, endpoint.Token)
	if database == nil {
		return nil, ErrOpenFailed
	}
	return &handle{
		database:           database,
		pingTimeout:        a.pingTimeout,
		migrationTimeout:   a.migrationTimeout,
		cleanupTimeout:     a.cleanupTimeout,
		persistenceTimeout: a.persistenceTimeout,
		migrationAllowed:   migrationEndpointAllowed(endpoint),
	}, nil
}

func migrationEndpointAllowed(endpoint storage.Endpoint) bool {
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || strings.ToLower(parsed.Scheme) != "http" || endpoint.Token != "" {
		return false
	}
	ip := net.ParseIP(parsed.Hostname())
	return ip != nil && ip.IsLoopback()
}

func normalizeEndpoint(endpoint storage.Endpoint) (string, bool) {
	if endpoint.URL == "" {
		return "", false
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", false
	}
	if parsed.RawPath != "" {
		return "", false
	}

	switch strings.ToLower(parsed.Scheme) {
	case "turso":
		parsed.Scheme = "https"
	case "https":
		parsed.Scheme = "https"
	case "http":
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() || endpoint.Token != "" {
			return "", false
		}
		parsed.Scheme = "http"
	default:
		return "", false
	}
	if parsed.Hostname() == "" {
		return "", false
	}
	parsed.Path = ""
	return parsed.String(), true
}

type databaseHandle interface {
	PingContext(context.Context) error
	Conn(context.Context) (*sql.Conn, error)
	Close() error
}

type databaseFactory func(databaseURL, token string) databaseHandle

type connectorDatabase struct {
	*sql.DB
	connector *tursodriver.Connector
}

func (d *connectorDatabase) CloseContext(ctx context.Context) error {
	return d.connector.CloseContext(ctx)
}

func (d *connectorDatabase) sqlDatabase() *sql.DB {
	return d.DB
}

type handle struct {
	database           databaseHandle
	pingTimeout        time.Duration
	migrationTimeout   time.Duration
	cleanupTimeout     time.Duration
	persistenceTimeout time.Duration
	migrationAllowed   bool
	closeOnce          sync.Once
	closeErr           error
}

func (h *handle) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrPingFailed, err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, h.pingTimeout)
	defer cancel()

	if err := h.database.PingContext(pingCtx); err != nil {
		if contextErr := pingCtx.Err(); contextErr != nil {
			return errors.Join(ErrPingFailed, contextErr)
		}
		return ErrPingFailed
	}
	return nil
}

func (h *handle) Close() error {
	h.closeOnce.Do(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), h.cleanupTimeout)
		defer cancel()
		if database, ok := h.database.(interface{ CloseContext(context.Context) error }); ok {
			if err := database.CloseContext(closeCtx); err != nil {
				h.closeErr = ErrCloseFailed
			}
		}
		if err := h.database.Close(); err != nil {
			h.closeErr = ErrCloseFailed
		}
	})
	return h.closeErr
}

var _ storage.Adapter = (*Adapter)(nil)
var _ storage.Handle = (*handle)(nil)
