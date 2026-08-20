// Package server implements InboxGate's bounded process-health runtime.
package server

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/mandloideep/inboxgate/internal/config"
)

const (
	MaxHeaderBytes  = 16 * 1024
	ShutdownTimeout = 10 * time.Second
)

const (
	liveBody                  = "{\"status\":\"live\"}\n"
	readyBody                 = "{\"status\":\"ready\"}\n"
	notReadyBody              = "{\"status\":\"not_ready\"}\n"
	methodNotAllowedBody      = "{\"error\":\"method_not_allowed\"}\n"
	notFoundBody              = "{\"error\":\"not_found\"}\n"
	requestTooLargeBody       = "{\"error\":\"request_too_large\"}\n"
	requestBodyNotAllowedBody = "{\"error\":\"request_body_not_allowed\"}\n"
)

type ListenFunc func(network, address string) (net.Listener, error)

type Option func(*Runtime)

type mcpCloser interface {
	Close() error
}

func WithListen(listen ListenFunc) Option {
	return func(runtime *Runtime) {
		runtime.listen = listen
	}
}

func WithShutdownTimeout(timeout time.Duration) Option {
	return func(runtime *Runtime) {
		runtime.shutdownTimeout = timeout
	}
}

func WithMCP(handler http.Handler, closer mcpCloser) Option {
	return func(runtime *Runtime) {
		runtime.mcpHandler = handler
		runtime.mcpCloser = closer
	}
}

type Runtime struct {
	readiness       atomic.Bool
	logger          *slog.Logger
	httpServer      *http.Server
	listen          ListenFunc
	shutdownTimeout time.Duration
	mcpHandler      http.Handler
	mcpCloser       mcpCloser
	mcpOwned        bool
	mcpClosed       atomic.Bool
}

func New(configuration config.Config, logOutput io.Writer, options ...Option) (*Runtime, error) {
	logger, err := newLogger(configuration.Logging, logOutput)
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		logger:          logger,
		listen:          net.Listen,
		shutdownTimeout: ShutdownTimeout,
	}
	for _, option := range options {
		option(runtime)
	}
	if runtime.listen == nil || runtime.shutdownTimeout <= 0 || (runtime.mcpHandler == nil) != (runtime.mcpCloser == nil) || reservedHealthPath(configuration.MCP.Path) {
		return nil, errors.New("invalid service runtime construction")
	}
	if configuration.MCP.Enabled && runtime.mcpHandler != nil {
		runtime.mcpOwned = true
	}
	runtime.httpServer = &http.Server{
		Handler:           runtime.routeHandler(configuration),
		ReadHeaderTimeout: configuration.Server.ReadHeaderTimeout,
		ReadTimeout:       configuration.Server.ReadTimeout,
		WriteTimeout:      configuration.Server.WriteTimeout,
		IdleTimeout:       configuration.Server.IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return runtime, nil
}

func newLogger(configuration config.Logging, output io.Writer) (*slog.Logger, error) {
	var level slog.Level
	switch configuration.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, errors.New("invalid logging level")
	}
	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch configuration.Format {
	case "json":
		handler = slog.NewJSONHandler(output, options)
	case "text":
		handler = slog.NewTextHandler(output, options)
	default:
		return nil, errors.New("invalid logging format")
	}
	return slog.New(handler), nil
}

func (runtime *Runtime) Handler() http.Handler {
	return runtime.httpServer.Handler
}

func (runtime *Runtime) Ready() bool {
	return runtime.readiness.Load()
}

func (runtime *Runtime) ListenAndServe(address string, signals <-chan os.Signal) int {
	listener, err := runtime.listen("tcp", address)
	if err != nil {
		_ = runtime.closeMCP()
		runtime.logFailure("listen_failed")
		return 1
	}
	listener = newBoundedListener(listener, MaxConnections)
	serveContext, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	runtime.httpServer.BaseContext = func(net.Listener) context.Context {
		return serveContext
	}

	started := make(chan struct{})
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- runtime.httpServer.Serve(&lifecycleListener{Listener: listener, started: started})
	}()
	<-started
	runtime.readiness.Store(true)
	runtime.logLifecycle("server_started")

	select {
	case err := <-serveResult:
		runtime.readiness.Store(false)
		_ = runtime.closeMCP()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runtime.logFailure("serve_failed")
			return 1
		}
		runtime.logFailure("serve_failed")
		return 1
	case <-signals:
		runtime.readiness.Store(false)
		runtime.logLifecycle("shutdown_started")
		shutdownContext, cancel := runtime.shutdownContext(context.Background())
		defer cancel()
		mcpResult := make(chan error, 1)
		go func() {
			mcpResult <- runtime.closeMCP()
		}()
		shutdownErr := runtime.httpServer.Shutdown(shutdownContext)
		if shutdownErr != nil {
			cancelServe()
			_ = runtime.httpServer.Close()
			if errors.Is(shutdownErr, context.DeadlineExceeded) {
				runtime.logFailure("shutdown_timeout")
			} else {
				runtime.logFailure("shutdown_failed")
			}
			return 1
		}
		var mcpErr error
		select {
		case mcpErr = <-mcpResult:
		case <-shutdownContext.Done():
			cancelServe()
			_ = runtime.httpServer.Close()
			runtime.logFailure("shutdown_timeout")
			return 1
		}
		serveErr := <-serveResult
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			runtime.logFailure("serve_failed")
			return 1
		}
		if mcpErr != nil {
			runtime.logFailure("shutdown_failed")
			return 1
		}
		runtime.logLifecycle("shutdown_completed")
		return 0
	}
}

func reservedHealthPath(path string) bool {
	return path == "/health/live" || path == "/health/ready"
}

func (runtime *Runtime) closeMCP() error {
	if !runtime.mcpOwned || !runtime.mcpClosed.CompareAndSwap(false, true) {
		return nil
	}
	return runtime.mcpCloser.Close()
}

type lifecycleListener struct {
	net.Listener
	started chan struct{}
	once    atomic.Bool
}

func (listener *lifecycleListener) Accept() (net.Conn, error) {
	if listener.once.CompareAndSwap(false, true) {
		close(listener.started)
	}
	return listener.Listener.Accept()
}

func (runtime *Runtime) shutdownContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, runtime.shutdownTimeout)
}

func (runtime *Runtime) logLifecycle(event string) {
	runtime.logger.Info(event, "event", event)
}

func (runtime *Runtime) logFailure(reason string) {
	runtime.logger.Error("server_failure", "event", "server_failure", "reason", reason)
}

func (runtime *Runtime) healthHandler(maxRequestBytes uint64) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		started := time.Now()
		routePath := request.URL.EscapedPath()
		operation := operationForPath(routePath)
		method := methodForLog(request.Method)
		status, body, outcome, allow := runtime.routeHealth(request, routePath, maxRequestBytes)
		writeFixedResponse(response, request.Method == http.MethodHead, status, body, allow)
		duration := time.Since(started).Milliseconds()
		if duration < 0 {
			duration = 0
		}
		runtime.logger.Info("http_request",
			"event", "http_request",
			"operation", operation,
			"method", method,
			"status", status,
			"duration_ms", duration,
			"outcome", outcome,
		)
	})
}

func (runtime *Runtime) routeHandler(configuration config.Config) http.Handler {
	health := runtime.healthHandler(configuration.Server.MaxRequestBytes)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if runtime.mcpOwned && exactMCPPath(request, configuration.MCP.Path) {
			runtime.mcpHandler.ServeHTTP(response, request)
			return
		}
		health.ServeHTTP(response, request)
	})
}

func exactMCPPath(request *http.Request, path string) bool {
	return request.URL != nil && request.URL.Path == path && request.URL.RawPath == "" && request.URL.RawQuery == "" && request.URL.Fragment == "" && request.URL.EscapedPath() == path
}

func (runtime *Runtime) routeHealth(request *http.Request, routePath string, maxRequestBytes uint64) (int, string, string, string) {
	if routePath != "/health/live" && routePath != "/health/ready" {
		return http.StatusNotFound, notFoundBody, "not_found", ""
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return http.StatusMethodNotAllowed, methodNotAllowedBody, "method_not_allowed", "GET, HEAD"
	}
	if request.ContentLength > int64(maxRequestBytes) {
		return http.StatusRequestEntityTooLarge, requestTooLargeBody, "request_too_large", ""
	}
	if request.ContentLength != 0 || len(request.TransferEncoding) != 0 || request.Body != nil && request.Body != http.NoBody {
		return http.StatusBadRequest, requestBodyNotAllowedBody, "request_body_not_allowed", ""
	}
	if routePath == "/health/live" {
		return http.StatusOK, liveBody, "live", ""
	}
	if runtime.readiness.Load() {
		return http.StatusOK, readyBody, "ready", ""
	}
	return http.StatusServiceUnavailable, notReadyBody, "not_ready", ""
}

func writeFixedResponse(response http.ResponseWriter, head bool, status int, body, allow string) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if allow != "" {
		response.Header().Set("Allow", allow)
	}
	response.WriteHeader(status)
	if !head {
		_, _ = io.WriteString(response, body)
	}
}

func operationForPath(path string) string {
	switch path {
	case "/health/live":
		return "health.live"
	case "/health/ready":
		return "health.ready"
	default:
		return "unmatched"
	}
}

func methodForLog(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return method
	default:
		return "other"
	}
}
