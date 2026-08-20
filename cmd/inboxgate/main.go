package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	accountlife "github.com/mandloideep/inboxgate/internal/account"
	"github.com/mandloideep/inboxgate/internal/accountstatus"
	"github.com/mandloideep/inboxgate/internal/buildmeta"
	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/gmail"
	inboxmcp "github.com/mandloideep/inboxgate/internal/mcp"
	"github.com/mandloideep/inboxgate/internal/reviewinspect"
	"github.com/mandloideep/inboxgate/internal/server"
	"github.com/mandloideep/inboxgate/internal/storage"
	"github.com/mandloideep/inboxgate/internal/storage/turso"
)

var version = "dev"
var commit string

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}
	configPath, explicitConfig, remaining, usageError := parseGlobalFlags(args)
	if usageError != "" {
		return printUsageError(stderr, usageError, printHelp)
	}
	args = remaining
	if len(args) == 0 {
		return printUsageError(stderr, "missing command", printHelp)
	}

	switch args[0] {
	case "version":
		if len(args) != 1 {
			return printUsageError(stderr, "version does not accept arguments", printHelp)
		}
		metadata, err := buildmeta.Format(version, commit)
		if err != nil {
			fmt.Fprintf(stderr, "invalid release metadata: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "inboxgate %s\n", metadata)
		return 0
	case "help", "-h", "--help":
		if len(args) != 1 {
			return printUsageError(stderr, "help does not accept arguments", printHelp)
		}
		printHelp(stdout)
		return 0
	case "config":
		return runConfig(args[1:], configPath, explicitConfig, stdout, stderr)
	case "capabilities":
		return runCapabilities(args[1:], configPath, explicitConfig, stdout, stderr)
	case "serve":
		return runServe(args[1:], configPath, explicitConfig, stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], configPath, explicitConfig, stdout, stderr)
	case "account":
		return runAccount(args[1:], configPath, explicitConfig, stdout, stderr)
	default:
		return printUsageError(stderr, fmt.Sprintf("unknown command %q", args[0]), printHelp)
	}
}

var accountAddCommand = runAccountAddCommand
var accountLifecycleCommand = runAccountLifecycleCommand
var accountAddListen = net.Listen
var lookupAccountEnvironment = os.LookupEnv
var newAccountEnrollment = gmail.New
var newAccountLifecycleManager = accountlife.NewWithKeyringResolver

func runAccount(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printUsageError(stderr, "account requires a subcommand", printAccountHelp)
	}
	if args[0] != "add" && args[0] != "list" && args[0] != "pause" && args[0] != "resume" && args[0] != "revoke" {
		return printUsageError(stderr, fmt.Sprintf("unknown account subcommand %q", args[0]), printAccountHelp)
	}
	if args[0] != "add" {
		return runAccountLifecycle(args, configPath, explicitConfig, stdout, stderr)
	}
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
		printAccountAddHelp(stdout)
		return 0
	}
	if len(args) != 1 {
		return printUsageError(stderr, "account add does not accept arguments", printAccountAddHelp)
	}
	configuration, ok := loadSelectedConfig(configPath, explicitConfig, stderr)
	if !ok {
		return 1
	}
	return accountAddCommand(configuration, stdout, stderr)
}

const (
	accountPausedMessage           = "account paused\n"
	accountActiveMessage           = "account active\n"
	accountRevokedConfirmedMessage = "account revoked; provider revocation confirmed\n"
	accountRevokedManualMessage    = "account revoked locally; provider revocation requires owner action\n"
)

func runAccountLifecycle(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	action := args[0]
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
		printAccountLifecycleHelp(stdout, action)
		return 0
	}
	accountID := ""
	confirmed := false
	valid := false
	switch action {
	case "list":
		valid = len(args) == 1
	case "pause", "resume":
		valid = len(args) == 2
		if valid {
			accountID = args[1]
			_, parseErr := storage.ParseAccountID(accountID)
			valid = parseErr == nil
		}
	case "revoke":
		valid = len(args) == 3 && args[2] == "--confirm"
		if valid {
			accountID = args[1]
			_, parseErr := storage.ParseAccountID(accountID)
			valid = parseErr == nil
			confirmed = valid
		}
	}
	if !valid {
		return printUsageError(stderr, "invalid account "+action+" arguments", func(output io.Writer) { printAccountLifecycleHelp(output, action) })
	}
	configuration, ok := loadSelectedConfig(configPath, explicitConfig, stderr)
	if !ok {
		return 1
	}
	return accountLifecycleCommand(configuration, action, accountID, confirmed, stdout, stderr)
}

func runAccountLifecycleCommand(configuration config.Config, action, rawAccountID string, confirmed bool, stdout, stderr io.Writer) int {
	if !accountLifecycleSelectorsSeparated(configuration) {
		fmt.Fprintln(stderr, "account operation unavailable: invalid runtime configuration")
		return 1
	}
	databaseURL, ok := resolvedAccountSecretEnvironment(configuration.Database.URLEnv, 2048)
	if !ok {
		fmt.Fprintln(stderr, "account operation unavailable: invalid runtime secret")
		return 1
	}
	defer clear(databaseURL)
	databaseToken, ok := resolvedOptionalAccountSecretEnvironment(configuration.Database.AuthTokenEnv, 4096)
	if !ok {
		fmt.Fprintln(stderr, "account operation unavailable: invalid runtime secret")
		return 1
	}
	defer clear(databaseToken)
	if !accountEnrollmentStorageAllowed(string(databaseURL), databaseToken) {
		fmt.Fprintln(stderr, "account operation unavailable: storage setup failed")
		return 1
	}
	adapter, err := turso.New(turso.Options{})
	if err != nil {
		fmt.Fprintln(stderr, "account operation unavailable: storage setup failed")
		return 1
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: string(databaseURL), Token: string(databaseToken)})
	if err != nil {
		fmt.Fprintln(stderr, "account operation unavailable: storage setup failed")
		return 1
	}
	defer handle.Close()
	var resolvedRing *cryptobox.Keyring
	manager := newAccountLifecycleManager(handle, func() (*cryptobox.Keyring, error) {
		keyText, ok := resolvedAccountSecretEnvironment(configuration.Encryption.MasterKeyEnv, cryptobox.MaximumKeyringBytes)
		if !ok {
			return nil, accountlife.ErrRecoveryRequired
		}
		defer clear(keyText)
		ring, err := cryptobox.ParseKeyring(keyText)
		if err != nil {
			return nil, accountlife.ErrRecoveryRequired
		}
		resolvedRing = ring
		return ring, nil
	})
	defer func() {
		if resolvedRing != nil {
			_ = resolvedRing.Close()
		}
	}()
	if action == "list" {
		summaries, err := manager.List(context.Background())
		if err != nil {
			fmt.Fprintln(stderr, "account listing failed")
			return 1
		}
		data, err := renderAccountList(summaries)
		if err != nil {
			fmt.Fprintln(stderr, "account listing failed")
			return 1
		}
		written, err := stdout.Write(data)
		if err != nil || written != len(data) {
			fmt.Fprintln(stderr, "account listing failed")
			return 1
		}
		return 0
	}
	accountID, err := storage.ParseAccountID(rawAccountID)
	if err != nil {
		fmt.Fprintln(stderr, "account operation failed")
		return 1
	}
	switch action {
	case "pause":
		err = manager.Pause(context.Background(), accountID)
		if err == nil {
			_, err = io.WriteString(stdout, accountPausedMessage)
		}
	case "resume":
		err = manager.Resume(context.Background(), accountID)
		if err == nil {
			_, err = io.WriteString(stdout, accountActiveMessage)
		}
	case "revoke":
		if !confirmed {
			err = accountlife.ErrTransition
			break
		}
		result, revokeErr := manager.Revoke(context.Background(), accountID)
		if result == accountlife.RevocationConfirmed && revokeErr == nil {
			_, err = io.WriteString(stdout, accountRevokedConfirmedMessage)
		} else if result == accountlife.RevocationManual {
			_, _ = io.WriteString(stdout, accountRevokedManualMessage)
			return 1
		} else {
			err = revokeErr
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "account operation failed")
		return 1
	}
	return 0
}

func accountLifecycleSelectorsSeparated(configuration config.Config) bool {
	allNames := []string{
		configuration.Database.URLEnv, configuration.Database.AuthTokenEnv,
		configuration.Gmail.OAuthClientIDEnv, configuration.Gmail.OAuthClientSecretEnv,
		configuration.Gmail.OAuthRedirectURLEnv, configuration.Encryption.MasterKeyEnv,
		configuration.MCP.BearerTokenEnv,
	}
	seen := make(map[string]struct{}, len(allNames))
	for _, name := range allNames {
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

type accountListDocument struct {
	OutputVersion int                   `json:"output_version"`
	Accounts      []accountListJSONItem `json:"accounts"`
}

type accountListJSONItem struct {
	AccountID             string  `json:"account_id"`
	Provider              string  `json:"provider"`
	State                 string  `json:"state"`
	StateVersion          int64   `json:"state_version"`
	ReauthorizationReason *string `json:"reauthorization_reason"`
	RevocationStatus      string  `json:"revocation_status"`
	CursorPresent         bool    `json:"cursor_present"`
	CredentialPresent     bool    `json:"credential_present"`
}

func renderAccountList(summaries []storage.AccountSummary) ([]byte, error) {
	if len(summaries) > storage.MaximumAccountList {
		return nil, storage.ErrResultTooLarge
	}
	document := accountListDocument{OutputVersion: 1, Accounts: make([]accountListJSONItem, 0, len(summaries))}
	for _, summary := range summaries {
		var reason *string
		if summary.ReauthorizationReason != nil {
			text := summary.ReauthorizationReason.String()
			reason = &text
		}
		document.Accounts = append(document.Accounts, accountListJSONItem{
			AccountID: summary.AccountID.String(), Provider: summary.Provider, State: summary.State.String(), StateVersion: summary.StateVersion.Int64(),
			ReauthorizationReason: reason, RevocationStatus: summary.RevocationStatus.String(), CursorPresent: summary.CursorPresent, CredentialPresent: summary.CredentialPresent,
		})
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(data)+1 > 64<<10 {
		return nil, storage.ErrResultTooLarge
	}
	return append(data, '\n'), nil
}

func runAccountAddCommand(configuration config.Config, stdout, stderr io.Writer) int {
	if !accountEnrollmentSelectorsSeparated(configuration) {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime configuration")
		return 1
	}
	clientID, ok := resolvedAccountPublicEnvironment(configuration.Gmail.OAuthClientIDEnv, 512)
	if !ok {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer clear(clientID)
	clientSecret, ok := resolvedAccountSecretEnvironment(configuration.Gmail.OAuthClientSecretEnv, 512)
	if !ok {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer clear(clientSecret)
	redirect, ok := resolvedAccountPublicEnvironment(configuration.Gmail.OAuthRedirectURLEnv, 2048)
	if !ok {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer clear(redirect)
	keyText, ok := resolvedAccountSecretEnvironment(configuration.Encryption.MasterKeyEnv, cryptobox.MaximumKeyringBytes)
	if !ok {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer clear(keyText)
	databaseURL, ok := resolvedAccountSecretEnvironment(configuration.Database.URLEnv, 2048)
	if !ok {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer clear(databaseURL)
	databaseToken, ok := resolvedOptionalAccountSecretEnvironment(configuration.Database.AuthTokenEnv, 4096)
	if !ok {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer clear(databaseToken)
	if !accountEnrollmentStorageAllowed(string(databaseURL), databaseToken) {
		fmt.Fprintln(stderr, "account enrollment unavailable: storage setup failed")
		return 1
	}
	ring, err := cryptobox.ParseKeyring(keyText)
	if err != nil {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer ring.Close()
	adapter, err := turso.New(turso.Options{})
	if err != nil {
		fmt.Fprintln(stderr, "account enrollment unavailable: storage setup failed")
		return 1
	}
	handle, err := adapter.Open(context.Background(), storage.Endpoint{URL: string(databaseURL), Token: string(databaseToken)})
	if err != nil {
		fmt.Fprintln(stderr, "account enrollment unavailable: storage setup failed")
		return 1
	}
	defer handle.Close()
	enrollment, err := newAccountEnrollment(clientID, clientSecret, string(redirect), handle, ring)
	if err != nil {
		fmt.Fprintln(stderr, "account enrollment unavailable: invalid runtime secret")
		return 1
	}
	defer enrollment.Close()
	listener, err := accountAddListen("tcp", configuration.Server.Listen)
	if err != nil {
		fmt.Fprintln(stderr, "account enrollment unavailable: callback listener failed")
		return 1
	}
	defer listener.Close()
	if err := enrollment.Run(context.Background(), listener, stdout); err != nil {
		fmt.Fprintln(stderr, "account enrollment failed")
		return 1
	}
	fmt.Fprintln(stdout, "account enrolled")
	return 0
}

func accountEnrollmentSelectorsSeparated(configuration config.Config) bool {
	names := []string{
		configuration.Gmail.OAuthClientIDEnv,
		configuration.Gmail.OAuthClientSecretEnv,
		configuration.Gmail.OAuthRedirectURLEnv,
		configuration.Encryption.MasterKeyEnv,
		configuration.Database.URLEnv,
		configuration.Database.AuthTokenEnv,
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func accountEnrollmentStorageAllowed(databaseURL string, token []byte) bool {
	if len(token) != 0 {
		return false
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return false
	}
	ip := net.ParseIP(parsed.Hostname())
	return ip != nil && ip.IsLoopback()
}

func resolvedAccountPublicEnvironment(name string, maximum int) ([]byte, bool) {
	value, set := lookupAccountEnvironment(name)
	if !set || len(value) < 1 || len(value) > maximum {
		return nil, false
	}
	return []byte(value), true
}

func resolvedAccountSecretEnvironment(name string, maximum int) ([]byte, bool) {
	value, set := lookupAccountEnvironment(name)
	if !set || len(value) < 1 || len(value) > maximum {
		return nil, false
	}
	return []byte(value), true
}

func resolvedOptionalAccountSecretEnvironment(name string, maximum int) ([]byte, bool) {
	value, set := lookupAccountEnvironment(name)
	if !set {
		return []byte{}, true
	}
	if len(value) > maximum {
		return nil, false
	}
	return []byte(value), true
}

var doctorResult = []byte("{\n  \"output_version\": 1,\n  \"status\": \"ok\",\n  \"checks\": [\n    {\n      \"name\": \"configuration\",\n      \"status\": \"pass\"\n    },\n    {\n      \"name\": \"service_runtime\",\n      \"status\": \"pass\"\n    }\n  ]\n}\n")

var lookupMCPEnvironment = os.LookupEnv
var lookupOperatorDatabaseEnvironment = os.LookupEnv
var openOperatorAccountStatusSource = func(ctx context.Context, endpoint storage.Endpoint) (storage.Handle, error) {
	adapter, err := turso.New(turso.Options{})
	if err != nil {
		return nil, err
	}
	return adapter.Open(ctx, endpoint)
}

func openMCPReadSource(ctx context.Context, endpoint storage.Endpoint) (storage.Handle, error) {
	return openOperatorAccountStatusSource(ctx, endpoint)
}

func openMCPReadServices(ctx context.Context, configuration config.Config, endpoint storage.Endpoint) (storage.Handle, *accountstatus.Service, *reviewinspect.Service, error) {
	sharedMCPSource, err := openMCPReadSource(ctx, endpoint)
	if err != nil {
		return nil, nil, nil, err
	}
	var accountStatus *accountstatus.Service
	var reviewInspection *reviewinspect.Service
	if configuration.MCP.EnableOperatorTools {
		accountStatus, err = accountstatus.New(sharedMCPSource, config.CapabilityRegistry(configuration))
		if err != nil {
			_ = sharedMCPSource.Close()
			return nil, nil, nil, err
		}
	}
	if configuration.Capabilities.MailReviewRead {
		reviewInspection, err = reviewinspect.New(sharedMCPSource, configuration.Gate, configuration.Review)
		if err != nil {
			_ = sharedMCPSource.Close()
			return nil, nil, nil, err
		}
	}
	return sharedMCPSource, accountStatus, reviewInspection, nil
}

type mcpReadCloser struct {
	handler *inboxmcp.Handler
	source  storage.Handle
}

func (closer *mcpReadCloser) Close() error {
	return errors.Join(closer.handler.Close(), closer.source.Close())
}

type accountStatusMCPCloser = mcpReadCloser

func runServe(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printServeHelp(stdout)
		return 0
	}
	if len(args) != 0 {
		return printUsageError(stderr, "serve does not accept arguments", printServeHelp)
	}
	configuration, ok := loadSelectedConfig(configPath, explicitConfig, stderr)
	if !ok {
		return 1
	}
	var runtimeOptions []server.Option
	var mcpHandler *inboxmcp.Handler
	var mcpCloser interface{ Close() error }
	if configuration.MCP.Enabled {
		value, found := lookupMCPEnvironment(configuration.MCP.BearerTokenEnv)
		if !found {
			fmt.Fprintln(stderr, "cannot construct MCP runtime")
			return 1
		}
		encodedToken := []byte(value)
		decodedToken, tokenErr := inboxmcp.ParseBearerToken(value)
		clear(decodedToken)
		if tokenErr != nil {
			clear(encodedToken)
			fmt.Fprintln(stderr, "cannot construct MCP runtime")
			return 1
		}
		var accountStatus *accountstatus.Service
		var reviewInspection *reviewinspect.Service
		var sharedMCPSource storage.Handle
		if configuration.MCP.EnableOperatorTools || configuration.Capabilities.MailReviewRead {
			if configuration.Database.URLEnv == configuration.Database.AuthTokenEnv ||
				configuration.Database.URLEnv == configuration.MCP.BearerTokenEnv ||
				configuration.Database.AuthTokenEnv == configuration.MCP.BearerTokenEnv {
				clear(encodedToken)
				fmt.Fprintln(stderr, "cannot construct MCP runtime")
				return 1
			}
			databaseURL, urlSet := lookupOperatorDatabaseEnvironment(configuration.Database.URLEnv)
			databaseToken, tokenSet := lookupOperatorDatabaseEnvironment(configuration.Database.AuthTokenEnv)
			if !urlSet || len(databaseURL) < 1 || len(databaseURL) > 2048 || len(databaseToken) > 4096 || tokenSet ||
				!accountEnrollmentStorageAllowed(databaseURL, []byte(databaseToken)) {
				clear(encodedToken)
				fmt.Fprintln(stderr, "cannot construct MCP runtime")
				return 1
			}
			var adapterErr error
			sharedMCPSource, accountStatus, reviewInspection, adapterErr = openMCPReadServices(context.Background(), configuration, storage.Endpoint{URL: databaseURL})
			if adapterErr != nil {
				clear(encodedToken)
				fmt.Fprintln(stderr, "cannot construct MCP runtime")
				return 1
			}
		}
		var err error
		mcpHandler, err = inboxmcp.New(inboxmcp.Options{
			Configuration:    configuration,
			BinaryVersion:    version,
			BinaryCommit:     commit,
			BearerToken:      encodedToken,
			AuditOutput:      stderr,
			AccountStatus:    accountStatus,
			ReviewInspection: reviewInspection,
		})
		clear(encodedToken)
		if err != nil {
			if sharedMCPSource != nil {
				_ = sharedMCPSource.Close()
			}
			fmt.Fprintln(stderr, "cannot construct MCP runtime")
			return 1
		}
		mcpCloser = mcpHandler
		if sharedMCPSource != nil {
			mcpCloser = &mcpReadCloser{handler: mcpHandler, source: sharedMCPSource}
		}
		runtimeOptions = append(runtimeOptions, server.WithMCP(mcpHandler, mcpCloser))
	}
	runtime, err := server.New(configuration, stderr, runtimeOptions...)
	if err != nil {
		if mcpHandler != nil {
			_ = mcpCloser.Close()
		}
		fmt.Fprintln(stderr, "cannot construct service runtime")
		return 1
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	return runtime.ListenAndServe(configuration.Server.Listen, signals)
}

func runDoctor(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printDoctorHelp(stdout)
		return 0
	}
	if len(args) != 0 {
		return printUsageError(stderr, "doctor does not accept arguments", printDoctorHelp)
	}
	configuration, ok := loadSelectedConfig(configPath, explicitConfig, stderr)
	if !ok {
		return 1
	}
	if _, err := server.New(configuration, stderr); err != nil {
		fmt.Fprintln(stderr, "cannot construct service runtime")
		return 1
	}
	written, err := stdout.Write(doctorResult)
	if err != nil || written != len(doctorResult) {
		fmt.Fprintln(stderr, "cannot write doctor result")
		return 1
	}
	return 0
}

func loadSelectedConfig(configPath string, explicitConfig bool, stderr io.Writer) (config.Config, bool) {
	selection, selectionError := selectConfig(configPath, explicitConfig)
	if selectionError != "" {
		fmt.Fprintf(stderr, "configuration invalid: %s\n", selectionError)
		return config.Config{}, false
	}
	configuration, err := config.Load(selection.path)
	if err != nil {
		printConfigValidationError(stderr, err)
		return config.Config{}, false
	}
	return configuration, true
}

func runCapabilities(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printCapabilitiesHelp(stdout)
		return 0
	}
	if len(args) != 0 {
		return printUsageError(stderr, "capabilities does not accept arguments", printCapabilitiesHelp)
	}
	selection, selectionError := selectConfig(configPath, explicitConfig)
	if selectionError != "" {
		fmt.Fprintf(stderr, "configuration invalid: %s\n", selectionError)
		return 1
	}
	configuration, err := config.Load(selection.path)
	if err != nil {
		return printConfigValidationError(stderr, err)
	}
	data, err := config.CapabilitiesJSON(configuration)
	if err != nil {
		fmt.Fprintln(stderr, "cannot render capabilities")
		return 1
	}
	written, err := stdout.Write(data)
	if err != nil || written != len(data) {
		fmt.Fprintln(stderr, "cannot write capabilities")
		return 1
	}
	return 0
}

func parseGlobalFlags(args []string) (string, bool, []string, string) {
	var path string
	explicit := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		argument := args[0]
		if argument == "-h" || argument == "--help" {
			return "", false, args, ""
		}
		if argument == "--config" {
			if explicit {
				return "", false, nil, "--config may be specified only once"
			}
			if len(args) < 2 {
				return "", false, nil, "--config requires a path"
			}
			if strings.HasPrefix(args[1], "-") {
				if args[1] == "--config" || strings.HasPrefix(args[1], "--config=") {
					return "", false, nil, "--config may be specified only once"
				}
				return "", false, nil, "--config requires a path"
			}
			path, explicit, args = args[1], true, args[2:]
			continue
		}
		if strings.HasPrefix(argument, "--config=") {
			if explicit {
				return "", false, nil, "--config may be specified only once"
			}
			path, explicit, args = strings.TrimPrefix(argument, "--config="), true, args[1:]
			continue
		}
		return "", false, nil, fmt.Sprintf("unknown global flag %q", argument)
	}
	if explicit && strings.TrimSpace(path) == "" {
		return "", false, nil, "--config requires a non-empty path"
	}
	return path, explicit, args, ""
}

func runConfig(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printConfigHelp(stdout)
		return 0
	}
	if len(args) == 0 {
		return printUsageError(stderr, "config requires a subcommand", printConfigHelp)
	}
	if args[0] != "validate" && args[0] != "effective" {
		return printUsageError(stderr, fmt.Sprintf("unknown config subcommand %q", args[0]), printConfigHelp)
	}
	if args[0] == "validate" {
		return runConfigValidate(args[1:], configPath, explicitConfig, stdout, stderr)
	}
	return runConfigEffective(args[1:], configPath, explicitConfig, stdout, stderr)
}

type configSelection struct {
	path   string
	source string
}

func selectConfig(configPath string, explicitConfig bool) (configSelection, string) {
	if explicitConfig {
		return configSelection{path: configPath, source: "flag"}, ""
	}
	if environmentPath, set := os.LookupEnv("INBOXGATE_CONFIG"); set {
		if strings.TrimSpace(environmentPath) == "" {
			return configSelection{}, "INBOXGATE_CONFIG: path must not be empty"
		}
		return configSelection{path: environmentPath, source: "environment"}, ""
	}
	return configSelection{path: "/etc/inboxgate/config.yaml", source: "default"}, ""
}

func runConfigValidate(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printConfigValidateHelp(stdout)
		return 0
	}
	if len(args) != 0 {
		return printUsageError(stderr, "config validate does not accept arguments", printConfigValidateHelp)
	}
	selection, selectionError := selectConfig(configPath, explicitConfig)
	if selectionError != "" {
		fmt.Fprintf(stderr, "configuration invalid: %s\n", selectionError)
		return 1
	}
	if _, err := config.Load(selection.path); err != nil {
		return printConfigValidationError(stderr, err)
	}
	fmt.Fprintln(stdout, "configuration valid")
	return 0
}

func runConfigEffective(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		printConfigEffectiveHelp(stdout)
		return 0
	}
	if len(args) != 0 {
		return printUsageError(stderr, "config effective does not accept arguments", printConfigEffectiveHelp)
	}
	selection, selectionError := selectConfig(configPath, explicitConfig)
	if selectionError != "" {
		fmt.Fprintf(stderr, "configuration invalid: %s\n", selectionError)
		return 1
	}
	effective, err := config.LoadEffective(selection.path)
	if err != nil {
		return printConfigValidationError(stderr, err)
	}
	data, err := effective.JSON(selection.source)
	if err != nil {
		fmt.Fprintln(stderr, "cannot render effective configuration")
		return 1
	}
	written, err := stdout.Write(data)
	if err != nil || written != len(data) {
		fmt.Fprintln(stderr, "cannot write effective configuration")
		return 1
	}
	return 0
}

func printConfigValidationError(stderr io.Writer, err error) int {
	var validation *config.ValidationError
	if errors.As(err, &validation) {
		for _, problem := range validation.Problems {
			fmt.Fprintf(stderr, "configuration invalid: %s\n", problem.Error())
		}
	} else {
		fmt.Fprintln(stderr, "configuration invalid: file: validation failed")
	}
	return 1
}

func printUsageError(output io.Writer, message string, usage func(io.Writer)) int {
	fmt.Fprintln(output, message)
	fmt.Fprintln(output)
	usage(output)
	return 2
}

func printHelp(output io.Writer) {
	fmt.Fprintln(output, "InboxGate keeps high-volume email behind a deterministic review gate.")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  capabilities  Inspect compile-time and configured capability status as JSON")
	fmt.Fprintln(output, "  account       Enroll a Gmail account through a one-shot operator flow")
	fmt.Fprintln(output, "  config        Validate and inspect InboxGate configuration")
	fmt.Fprintln(output, "  serve         Run bounded process-health endpoints")
	fmt.Fprintln(output, "  doctor        Validate local service construction")
	fmt.Fprintln(output, "  version       Print the InboxGate version")
	fmt.Fprintln(output, "  help          Show this help")
}

func printAccountHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] account <subcommand>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Subcommands:")
	fmt.Fprintln(output, "  add  Enroll one Gmail account")
	fmt.Fprintln(output, "  list  List bounded account lifecycle summaries")
	fmt.Fprintln(output, "  pause  Pause one account")
	fmt.Fprintln(output, "  resume  Resume one complete paused account")
	fmt.Fprintln(output, "  revoke  Revoke one account after explicit confirmation")
}

func printAccountLifecycleHelp(output io.Writer, action string) {
	fmt.Fprintln(output, "Usage:")
	switch action {
	case "list":
		fmt.Fprintln(output, "  inboxgate [--config PATH] account list")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Prints at most 100 account lifecycle summaries as canonical JSON.")
		fmt.Fprintln(output, "Account IDs are sensitive and must not be copied into public output.")
	case "pause":
		fmt.Fprintln(output, "  inboxgate [--config PATH] account pause <account-id>")
	case "resume":
		fmt.Fprintln(output, "  inboxgate [--config PATH] account resume <account-id>")
	case "revoke":
		fmt.Fprintln(output, "  inboxgate [--config PATH] account revoke <account-id> --confirm")
		fmt.Fprintln(output)
		fmt.Fprintln(output, "Persists revoked intent before one bounded Google revocation request.")
	}
}

func printAccountAddHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] account add")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Runs a one-shot flow, prints one authorization URL, and waits for one callback.")
	fmt.Fprintln(output, "Credential values are read only from the environment names selected by validated configuration.")
}

func printServeHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] serve")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Runs bounded liveness and process-readiness endpoints until SIGINT or SIGTERM.")
	fmt.Fprintln(output, "Bind only to an approved private interface or private reverse-proxy path.")
}

func printDoctorHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] doctor")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Validates configuration and local service construction without binding a listener.")
}

func printCapabilitiesHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] capabilities")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Prints the typed capability registry after strict schema v1 validation.")
	fmt.Fprintln(output, "Named secret values are never read, but environment-variable names in the output can be sensitive.")
}

func printConfigHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] config <subcommand>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Subcommands:")
	fmt.Fprintln(output, "  validate  Validate schema v1 without reading secrets or contacting services")
	fmt.Fprintln(output, "  effective Print normalized schema v1 policy and field provenance as JSON")
}

func printConfigValidateHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] config validate")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Validates configuration schema v1 without reading named secrets or contacting services.")
}

func printConfigEffectiveHelp(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate [--config PATH] config effective")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Prints normalized schema v1 policy and field provenance as JSON.")
	fmt.Fprintln(output, "Named secret values are never read, but non-secret policy in the output can still be sensitive.")
}
