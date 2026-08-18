package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mandloideep/inboxgate/internal/buildmeta"
	"github.com/mandloideep/inboxgate/internal/config"
	"github.com/mandloideep/inboxgate/internal/cryptobox"
	"github.com/mandloideep/inboxgate/internal/gmail"
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
var accountAddListen = net.Listen
var lookupAccountEnvironment = os.LookupEnv
var newAccountEnrollment = gmail.New

func runAccount(args []string, configPath string, explicitConfig bool, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printUsageError(stderr, "account requires a subcommand", printAccountHelp)
	}
	if args[0] != "add" {
		return printUsageError(stderr, fmt.Sprintf("unknown account subcommand %q", args[0]), printAccountHelp)
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
	runtime, err := server.New(configuration, stderr)
	if err != nil {
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
