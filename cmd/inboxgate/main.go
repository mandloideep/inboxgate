package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mandloideep/inboxgate/internal/buildmeta"
	"github.com/mandloideep/inboxgate/internal/config"
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
	default:
		return printUsageError(stderr, fmt.Sprintf("unknown command %q", args[0]), printHelp)
	}
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
	fmt.Fprintln(output, "  config        Validate and inspect InboxGate configuration")
	fmt.Fprintln(output, "  version       Print the InboxGate version")
	fmt.Fprintln(output, "  help          Show this help")
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
