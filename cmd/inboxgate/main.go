package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return 0
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "inboxgate %s\n", version)
		return 0
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printHelp(stderr)
		return 2
	}
}

func printHelp(output io.Writer) {
	fmt.Fprintln(output, "InboxGate keeps high-volume email behind a deterministic review gate.")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  inboxgate <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  version  Print the InboxGate version")
	fmt.Fprintln(output, "  help     Show this help")
}
