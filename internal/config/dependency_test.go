package config

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestModuleGraphContainsOnlyReviewedDirectDependencies(t *testing.T) {
	command := exec.Command("go", "list", "-mod=readonly", "-m", "all")
	command.Dir = repositoryRoot(t)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m all: %v: %s", err, output)
	}
	got := strings.Split(strings.TrimSpace(string(output)), "\n")
	want := []string{
		"github.com/mandloideep/inboxgate",
		"go.yaml.in/yaml/v3 v3.0.5",
		"turso.tech/database/tursogo-serverless v0.0.0-20260817122138-24adc316cdc4",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("module graph = %q, want %q", got, want)
	}
}

func TestConfigDependencyGraphEmbedsTimezoneDataWithoutNetworkClients(t *testing.T) {
	command := exec.Command("go", "list", "-mod=readonly", "-deps", "./internal/config")
	command.Dir = repositoryRoot(t)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v: %s", err, output)
	}
	dependencies := make(map[string]bool)
	for _, dependency := range strings.Fields(string(output)) {
		dependencies[dependency] = true
	}
	if !dependencies["time/tzdata"] {
		t.Error("config dependency graph does not include embedded time/tzdata")
	}
	for _, forbidden := range []string{"net/http", "net/url", "crypto/tls"} {
		if dependencies[forbidden] {
			t.Errorf("config dependency graph includes network client package %q", forbidden)
		}
	}
}
