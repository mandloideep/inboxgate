package config

import (
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestModuleGraphContainsOnlyPinnedYAML(t *testing.T) {
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
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("module graph = %q, want %q", got, want)
	}
}

func TestProductionDependencyGraphEmbedsTimezoneDataWithoutNetworkClients(t *testing.T) {
	command := exec.Command("go", "list", "-mod=readonly", "-deps", "./cmd/inboxgate")
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
		t.Error("production dependency graph does not include embedded time/tzdata")
	}
	for _, forbidden := range []string{"net/http", "net/url", "crypto/tls"} {
		if dependencies[forbidden] {
			t.Errorf("production validation dependency graph includes network client package %q", forbidden)
		}
	}
}
