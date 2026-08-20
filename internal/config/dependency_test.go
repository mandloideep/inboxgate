package config

import (
	"os"
	"os/exec"
	"path/filepath"
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
		"cloud.google.com/go/compute/metadata v0.3.0",
		"github.com/golang-jwt/jwt/v5 v5.3.1",
		"github.com/google/go-cmp v0.7.0",
		"github.com/google/jsonschema-go v0.4.3",
		"github.com/modelcontextprotocol/go-sdk v1.7.0",
		"github.com/segmentio/asm v1.1.3",
		"github.com/segmentio/encoding v0.5.4",
		"github.com/yosida95/uritemplate/v3 v3.0.2",
		"go.yaml.in/yaml/v3 v3.0.5",
		"golang.org/x/oauth2 v0.36.0",
		"golang.org/x/sync v0.20.0",
		"golang.org/x/sys v0.41.0",
		"golang.org/x/time v0.15.0",
		"golang.org/x/tools v0.42.0",
		"turso.tech/database/tursogo-serverless v0.0.0-20260817122138-24adc316cdc4 => ./third_party/tursogo-serverless",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("module graph = %q, want %q", got, want)
	}
}

func TestMCPModuleGraphAndDistributionNoticesAreExact(t *testing.T) {
	command := exec.Command("go", "mod", "graph")
	command.Dir = repositoryRoot(t)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go mod graph: %v: %s", err, output)
	}
	wantGraph := `github.com/mandloideep/inboxgate github.com/google/jsonschema-go@v0.4.3
github.com/mandloideep/inboxgate github.com/modelcontextprotocol/go-sdk@v1.7.0
github.com/mandloideep/inboxgate github.com/segmentio/asm@v1.1.3
github.com/mandloideep/inboxgate github.com/segmentio/encoding@v0.5.4
github.com/mandloideep/inboxgate github.com/yosida95/uritemplate/v3@v3.0.2
github.com/mandloideep/inboxgate go@1.26.0
github.com/mandloideep/inboxgate go.yaml.in/yaml/v3@v3.0.5
github.com/mandloideep/inboxgate golang.org/x/oauth2@v0.36.0
github.com/mandloideep/inboxgate golang.org/x/sync@v0.20.0
github.com/mandloideep/inboxgate golang.org/x/sys@v0.41.0
github.com/mandloideep/inboxgate golang.org/x/time@v0.15.0
github.com/mandloideep/inboxgate toolchain@go1.26.6
github.com/mandloideep/inboxgate turso.tech/database/tursogo-serverless@v0.0.0-20260817122138-24adc316cdc4
github.com/google/jsonschema-go@v0.4.3 github.com/google/go-cmp@v0.7.0
github.com/google/jsonschema-go@v0.4.3 go@1.23.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/golang-jwt/jwt/v5@v5.3.1
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/google/go-cmp@v0.7.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/google/jsonschema-go@v0.4.3
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/segmentio/encoding@v0.5.4
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/yosida95/uritemplate/v3@v3.0.2
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/oauth2@v0.35.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/time@v0.15.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/tools@v0.42.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 github.com/segmentio/asm@v1.1.3
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/sync@v0.20.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 golang.org/x/sys@v0.41.0
github.com/modelcontextprotocol/go-sdk@v1.7.0 go@1.25.0
github.com/segmentio/asm@v1.1.3 golang.org/x/sys@v0.0.0-20211110154304-99a53858aa08
github.com/segmentio/encoding@v0.5.4 github.com/segmentio/asm@v1.1.3
github.com/segmentio/encoding@v0.5.4 golang.org/x/sys@v0.0.0-20211110154304-99a53858aa08
github.com/segmentio/encoding@v0.5.4 go@1.23
go@1.26.0 toolchain@go1.26.0
golang.org/x/oauth2@v0.36.0 cloud.google.com/go/compute/metadata@v0.3.0
golang.org/x/oauth2@v0.36.0 go@1.25.0
golang.org/x/sync@v0.20.0 go@1.25.0
golang.org/x/sys@v0.41.0 go@1.24.0
golang.org/x/time@v0.15.0 go@1.25.0
turso.tech/database/tursogo-serverless@v0.0.0-20260817122138-24adc316cdc4 go@1.24.0
`
	if string(output) != wantGraph {
		t.Errorf("module graph = %q, want exact reviewed graph %q", output, wantGraph)
	}

	notices, err := os.ReadFile(filepath.Join(repositoryRoot(t), "THIRD_PARTY_NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{
		"`github.com/modelcontextprotocol/go-sdk` v1.7.0",
		"`github.com/golang-jwt/jwt/v5` v5.3.1",
		"`github.com/google/go-cmp` v0.7.0",
		"`github.com/google/jsonschema-go` v0.4.3",
		"`github.com/segmentio/encoding` v0.5.4",
		"`github.com/segmentio/asm` v1.1.3",
		"`github.com/yosida95/uritemplate/v3` v3.0.2",
		"`golang.org/x/time` v0.15.0",
		"`golang.org/x/tools` v0.42.0",
		"`golang.org/x/sync` v0.20.0",
		"`golang.org/x/sys` v0.41.0",
	} {
		if !strings.Contains(string(notices), module) {
			t.Errorf("distribution notices omit %q", module)
		}
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
