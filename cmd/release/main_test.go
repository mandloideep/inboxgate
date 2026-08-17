package main

import (
	"strings"
	"testing"

	"github.com/mandloideep/inboxgate/internal/releasebuild"
)

func TestWriteTargetsUsesCanonicalReleaseMatrix(t *testing.T) {
	t.Parallel()

	var output strings.Builder
	if err := writeTargets(&output); err != nil {
		t.Fatalf("writeTargets() error = %v", err)
	}

	var want strings.Builder
	for _, target := range releasebuild.Targets {
		want.WriteString(target.GOOS)
		want.WriteByte('/')
		want.WriteString(target.GOARCH)
		want.WriteByte('\n')
	}
	if output.String() != want.String() {
		t.Fatalf("writeTargets() = %q, want %q", output.String(), want.String())
	}
}
