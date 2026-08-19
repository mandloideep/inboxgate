package releasebuild

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSBOMRejectsJSONKeyDifferentialsAtEveryDepth(t *testing.T) {
	valid := string(validSBOMJSON(t))
	duplicateCreated := replaceSBOMJSONOnce(t, valid, `"created":"2026-08-16T00:00:00Z"`, `"created":"2026-08-16T00:00:00Z","created":"2026-08-16T00:00:00Z"`)
	duplicateFileName := replaceSBOMJSONOnce(t, valid,
		`"fileName":"inboxgate_0.1.0_darwin_amd64/inboxgate"`,
		`"fileName":"inboxgate_0.1.0_darwin_amd64/inboxgate","fileName":"inboxgate_0.1.0_darwin_amd64/inboxgate"`)
	packageNameAlias := replaceSBOMJSONFirst(t, valid,
		`"name":"github.com/mandloideep/inboxgate"`,
		`"Name":"ignored","name":"github.com/mandloideep/inboxgate"`)
	tests := []struct {
		name string
		raw  string
	}{
		{name: "duplicate packages", raw: `{"packages":[],` + valid[1:]},
		{name: "packages case alias", raw: `{"PACKAGES":[],` + valid[1:]},
		{name: "package name case alias", raw: packageNameAlias},
		{name: "duplicate creation key", raw: duplicateCreated},
		{name: "duplicate file key", raw: duplicateFileName},
		{name: "duplicate unrelated nested key", raw: `{"unrelated":{"value":1,"value":2},` + valid[1:]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRawSBOM(t, test.raw); err == nil {
				t.Fatal("ValidateSBOM accepted a JSON key differential")
			}
		})
	}
}

func TestValidateSBOMRejectsEveryRecognizedFieldCaseAliasAtNestedDepth(t *testing.T) {
	recognized := []string{
		"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages", "files",
		"created", "creators", "versionInfo", "sourceInfo", "downloadLocation", "licenseConcluded", "licenseDeclared",
		"copyrightText", "filesAnalyzed", "fileName",
	}
	valid := string(validSBOMJSON(t))
	for _, field := range recognized {
		alias := nonExactJSONKeyAlias(field)
		t.Run(field, func(t *testing.T) {
			raw := `{"unrelated":{"nested":{"` + alias + `":null}},` + valid[1:]
			if err := validateRawSBOM(t, raw); err == nil {
				t.Fatalf("ValidateSBOM accepted case alias %q for %q", alias, field)
			}
		})
	}
}

func TestValidateSBOMPreservesUniqueUnrelatedSPDXFields(t *testing.T) {
	valid := string(validSBOMJSON(t))
	raw := `{"unrelated":{"nested":{"CamelCase":true,"lowercase":"allowed"}},` + valid[1:]
	if err := validateRawSBOM(t, raw); err != nil {
		t.Fatalf("ValidateSBOM rejected unique unrelated SPDX fields: %v", err)
	}
}

func validateRawSBOM(t *testing.T, raw string) error {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "sbom.spdx.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return ValidateSBOM(path, "v0.1.0", directory)
}

func replaceSBOMJSONOnce(t *testing.T, value, old, replacement string) string {
	t.Helper()
	if strings.Count(value, old) != 1 {
		t.Fatalf("SBOM fixture occurrence count for %q = %d, want 1", old, strings.Count(value, old))
	}
	return strings.Replace(value, old, replacement, 1)
}

func replaceSBOMJSONFirst(t *testing.T, value, old, replacement string) string {
	t.Helper()
	if !strings.Contains(value, old) {
		t.Fatalf("SBOM fixture does not contain %q", old)
	}
	return strings.Replace(value, old, replacement, 1)
}

func nonExactJSONKeyAlias(field string) string {
	if field == "SPDXID" {
		return "spdxid"
	}
	first := field[0]
	if first >= 'a' && first <= 'z' {
		return string(first-'a'+'A') + field[1:]
	}
	return strings.ToLower(field)
}
