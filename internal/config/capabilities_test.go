package config

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCapabilityDefinitionsControlValidationAndRegistry(t *testing.T) {
	configuration := Defaults()
	configuration.Capabilities.GmailRead = true
	definition := capabilityDefinition{
		Name:                   CapabilityGmailRead,
		ConfigBinding:          capabilityConfigGmailRead,
		ImplementationStatus:   ImplementationStatusImplemented,
		Prerequisites:          capabilityPrerequisitesGmail,
		SecurityClassification: SecuritySensitiveRead,
	}

	var problems []Problem
	validateCapabilityDefinitions(configuration, []capabilityDefinition{definition}, &problems)
	if len(problems) != 0 {
		t.Fatalf("implemented configurable definition rejected true: %v", problems)
	}
	registry := capabilityRegistryFromDefinitions(configuration, []capabilityDefinition{definition})
	if len(registry) != 1 || registry[0].ConfigurationStatus != ConfigurationStatusEnabled || !registry[0].Enabled {
		t.Fatalf("implemented configurable registry = %#v", registry)
	}

	definition.ImplementationStatus = ImplementationStatusNotImplemented
	problems = nil
	validateCapabilityDefinitions(configuration, []capabilityDefinition{definition}, &problems)
	if len(problems) != 1 || problems[0].Path != "capabilities.gmail.read" || problems[0].Reason != "cannot enable a capability not implemented by this binary" {
		t.Fatalf("not-implemented configurable problems = %#v", problems)
	}
	registry = capabilityRegistryFromDefinitions(configuration, []capabilityDefinition{definition})
	if len(registry) != 1 || registry[0].ConfigurationStatus != ConfigurationStatusEnabled || registry[0].Enabled {
		t.Fatalf("not-implemented configurable registry = %#v", registry)
	}
}

func TestCapabilityRegistryDefaultContract(t *testing.T) {
	registry := CapabilityRegistry(Defaults())
	wantNames := []CapabilityName{
		CapabilityGmailBackfill,
		CapabilityGmailCurrentSync,
		CapabilityGmailModify,
		CapabilityGmailRead,
		CapabilityMailReviewRead,
		CapabilityMailReviewWrite,
		CapabilitySystemCapabilities,
		CapabilityVikunjaWrite,
		CapabilityZohoRead,
	}
	if len(registry) != len(wantNames) {
		t.Fatalf("registry length = %d, want %d", len(registry), len(wantNames))
	}
	for index, capability := range registry {
		if capability.Name != wantNames[index] {
			t.Errorf("registry[%d].Name = %q, want %q", index, capability.Name, wantNames[index])
		}
		if capability.ImplementationStatus == ImplementationStatusNotImplemented && capability.Enabled {
			t.Errorf("not-implemented capability %q is enabled", capability.Name)
		}
		if capability.RequiredSecretNames == nil {
			t.Errorf("capability %q has nil required secret names", capability.Name)
		}
		if capability.RequiredDatabaseMigration != nil {
			t.Errorf("capability %q migration = %q, want nil", capability.Name, *capability.RequiredDatabaseMigration)
		}
	}
	system := registry[6]
	if system.ImplementationStatus != ImplementationStatusImplemented || system.ConfigurationStatus != ConfigurationStatusNotConfigurable || !system.Enabled || system.SecurityClassification != SecurityOperationalMetadata {
		t.Errorf("system capability = %#v", system)
	}
	modify := registry[2]
	if modify.ConfigurationStatus != ConfigurationStatusNotConfigurable || modify.SecurityClassification != SecurityProhibited || modify.Enabled {
		t.Errorf("Gmail mutation capability = %#v", modify)
	}
}

func TestCapabilityRegistryReturnsFreshSnapshot(t *testing.T) {
	first := CapabilityRegistry(Defaults())
	original := CapabilityRegistry(Defaults())
	first[0].Name = CapabilityName("mutated")
	if len(first[0].RequiredSecretNames) != 0 {
		first[0].RequiredSecretNames[0] = "MUTATED_SECRET_NAME"
	}
	second := CapabilityRegistry(Defaults())
	if !reflect.DeepEqual(second, original) {
		t.Errorf("registry shared mutable state:\n got %#v\nwant %#v", second, original)
	}
}

func TestCapabilitiesJSONContract(t *testing.T) {
	data, err := CapabilitiesJSON(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("}\n")) || bytes.HasSuffix(data, []byte("}\n\n")) {
		t.Fatalf("JSON must have exactly one final newline: %q", data[len(data)-4:])
	}
	var envelope struct {
		OutputVersion              uint64       `json:"output_version"`
		ConfigurationSchemaVersion uint64       `json:"configuration_schema_version"`
		Capabilities               []Capability `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OutputVersion != 1 || envelope.ConfigurationSchemaVersion != 1 || !reflect.DeepEqual(envelope.Capabilities, CapabilityRegistry(Defaults())) {
		t.Errorf("capability envelope = %#v", envelope)
	}
	output := string(data)
	assertCapabilityOrdered(t, output, []string{`"output_version"`, `"configuration_schema_version"`, `"capabilities"`})
	firstEntry := output[strings.Index(output, "{\n      \"name\""):]
	assertCapabilityOrdered(t, firstEntry, []string{`"name"`, `"implementation_status"`, `"configuration_status"`, `"enabled"`, `"required_secret_names"`, `"required_database_migration"`, `"security_classification"`})
}

func TestCapabilitiesConfigurationIsFailClosed(t *testing.T) {
	configurable := []string{
		"gmail.read",
		"gmail.current_sync",
		"gmail.backfill",
		"mail.review_read",
		"mail.review_write",
	}
	for _, name := range configurable {
		t.Run(strings.ReplaceAll(name, ".", "_"), func(t *testing.T) {
			configuration, err := Parse([]byte("version: 1\ncapabilities:\n  " + name + ": false\n"))
			if err != nil {
				t.Fatalf("explicit false rejected: %v", err)
			}
			for _, capability := range CapabilityRegistry(configuration) {
				if capability.Name == CapabilityName(name) && (capability.ConfigurationStatus != ConfigurationStatusDisabled || capability.Enabled) {
					t.Errorf("explicit false registry entry = %#v", capability)
				}
			}

			_, err = Parse([]byte("version: 1\ncapabilities:\n  " + name + ": true\n"))
			want := name + ": cannot enable a capability not implemented by this binary"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("explicit true error = %v, want %q", err, want)
			}
		})
	}

	for _, name := range []string{"gmail.modify", "zoho.read", "vikunja.write", "system.capabilities", "gmail.typo", "arbitrary.name"} {
		t.Run("unknown_"+strings.ReplaceAll(name, ".", "_"), func(t *testing.T) {
			_, err := Parse([]byte("version: 1\ncapabilities:\n  " + name + ": false\n"))
			if err == nil || !strings.Contains(err.Error(), "capabilities") || !strings.Contains(err.Error(), "unknown key") {
				t.Fatalf("excluded key error = %v", err)
			}
		})
	}

	_, err := Parse([]byte("version: 1\ncapabilities:\n  gmail.read: false\n  gmail.read: false\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate capability key error = %v", err)
	}
}

func TestPolicyBooleansDoNotBypassCapabilityGate(t *testing.T) {
	configuration, err := Parse([]byte("version: 1\nbackfill: {enabled: true}\nmcp: {enabled: true, enable_review_writes: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range CapabilityRegistry(configuration) {
		if capability.Name != CapabilitySystemCapabilities && capability.Enabled {
			t.Errorf("subordinate policy enabled capability %#v", capability)
		}
	}
}

func TestCapabilitiesJSONUsesEnvironmentNamesWithoutValues(t *testing.T) {
	const sentinel = "SYNTHETIC_VALUE_MUST_NOT_APPEAR"
	configuration, err := Parse([]byte(`version: 1
database: {url_env: CUSTOM_DATABASE_URL, auth_token_env: CUSTOM_DATABASE_TOKEN}
gmail: {oauth_client_id_env: CUSTOM_CLIENT_ID, oauth_client_secret_env: CUSTOM_CLIENT_SECRET, oauth_redirect_url_env: CUSTOM_REDIRECT_URL}
encryption: {master_key_env: CUSTOM_MASTER_KEY}
`))
	if err != nil {
		t.Fatal(err)
	}
	customNames := []string{"CUSTOM_DATABASE_URL", "CUSTOM_DATABASE_TOKEN", "CUSTOM_CLIENT_ID", "CUSTOM_CLIENT_SECRET", "CUSTOM_REDIRECT_URL", "CUSTOM_MASTER_KEY"}
	for _, name := range customNames {
		previous, existed := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		name := name
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(name, previous)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
	withoutValues, err := CapabilitiesJSON(configuration)
	if err != nil {
		t.Fatal(err)
	}
	for index, name := range customNames {
		if err := os.Setenv(name, sentinel+string(rune('A'+index))+name); err != nil {
			t.Fatal(err)
		}
	}
	withValues, err := CapabilitiesJSON(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withoutValues, withValues) {
		t.Fatalf("capabilities output changed when YAML-derived environment names became set:\nunset:\n%s\nset:\n%s", withoutValues, withValues)
	}
	if strings.Contains(string(withValues), sentinel) {
		t.Fatalf("capabilities output contains a named environment value: %s", withValues)
	}
	for _, name := range customNames {
		if !strings.Contains(string(withValues), `"`+name+`"`) {
			t.Errorf("capabilities output omits environment name %q", name)
		}
	}

	gmailSecrets := []string{"CUSTOM_CLIENT_ID", "CUSTOM_CLIENT_SECRET", "CUSTOM_DATABASE_TOKEN", "CUSTOM_DATABASE_URL", "CUSTOM_MASTER_KEY", "CUSTOM_REDIRECT_URL"}
	reviewSecrets := []string{"CUSTOM_DATABASE_TOKEN", "CUSTOM_DATABASE_URL"}
	registry := CapabilityRegistry(configuration)
	for _, capability := range registry {
		var want []string
		switch capability.Name {
		case CapabilityGmailBackfill, CapabilityGmailCurrentSync, CapabilityGmailRead:
			want = gmailSecrets
		case CapabilityMailReviewRead, CapabilityMailReviewWrite:
			want = reviewSecrets
		default:
			want = []string{}
		}
		if !reflect.DeepEqual(capability.RequiredSecretNames, want) {
			t.Errorf("%s required secret names = %#v, want %#v", capability.Name, capability.RequiredSecretNames, want)
		}
		for _, defaultName := range []string{"GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_OAUTH_REDIRECT_URL", "INBOXGATE_MASTER_KEY", "TURSO_AUTH_TOKEN", "TURSO_DATABASE_URL"} {
			if slicesContain(capability.RequiredSecretNames, defaultName) {
				t.Errorf("%s retained default environment name %q", capability.Name, defaultName)
			}
		}
	}
}

func slicesContain(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func assertCapabilityOrdered(t *testing.T, output string, values []string) {
	t.Helper()
	previous := -1
	for _, value := range values {
		index := strings.Index(output[previous+1:], value)
		if index < 0 {
			t.Fatalf("output does not contain %q after previous fields", value)
		}
		previous += index + 1
	}
}
