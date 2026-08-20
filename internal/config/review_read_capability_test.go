package config

import (
	"reflect"
	"testing"
)

func TestMailReviewReadCapabilityIsExactAndDualGated(t *testing.T) {
	configuration := Defaults()
	configuration.Database.URLEnv = "SYNTHETIC_DATABASE_URL"
	configuration.Database.AuthTokenEnv = "SYNTHETIC_DATABASE_TOKEN"
	configuration.MCP.BearerTokenEnv = "SYNTHETIC_MCP_TOKEN"

	assert := func(t *testing.T, wantStatus ConfigurationStatus, wantEnabled bool) {
		t.Helper()
		var matches []Capability
		for _, capability := range CapabilityRegistry(configuration) {
			if capability.Name == CapabilityMailReviewRead {
				matches = append(matches, capability)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("mail.review_read entries = %d", len(matches))
		}
		migration := "0006_gate_decisions.sql"
		want := Capability{
			Name: CapabilityMailReviewRead, ImplementationStatus: ImplementationStatusImplemented,
			ConfigurationStatus: wantStatus, Enabled: wantEnabled,
			RequiredSecretNames:       []string{"SYNTHETIC_DATABASE_TOKEN", "SYNTHETIC_DATABASE_URL", "SYNTHETIC_MCP_TOKEN"},
			RequiredDatabaseMigration: &migration, SecurityClassification: SecuritySensitiveRead,
		}
		if !reflect.DeepEqual(matches[0], want) {
			t.Fatalf("mail.review_read = %#v, want %#v", matches[0], want)
		}
	}

	assert(t, ConfigurationStatusDisabled, false)
	configuration.MCP.Enabled = true
	assert(t, ConfigurationStatusDisabled, false)
	configuration.Capabilities.MailReviewRead = true
	assert(t, ConfigurationStatusEnabled, true)
	configuration.MCP.Enabled = false
	assert(t, ConfigurationStatusDisabled, false)
}

func TestMailReviewReadAddsNoYAMLKeyOrUnrelatedAuthority(t *testing.T) {
	configuration := Defaults()
	configuration.MCP.Enabled = true
	configuration.Capabilities.MailReviewRead = true
	for _, capability := range CapabilityRegistry(configuration) {
		if capability.Name == CapabilityMailReviewRead || capability.Name == CapabilitySystemAccountStatus || capability.Name == CapabilitySystemCapabilities {
			continue
		}
		if capability.ImplementationStatus == ImplementationStatusImplemented || capability.Enabled {
			t.Fatalf("review read activated unrelated capability %#v", capability)
		}
	}
	if configuration.MCP.EnableReviewWrites {
		configuration.MCP.EnableReviewWrites = false
	}
	if registry := CapabilityRegistry(configuration); !capabilityNamed(registry, CapabilityMailReviewRead).Enabled {
		t.Fatal("review-write policy changed read capability")
	}
}

func capabilityNamed(registry []Capability, name CapabilityName) Capability {
	for _, capability := range registry {
		if capability.Name == name {
			return capability
		}
	}
	return Capability{}
}
