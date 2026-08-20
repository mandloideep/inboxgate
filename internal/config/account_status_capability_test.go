package config

import (
	"reflect"
	"testing"
)

func TestAccountStatusCapabilityIsExactAndOperatorGated(t *testing.T) {
	configuration := Defaults()
	configuration.Database.URLEnv = "SYNTHETIC_DATABASE_URL"
	configuration.Database.AuthTokenEnv = "SYNTHETIC_DATABASE_TOKEN"
	configuration.MCP.BearerTokenEnv = "SYNTHETIC_MCP_TOKEN"

	assertAccountStatus := func(t *testing.T, configuration Config, wantStatus ConfigurationStatus, wantEnabled bool) {
		t.Helper()
		registry := CapabilityRegistry(configuration)
		var matches []Capability
		for _, capability := range registry {
			if capability.Name == CapabilitySystemAccountStatus {
				matches = append(matches, capability)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("system.account_status entries = %d", len(matches))
		}
		migration := "0004_account_lifecycle.sql"
		want := Capability{
			Name: CapabilitySystemAccountStatus, ImplementationStatus: ImplementationStatusImplemented,
			ConfigurationStatus: wantStatus, Enabled: wantEnabled,
			RequiredSecretNames:       []string{"SYNTHETIC_DATABASE_TOKEN", "SYNTHETIC_DATABASE_URL", "SYNTHETIC_MCP_TOKEN"},
			RequiredDatabaseMigration: &migration, SecurityClassification: SecuritySensitiveRead,
		}
		if !reflect.DeepEqual(matches[0], want) {
			t.Fatalf("system.account_status = %#v, want %#v", matches[0], want)
		}
	}

	assertAccountStatus(t, configuration, ConfigurationStatusDisabled, false)
	configuration.MCP.Enabled = true
	assertAccountStatus(t, configuration, ConfigurationStatusDisabled, false)
	configuration.MCP.EnableOperatorTools = true
	assertAccountStatus(t, configuration, ConfigurationStatusEnabled, true)
	configuration.MCP.Enabled = false
	assertAccountStatus(t, configuration, ConfigurationStatusDisabled, false)
}

func TestAccountStatusCapabilityAddsNoConfigurationKeyOrOtherActivation(t *testing.T) {
	configuration := Defaults()
	configuration.MCP.Enabled = true
	configuration.MCP.EnableOperatorTools = true
	registry := CapabilityRegistry(configuration)
	for _, capability := range registry {
		if capability.Name == CapabilitySystemAccountStatus || capability.Name == CapabilitySystemCapabilities {
			continue
		}
		if capability.Name == CapabilityMailReviewRead {
			if capability.Enabled {
				t.Fatalf("operator gate activated review read capability %#v", capability)
			}
			continue
		}
		if capability.ImplementationStatus == ImplementationStatusImplemented || capability.Enabled {
			t.Fatalf("operator gate activated unrelated capability %#v", capability)
		}
	}
}
