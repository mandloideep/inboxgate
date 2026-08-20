package config

import (
	"strings"
	"testing"
)

func TestMCPPathRejectsHealthProbeCollisionsWhenEnabledOrDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, path := range []string{"/health/live", "/health/ready"} {
			document := "version: 1\nmcp:\n  enabled: " + map[bool]string{false: "false", true: "true"}[enabled] + "\n  path: " + path + "\n"
			_, err := Parse([]byte(document))
			if err == nil || !strings.Contains(err.Error(), "mcp.path") {
				t.Errorf("enabled=%t path=%q error = %v, want reserved-path rejection", enabled, path, err)
			}
		}
	}
}
