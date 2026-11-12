package panel

import "testing"

func TestSavedInboundPreservesDeploymentRole(t *testing.T) {
	for role, want := range map[string]string{"node": " -node-only", "panel": " -panel-only", "combined": "", "": ""} {
		if got := wdttRoleArgs(role); got != want {
			t.Fatalf("%s changed role to %q", role, got)
		}
	}
}
