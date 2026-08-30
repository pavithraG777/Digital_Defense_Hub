package recovery

import "testing"

func TestAllowedRecoveryActions(t *testing.T) {
	for _, action := range []string{"ISOLATE_DEVICE", "RESTORE_FILE", "ROTATE_CREDENTIAL", "BLOCK_IOC", "RECONNECT_DEVICE"} {
		if !allowedAction(action) {
			t.Fatalf("expected %s to be allowed", action)
		}
	}
	for _, action := range []string{"RUN_COMMAND", "DELETE_DATABASE", "", "ARBITRARY_SCRIPT"} {
		if allowedAction(action) {
			t.Fatalf("unsafe action %s must be rejected", action)
		}
	}
}
