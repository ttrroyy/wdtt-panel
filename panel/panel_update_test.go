package panel

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPanelRuntimeUpdateCanRestoreExistingFiles(t *testing.T) {
	root := t.TempDir()
	next, dest := filepath.Join(root, "next"), filepath.Join(root, "live")
	for _, dir := range []string{next, dest} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"protocols.py", "edge_protocols.py", "fleet.py", "frontend.py", "preflight.py", "uninstall.py", "panel-firewall.py", "node-source.tar.gz"} {
		if err := os.WriteFile(filepath.Join(next, name), []byte("new"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	existing := filepath.Join(dest, "protocols.py")
	if err := os.WriteFile(existing, []byte("old"), 0755); err != nil {
		t.Fatal(err)
	}
	restore, err := replacePanelRuntime(next, dest)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "new" {
		t.Fatalf("install: %q, %v", data, err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "old" {
		t.Fatalf("restore: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "node-source.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("new file survived rollback: %v", err)
	}
}

func TestPanelReleaseBinName(t *testing.T) {
	name := panelReleaseBinName()
	switch runtime.GOARCH {
	case "arm64":
		if name != "wdtt-linux-arm64" {
			t.Fatalf("got %q want wdtt-linux-arm64", name)
		}
	default:
		if name != "wdtt-linux-amd64" {
			t.Fatalf("got %q want wdtt-linux-amd64", name)
		}
	}
}

func TestPanelInstallPathUnifiedFallback(t *testing.T) {
	if serviceUnitExists(panelServiceUnit) {
		t.Skip("legacy wdtt-panel.service present")
	}
	path := panelInstallPath()
	if path != wdttServerBin && path != "/usr/local/bin/wdtt" && path != "/usr/local/bin/wdtt-app" {
		t.Fatalf("unexpected install path: %s", path)
	}
}
