package panel

import (
	"github.com/ildarmaga/wdtt/pkg/paneldb"
	"path/filepath"
	"testing"
)

func TestInstallationCreatesOneStableDefaultSubscription(t *testing.T) {
	previousDB, previousPath, previousDir := panelDB, panelDBPath, wdttConfigDir
	wdttConfigDir = t.TempDir()
	panelDBPath = filepath.Join(wdttConfigDir, "panel.db")
	defer func() {
		if panelDB != nil {
			panelDB.Close()
		}
		panelDB, panelDBPath, wdttConfigDir = previousDB, previousPath, previousDir
	}()
	if err := initPanelDB(); err != nil {
		t.Fatal(err)
	}
	ensureDefaultWdttData()
	t.Setenv("WDTT_BACKEND_PORT", "2860")
	t.Setenv("WDTT_SUB_PORT", "2096")
	t.Setenv("WDTT_PUBLIC_URL", "https://panel.example.com")
	t.Setenv("WDTT_INITIAL_PASSWORD", "test-installation-password")
	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	first, err := paneldb.LoadStore(panelDB)
	if err != nil {
		t.Fatal(err)
	}
	password := first.MainPassword
	if first.MainPassword == "" || first.Users[password] == nil || first.Users[password].SubID == "" {
		t.Fatal("owner or default subscription not seeded")
	}
	id := first.Users[password].SubID
	inbound, err := loadWdttInbound()
	if err != nil {
		t.Fatal(err)
	}
	inbound.MaxUsers = 123
	inbound.ServerHost = "vpn.example.com"
	if err := saveWdttInbound(inbound); err != nil {
		t.Fatal(err)
	}

	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	restored, err := loadWdttInbound()
	if err != nil || restored.MaxUsers != 123 || restored.ServerHost != "vpn.example.com" {
		t.Fatal("reinstall reset inbound settings", err)
	}
	second, err := paneldb.LoadStore(panelDB)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Users) != len(first.Users) || second.Users[password].SubID != id {
		t.Fatal("reinstallation changed default user identity")
	}
	if len(first.Users) != 1 {
		t.Fatal("installation created a second main subscription")
	}
	selected := []string{"qwdtt", "freeturn"}
	if err := paneldb.SetUserProtocols(panelDB, id, selected); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	actual, err := paneldb.UserProtocols(panelDB, id)
	if err != nil || len(actual) != 2 || actual[0] != "qwdtt" {
		t.Fatal("reinstall reset chosen inbounds", actual, err)
	}
}
