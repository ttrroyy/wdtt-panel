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
	var password string
	if err := panelDB.QueryRow(`SELECT value FROM settings WHERE key='default_subscription_password'`).Scan(&password); err != nil {
		t.Fatal(err)
	}
	first, err := paneldb.LoadStore(panelDB)
	if err != nil {
		t.Fatal(err)
	}
	if first.MainPassword == "" || first.Users[password] == nil || first.Users[password].SubID == "" {
		t.Fatal("owner or default subscription not seeded")
	}
	id := first.Users[password].SubID
	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	second, err := paneldb.LoadStore(panelDB)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Users) != len(first.Users) || second.Users[password].SubID != id {
		t.Fatal("reinstallation changed default user identity")
	}
	if _, err := panelDB.Exec(`DELETE FROM wdtt_users WHERE password=?`, password); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	third, err := paneldb.LoadStore(panelDB)
	if err != nil {
		t.Fatal(err)
	}
	if third.Users[password] != nil {
		t.Fatal("explicitly deleted user was recreated")
	}
}
