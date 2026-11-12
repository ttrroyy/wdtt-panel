package panel

import (
	"github.com/ildarmaga/wdtt/pkg/paneldb"
	"path/filepath"
	"regexp"
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
	t.Setenv("WDTT_INITIAL_INBOUNDS", "wdtt,qwdtt")
	t.Setenv("WDTT_PUBLIC_URL", "http://127.0.0.1:2860")
	t.Setenv("WDTT_INITIAL_PASSWORD", "test-installation-password")
	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadPanelConfig()
	if err != nil || cfg.WebListen != "127.0.0.1" || cfg.SubListen != "127.0.0.1" || cfg.SubPort != cfg.Port || !regexp.MustCompile(`^/[A-Za-z0-9]{17,24}/$`).MatchString(cfg.SubPath) || !regexp.MustCompile(`^/[A-Za-z0-9]{17,24}/$`).MatchString(cfg.WebBasePath) || cfg.SubPath == cfg.WebBasePath || cfg.SubURI != "" {
		t.Fatal("installation must use one loopback listener", cfg, err)
	}
	if panelListenAddr(&PanelConfig{WebListen: "0.0.0.0", Port: 2860}) != "127.0.0.1:2860" {
		t.Fatal("public panel listener accepted")
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
	reinstalledCfg, _ := loadPanelConfig()
	if reinstalledCfg.WebBasePath != cfg.WebBasePath || reinstalledCfg.SubPath != cfg.SubPath {
		t.Fatal("reinstall changed public paths")
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
