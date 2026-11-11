package panel

import (
	"fmt"
	"github.com/ildarmaga/wdtt/pkg/paneldb"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
)

// ConfigureInstallation seeds configuration before any public listener is opened.
func ConfigureInstallation() error {
	store, err := paneldb.LoadStore(panelDB)
	if err != nil {
		return err
	}
	if store.MainPassword == "" {
		store.MainPassword = randomHex(16)
	}
	if store.Users[store.MainPassword] == nil {
		store.Users[store.MainPassword] = &paneldb.User{MaxDevices: 1, Comment: paneldb.MainUserComment}
	}
	if store.Users[store.MainPassword].SubID == "" {
		subID, err := genSubID()
		if err != nil {
			return err
		}
		store.Users[store.MainPassword].SubID = subID
	}
	if err := paneldb.SaveStore(panelDB, store, paneldb.SaveOptions{PreserveSubIDs: true}); err != nil {
		return err
	}
	var initialized int
	if err := panelDB.QueryRow(`SELECT COUNT(*) FROM vpn_user_inbounds WHERE sub_id=?`, store.Users[store.MainPassword].SubID).Scan(&initialized); err != nil {
		return err
	}
	if initialized == 0 {
		if err := paneldb.SetUserProtocols(panelDB, store.Users[store.MainPassword].SubID, paneldb.VPNProtocols); err != nil {
			return err
		}
	}
	cfg, err := loadPanelConfig()
	if err != nil {
		return err
	}
	cfg.WebListen = "127.0.0.1"
	cfg.SubListen = "127.0.0.1"
	cfg.WebCertFile, cfg.WebKeyFile = "", ""
	cfg.SubCertFile, cfg.SubKeyFile = "", ""
	cfg.SubURI = os.Getenv("WDTT_PUBLIC_URL") + "/wdtt/sub"
	for key, target := range map[string]*int{"WDTT_BACKEND_PORT": &cfg.Port, "WDTT_SUB_PORT": &cfg.SubPort} {
		value, err := strconv.Atoi(os.Getenv(key))
		if err != nil || value < 1024 || value > 65535 {
			return fmt.Errorf("invalid %s", key)
		}
		*target = value
	}
	if password := os.Getenv("WDTT_INITIAL_PASSWORD"); password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		cfg.PasswordHash = string(hash)
	}
	if err := savePanelConfig(cfg); err != nil {
		return err
	}
	inbound, err := loadWdttInbound()
	if err != nil {
		return err
	}
	if initialized == 0 {
		inbound.MaxUsers = maxUsersSubnetLimit
	}
	return saveWdttInbound(inbound)
}
