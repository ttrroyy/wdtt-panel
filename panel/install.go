package panel

import (
	"crypto/rand"
	"fmt"
	"github.com/ildarmaga/wdtt/pkg/paneldb"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
	"strings"
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
		selected := []string{}
		for _, name := range strings.Split(os.Getenv("WDTT_INITIAL_INBOUNDS"), ",") {
			if name != "" {
				selected = append(selected, name)
			}
		}
		if err := paneldb.SetUserProtocols(panelDB, store.Users[store.MainPassword].SubID, selected); err != nil {
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
	if err := ensureInstallationPaths(cfg); err != nil {
		return err
	}
	cfg.SubURI = ""
	for key, target := range map[string]*int{"WDTT_BACKEND_PORT": &cfg.Port} {
		value, err := strconv.Atoi(os.Getenv(key))
		if err != nil || value < 1024 || value > 65535 {
			return fmt.Errorf("invalid %s", key)
		}
		*target = value
	}
	cfg.SubPort = cfg.Port
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

func randomInstallationPath() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var seed [1]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return "", err
	}
	length := 17 + int(seed[0]&7)
	out := make([]byte, 0, length)
	for len(out) < length {
		var buffer [32]byte
		if _, err := rand.Read(buffer[:]); err != nil {
			return "", err
		}
		for _, v := range buffer {
			if v < 248 {
				out = append(out, alphabet[int(v)%len(alphabet)])
				if len(out) == length {
					break
				}
			}
		}
	}
	return "/" + string(out) + "/", nil
}

func ensureInstallationPaths(cfg *PanelConfig) error {
	legacyPanel := cfg.WebBasePath == "" || cfg.WebBasePath == "/wdtt/" || cfg.WebBasePath == "/"
	legacySub := cfg.SubPath == "" || cfg.SubPath == "/sub/" || cfg.SubPath == cfg.basePath()+"sub/"
	var err error
	if legacyPanel {
		cfg.WebBasePath, err = randomInstallationPath()
		if err != nil {
			return err
		}
	}
	if legacySub || cfg.SubPath == cfg.WebBasePath {
		cfg.SubPath, err = randomInstallationPath()
		if err != nil {
			return err
		}
	}
	for cfg.SubPath == cfg.WebBasePath {
		cfg.SubPath, err = randomInstallationPath()
		if err != nil {
			return err
		}
	}
	return nil
}
