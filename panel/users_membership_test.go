package panel

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ildarmaga/wdtt/pkg/paneldb"
)

func TestMembershipUpdatePreservesUserSettings(t *testing.T) {
	oldDB, oldPath, oldDir := panelDB, panelDBPath, wdttConfigDir
	wdttConfigDir = t.TempDir()
	panelDBPath = filepath.Join(wdttConfigDir, "panel.db")
	defer func() {
		if panelDB != nil {
			panelDB.Close()
		}
		panelDB, panelDBPath, wdttConfigDir = oldDB, oldPath, oldDir
	}()
	if err := initPanelDB(); err != nil {
		t.Fatal(err)
	}
	ensureDefaultWdttData()
	if _, err := panelDB.Exec(`INSERT INTO wdtt_users(password,sub_id,comment,total_bytes,is_deactivated,expires_at,max_devices) VALUES('member','membership-test','Keep',123456,1,1999999999,4)`); err != nil {
		t.Fatal(err)
	}
	a := &App{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"old_password":"member","inbounds":["qwdtt","freeturn"]}`))
	a.handleUserUpdate(w, r)
	var result struct {
		Success bool   `json:"success"`
		Message string `json:"msg"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.Success {
		t.Fatalf("update: %s %v", w.Body.String(), err)
	}
	s, err := paneldb.LoadStore(panelDB)
	if err != nil {
		t.Fatal(err)
	}
	u := s.Users["member"]
	if u.Comment != "Keep" || u.TotalBytes != 123456 || !u.IsDeactivated || u.ExpiresAt != 1999999999 || u.MaxDevices != 4 {
		t.Fatalf("membership reset user settings: %+v", u)
	}
	selected, err := paneldb.UserProtocols(panelDB, "membership-test")
	if err != nil || len(selected) != 2 {
		t.Fatalf("inbounds: %v %v", selected, err)
	}
}
