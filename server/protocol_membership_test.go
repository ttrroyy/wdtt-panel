package server

import (
	"github.com/ildarmaga/wdtt/pkg/paneldb"
	"testing"
)

func TestRemovedNativeMembershipDeniesMainCredentials(t *testing.T) {
	conn := setupStoreAdminPanelDB(t)
	if err := paneldb.EnsureWDTTSchema(conn); err != nil {
		t.Fatal(err)
	}
	if err := paneldb.UpsertUser(conn, "main", "main", &paneldb.User{SubID: "main-sub"}); err != nil {
		t.Fatal(err)
	}
	if err := paneldb.SetUserProtocols(conn, "main-sub", []string{"qwdtt", "freeturn"}); err != nil {
		t.Fatal(err)
	}
	incoming, _, err := loadDatabaseFromSQLite()
	if err != nil {
		t.Fatal(err)
	}
	if !incoming.Passwords["main"].NativeDisabled || incoming.Passwords["main"].IsDeactivated {
		t.Fatal("membership must suspend only native WDTT")
	}
	dbMutex.Lock()
	previous := db
	db = incoming
	dbMutex.Unlock()
	defer func() { dbMutex.Lock(); db = previous; dbMutex.Unlock() }()
	if _, allowed := authorizeRawCredentials(nil, "test-device", "main", false); allowed {
		t.Fatal("main password bypassed removed membership")
	}
	if err := paneldb.SetUserProtocols(conn, "main-sub", []string{"wdtt"}); err != nil {
		t.Fatal(err)
	}
	incoming, _, err = loadDatabaseFromSQLite()
	if err != nil {
		t.Fatal(err)
	}
	if incoming.Passwords["main"].NativeDisabled {
		t.Fatal("restoring membership did not restore native access")
	}
}
