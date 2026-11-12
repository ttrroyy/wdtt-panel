package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPIKeysScopeExpiryRevocationAndStorage(t *testing.T) {
	previous := apiKeysPath
	apiKeysPath = filepath.Join(t.TempDir(), "keys.json")
	defer func() { apiKeysPath = previous }()
	_, secret, err := newAPIKey("Read only", "read", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !validAPIKey(secret, "read") || validAPIKey(secret, "manage") || validAPIKey(secret, "node") {
		t.Fatal("key scope escaped")
	}
	b, err := os.ReadFile(apiKeysPath)
	if err != nil || strings.Contains(string(b), secret) {
		t.Fatal("plaintext key persisted")
	}
	keys, err := readAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	keys[0].Expires = time.Now().Unix() - 1
	if err = atomicFleetJSON(apiKeysPath, keys); err != nil {
		t.Fatal(err)
	}
	if validAPIKey(secret, "read") {
		t.Fatal("expired key accepted")
	}
	if err = atomicFleetJSON(apiKeysPath, []apiKeyEntry{}); err != nil {
		t.Fatal(err)
	}
	if validAPIKey(secret, "read") {
		t.Fatal("revoked key accepted")
	}
	if _, _, err = newAPIKey("Bad", "all", 0); err == nil {
		t.Fatal("unknown scope accepted")
	}
}
