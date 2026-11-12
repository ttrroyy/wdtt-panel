package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var apiKeysPath = "/etc/wdtt/api-keys.json"
var apiKeysMu sync.Mutex

type apiKeyEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	Hash    string `json:"hash,omitempty"`
	Created int64  `json:"created_at"`
	Expires int64  `json:"expires_at"`
}

func readAPIKeys() ([]apiKeyEntry, error) {
	keys := []apiKeyEntry{}
	b, err := os.ReadFile(apiKeysPath)
	if os.IsNotExist(err) {
		return keys, nil
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &keys)
	return keys, err
}
func newAPIKey(name, scope string, expires int64) (apiKeyEntry, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || (scope != "read" && scope != "manage" && scope != "node") || expires < 0 || (expires > 0 && expires <= time.Now().Unix()) {
		return apiKeyEntry{}, "", fmt.Errorf("Укажите имя, права и будущий срок действия ключа")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return apiKeyEntry{}, "", err
	}
	token := "wdtt_api_" + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	id, err := fleetID("k-")
	if err != nil {
		return apiKeyEntry{}, "", err
	}
	entry := apiKeyEntry{ID: id, Name: name, Scope: scope, Hash: hex.EncodeToString(sum[:]), Created: time.Now().Unix(), Expires: expires}
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	keys, err := readAPIKeys()
	if err != nil {
		return entry, "", err
	}
	keys = append(keys, entry)
	if err = atomicFleetJSON(apiKeysPath, keys); err != nil {
		return entry, "", err
	}
	entry.Hash = ""
	return entry, token, nil
}
func validAPIKey(token, scope string) bool {
	if !strings.HasPrefix(token, "wdtt_api_") || len(token) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	keys, err := readAPIKeys()
	if err != nil {
		return false
	}
	for _, key := range keys {
		if subtle.ConstantTimeCompare([]byte(digest), []byte(key.Hash)) == 1 && (key.Expires == 0 || key.Expires > time.Now().Unix()) && (key.Scope == scope || (scope == "read" && key.Scope == "manage")) {
			return true
		}
	}
	return false
}
func requestAPIKey(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
func (a *App) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	// Keys cannot mint or revoke other keys; only a logged-in panel session can.
	if a.parseSession(r) == nil {
		jsonError(w, "Требуется вход в панель", 401)
		return
	}
	if r.Method == http.MethodGet {
		apiKeysMu.Lock()
		keys, err := readAPIKeys()
		apiKeysMu.Unlock()
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		for i := range keys {
			keys[i].Hash = ""
		}
		jsonOK(w, keys)
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var req struct {
		Op      string `json:"op"`
		ID      string `json:"id"`
		Name    string `json:"name"`
		Scope   string `json:"scope"`
		Expires int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Некорректный запрос", 400)
		return
	}
	if req.Op == "create" {
		entry, secret, err := newAPIKey(req.Name, req.Scope, req.Expires)
		if err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		jsonOK(w, map[string]interface{}{"key": entry, "secret": secret})
		return
	}
	if req.Op != "delete" {
		jsonError(w, "Неизвестная операция", 400)
		return
	}
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()
	keys, err := readAPIKeys()
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	for i, k := range keys {
		if k.ID == req.ID {
			keys = append(keys[:i], keys[i+1:]...)
			if err := atomicFleetJSON(apiKeysPath, keys); err != nil {
				jsonError(w, err.Error(), 500)
				return
			}
			jsonOK(w, nil)
			return
		}
	}
	jsonError(w, "Ключ не найден", 404)
}

func CreateNodeAPIKey() error {
	entry, secret, err := newAPIKey("Node pairing", "node", 0)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"id": entry.ID, "key": secret})
}
