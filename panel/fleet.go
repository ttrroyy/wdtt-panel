package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var fleetDirectory = "/etc/wdtt/fleet"

type fleetNode struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	SSHPort     int    `json:"ssh_port"`
	MachineID   string `json:"machine_id"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}
type fleetState struct {
	Nodes []fleetNode `json:"nodes"`
}

func installationRole() string {
	data, _ := os.ReadFile("/etc/wdtt/role")
	return strings.TrimSpace(string(data))
}
func fleetKey() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.StdEncoding.EncodeToString(b), err
}
func fleetID(prefix string) (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	return prefix + hex.EncodeToString(b), err
}
func readFleet() (fleetState, error) {
	s := fleetState{Nodes: []fleetNode{}}
	b, err := os.ReadFile(fleetDirectory + "/state.json")
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}
func atomicFleetJSON(path string, value interface{}) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".private-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func runFleet(ctx context.Context, payload interface{}) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "/usr/local/lib/wdtt/fleet.py")
	cmd.Stdin = bytes.NewReader(b)
	output, err := cmd.Output()
	if !json.Valid(output) {
		return nil, fmt.Errorf("Контроллер нод недоступен")
	}
	return output, err
}
func (a *App) handleNodes(w http.ResponseWriter, r *http.Request) {
	request := map[string]interface{}{"op": "list"}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			jsonError(w, "Некорректный запрос", 400)
			return
		}
		if op, _ := request["op"].(string); op != "add" && op != "delete" {
			jsonError(w, "Неизвестная операция", 400)
			return
		}
	} else if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", 405)
		return
	}
	out, err := runFleet(r.Context(), request)
	if !json.Valid(out) {
		jsonError(w, "Контроллер нод недоступен", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(400)
	}
	_, _ = w.Write(out)
}
func proxyNodeInbound(w http.ResponseWriter, r *http.Request, op string) bool {
	id := r.URL.Query().Get("node_id")
	if id == "" || id == "local" {
		return false
	}
	payload := map[string]interface{}{}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			jsonError(w, "Некорректный запрос", 400)
			return true
		}
	}
	out, err := runFleet(r.Context(), map[string]interface{}{"op": op, "node_id": id, "request": payload})
	if !json.Valid(out) {
		jsonError(w, "Нода недоступна", 503)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(400)
	}
	_, _ = w.Write(out)
	return true
}
