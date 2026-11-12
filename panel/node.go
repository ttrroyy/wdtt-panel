package panel

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunNodeAgent exposes no pages, login or public listener. SSH carries its RPC.
func RunNodeAgent() error {
	cfg, err := loadPanelConfig()
	if err != nil {
		return err
	}
	tokenBytes, err := os.ReadFile("/etc/wdtt/node-token")
	if os.IsNotExist(err) {
		token, genErr := fleetKey()
		if genErr != nil {
			return genErr
		}
		tokenBytes = []byte(token)
		err = os.WriteFile("/etc/wdtt/node-token", tokenBytes, 0600)
	}
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(tokenBytes))
	address := "127.0.0.1:0"
	if b, e := os.ReadFile("/etc/wdtt/node-agent.json"); e == nil {
		var saved map[string]string
		if json.Unmarshal(b, &saved) == nil && strings.HasPrefix(saved["address"], "127.0.0.1:") {
			address = saved["address"]
		}
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	if err = atomicFleetJSON("/etc/wdtt/node-agent.json", map[string]string{"address": listener.Addr().String()}); err != nil {
		listener.Close()
		return err
	}
	app := &App{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, "method not allowed", 405)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil || !json.Valid(data) {
			jsonError(w, "Некорректный запрос", 400)
			return
		}
		cmd := exec.CommandContext(r.Context(), "python3", "/usr/local/lib/wdtt/fleet.py", "rpc")
		cmd.Stdin = bytes.NewReader(data)
		out, err := cmd.Output()
		if !json.Valid(out) {
			jsonError(w, "Ошибка агента ноды", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(400)
		}
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/inbound", app.handleInboundGet)
	mux.HandleFunc("/inbound-save", app.handleInboundSave)
	mux.HandleFunc("/links", func(w http.ResponseWriter, r *http.Request) {
		db, err := loadPasswords()
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		inbound, err := loadWdttInbound()
		if err != nil {
			jsonError(w, err.Error(), 500)
			return
		}
		links := map[string]string{}
		for password, entry := range db.Passwords {
			if entry != nil && userHasProtocol(entry.SubID, "wdtt") {
				links[entry.SubID] = buildWdttLink(app.resolveLinkHost(inbound), password, cfg.SubTitle, entry.VkHash, entry, inbound, "")
			}
		}
		jsonOK(w, links)
	})
	mux.HandleFunc("/routing", app.handleNodeRouting)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 && !validAPIKey(requestAPIKey(r), "node") {
			http.Error(w, "unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if r.URL.Path == "/inbound" {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Method = http.MethodGet
		}
		mux.ServeHTTP(w, r)
	})
	ensureWdttXrayDirs()
	patchWdttXrayService()
	if err := patchXrayStatsAPIOnDisk(); err != nil {
		log.Printf("node stats API: %v", err)
	}
	if installationRole() == "node" {
		go func() {
			for {
				if err := syncProtocolXray(); err != nil {
					log.Printf("node routing: %v", err)
				}
				time.Sleep(3 * time.Second)
			}
		}()
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return server.Serve(listener)
}
