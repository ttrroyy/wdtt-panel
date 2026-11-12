package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const protocolController = "/usr/local/lib/wdtt/protocols.py"
const protocolInboundsPath = "/etc/wdtt/protocol-inbounds.json"

func (a *App) handleProtocols(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Query().Get("all") == "1" {
		rows := []map[string]interface{}{}
		if installationRole() != "panel" {
			ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "python3", protocolController)
			cmd.Stdin = strings.NewReader(`{"op":"list"}`)
			out, err := cmd.Output()
			var response struct {
				Obj []map[string]interface{} `json:"obj"`
			}
			if err == nil && json.Unmarshal(out, &response) == nil {
				rows = response.Obj
			}
		}
		data, _ := os.ReadFile(fleetDirectory + "/inbounds.json")
		var entries map[string]map[string]interface{}
		_ = json.Unmarshal(data, &entries)
		for id, row := range entries {
			row["id"] = id
			rows = append(rows, row)
		}
		jsonOK(w, rows)
		return
	}
	req := map[string]interface{}{}
	if r.Method == http.MethodGet {
		req["op"] = "list"
		if r.URL.Query().Get("protocol") != "" {
			req["op"] = "users"
			req["protocol"] = r.URL.Query().Get("protocol")
		}
	} else if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Некорректный запрос", http.StatusBadRequest)
			return
		}
	} else {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	op, _ := req["op"].(string)
	switch op {
	case "list", "create", "delete", "enable", "disable", "update":
	default:
		jsonError(w, "Пользователи управляются через /panel/api/users", 400)
		return
	}
	if nodeID := r.URL.Query().Get("node_id"); nodeID != "" && nodeID != "local" {
		out, err := runFleet(r.Context(), map[string]interface{}{"op": "protocols", "node_id": nodeID, "request": req})
		if !json.Valid(out) {
			jsonError(w, "Нода недоступна", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(400)
		}
		_, _ = w.Write(out)
		return
	}
	if installationRole() == "panel" {
		if op == "list" {
			jsonOK(w, []interface{}{})
		} else {
			jsonError(w, "Сначала выберите ноду", 400)
		}
		return
	}
	if op == "create" {
		req["host"] = a.serverIP()
	}
	body, err := json.Marshal(req)
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", protocolController)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.Output()
	if !json.Valid(out) {
		jsonError(w, "Контроллер протоколов недоступен: проверьте установку и журнал wdtt-protocol-watch", 503)
		return
	}
	if err == nil {
		if req["protocol"] == "wdtt" && (op == "create" || op == "delete" || op == "enable" || op == "disable") {
			cfg, err := loadWdttInbound()
			if err != nil {
				jsonError(w, err.Error(), 500)
				return
			}
			cfg.Enable = op == "create" || op == "enable"
			if _, err := applyWdttInbound(cfg); err != nil {
				jsonError(w, err.Error(), 500)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	_, _ = w.Write(out)
}

func isProtocolInbound(tag string) bool { return strings.HasPrefix(tag, "vpn-") }

func protocolInbounds() []interface{} {
	data, err := os.ReadFile(protocolInboundsPath)
	if err != nil {
		return nil
	}
	var entries []interface{}
	if json.Unmarshal(data, &entries) != nil {
		return nil
	}
	return entries
}

func mergeProtocolInbounds(cfg map[string]interface{}) {
	generated := protocolInbounds()
	if generated == nil {
		return
	}
	current, _ := cfg["inbounds"].([]interface{})
	merged := make([]interface{}, 0, len(current)+len(generated))
	for _, entry := range current {
		item, _ := entry.(map[string]interface{})
		tag, _ := item["tag"].(string)
		if !isProtocolInbound(tag) {
			merged = append(merged, entry)
		}
	}
	cfg["inbounds"] = append(merged, generated...)
}

// Keep the user's table unchanged; expand protocol rules only in Xray's runtime copy.
func compileProtocolRouting(raw string) (string, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return "", err
	}
	entries, _ := cfg["inbounds"].([]interface{})
	children := map[string][]string{}
	if data, err := os.ReadFile("/etc/wdtt/protocols/user-route-aliases.json"); err == nil {
		if err := json.Unmarshal(data, &children); err != nil {
			return "", err
		}
	}
	var vpnTags []interface{}
	for _, entry := range entries {
		item, _ := entry.(map[string]interface{})
		tag, _ := item["tag"].(string)
		if isProtocolInbound(tag) {
			vpnTags = append(vpnTags, tag)
		}
		if pos := strings.Index(tag, "-user-"); isProtocolInbound(tag) && pos > 0 {
			children[tag[:pos]] = append(children[tag[:pos]], tag)
		}
	}
	routing, _ := cfg["routing"].(map[string]interface{})
	if routing == nil {
		routing = map[string]interface{}{}
		cfg["routing"] = routing
	}
	rules, _ := routing["rules"].([]interface{})
	for _, entry := range rules {
		rule, _ := entry.(map[string]interface{})
		tags, _ := rule["inboundTag"].([]interface{})
		expanded := append([]interface{}{}, tags...)
		for _, tag := range tags {
			name, _ := tag.(string)
			for _, child := range children[name] {
				expanded = append(expanded, child)
			}
		}
		if len(tags) > 0 {
			rule["inboundTag"] = expanded
		}
	}
	if len(vpnTags) > 0 {
		// Resolve SOCKS destinations before the private-address guard, including names resolving to localhost.
		routing["domainStrategy"] = "IPOnDemand"
		policy, _ := cfg["policy"].(map[string]interface{})
		if policy == nil {
			policy = map[string]interface{}{}
			cfg["policy"] = policy
		}
		system, _ := policy["system"].(map[string]interface{})
		if system == nil {
			system = map[string]interface{}{}
			policy["system"] = system
		}
		system["statsInboundUplink"], system["statsInboundDownlink"] = true, true
		// Transparent clients must not reach localhost control APIs through a freedom outbound.
		routing["rules"] = append([]interface{}{map[string]interface{}{
			"type": "field", "inboundTag": vpnTags, "outboundTag": "wdtt-local-block",
			"ip": []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10"},
		}}, rules...)
		outbounds, _ := cfg["outbounds"].([]interface{})
		clean := make([]interface{}, 0, len(outbounds)+1)
		for _, entry := range outbounds {
			item, _ := entry.(map[string]interface{})
			if item["tag"] != "wdtt-local-block" {
				clean = append(clean, entry)
			}
		}
		cfg["outbounds"] = append(clean, map[string]interface{}{"tag": "wdtt-local-block", "protocol": "blackhole", "settings": map[string]interface{}{}})
	}
	result, err := json.MarshalIndent(cfg, "", "  ")
	return string(result), err
}

type protocolRouteOption struct {
	Tag   string `json:"tag"`
	Label string `json:"label"`
}

func protocolRouteOptions() []protocolRouteOption {
	options := []protocolRouteOption{}
	data, err := os.ReadFile("/etc/wdtt/protocols/route-options.json")
	if err == nil {
		_ = json.Unmarshal(data, &options)
	}
	seen := map[string]bool{}
	for _, v := range options {
		seen[v.Tag] = true
	}
	if panelDB != nil {
		rows, err := panelDB.Query("SELECT sub_id,comment FROM wdtt_users WHERE sub_id<>''")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, label string
				if rows.Scan(&id, &label) == nil {
					tag := "vpn-user-" + id
					if !seen[tag] {
						options = append(options, protocolRouteOption{Tag: tag, Label: label})
						seen[tag] = true
					}
				}
			}
		}
	}
	if data, err = os.ReadFile(fleetDirectory + "/inbounds.json"); err == nil {
		var entries map[string]struct {
			NodeID  string `json:"node_id"`
			LocalID string `json:"local_id"`
			Name    string `json:"name"`
			Present bool   `json:"present"`
		}
		if json.Unmarshal(data, &entries) == nil {
			for _, v := range entries {
				if v.Present {
					tag := "vpn-node-" + v.NodeID + "--" + v.LocalID
					if !seen[tag] {
						options = append(options, protocolRouteOption{Tag: tag, Label: v.Name})
						seen[tag] = true
					}
				}
			}
		}
	}
	return options
}

func (a *App) handleProtocolRouteOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", 405)
		return
	}
	jsonOK(w, protocolRouteOptions())
}

var protocolRuntimeSignature string
var protocolXrayMu sync.Mutex

func syncProtocolXray() error {
	protocolXrayMu.Lock()
	defer protocolXrayMu.Unlock()
	generated := protocolInbounds()
	if generated == nil {
		return nil
	}
	raw, err := loadXrayConfigRaw()
	if err != nil {
		return err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return err
	}
	var old []interface{}
	entries, _ := cfg["inbounds"].([]interface{})
	for _, entry := range entries {
		item, _ := entry.(map[string]interface{})
		tag, _ := item["tag"].(string)
		if isProtocolInbound(tag) {
			old = append(old, entry)
		}
	}
	oldJSON, _ := json.Marshal(old)
	newJSON, _ := json.Marshal(generated)
	signature := string(newJSON)
	if bytes.Equal(oldJSON, newJSON) && signature == protocolRuntimeSignature {
		return nil
	}
	mergeProtocolInbounds(cfg)
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := writeXrayConfig(string(data)); err != nil {
		return fmt.Errorf("protocol xray: %w", err)
	}
	if err := serviceRestart(xrayServiceUnit); err != nil {
		return err
	}
	protocolRuntimeSignature = signature
	return nil
}

func resetProtocolUserTraffic(subID string) error {
	if _, err := os.Stat(protocolController); os.IsNotExist(err) {
		return nil
	}
	body, err := json.Marshal(map[string]string{"op": "reset-user-traffic", "sub_id": subID})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", protocolController)
	cmd.Stdin = bytes.NewReader(body)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("не удалось сбросить трафик протоколов: %w", err)
	}
	var response struct {
		Success bool   `json:"success"`
		Message string `json:"msg"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return err
	}
	if !response.Success {
		return fmt.Errorf("%s", response.Message)
	}
	return nil
}
