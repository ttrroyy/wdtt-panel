package panel

import (
	"encoding/json"
	"net/http"
)

func (a *App) handleNodeRouting(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var update map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		jsonError(w, "Некорректная маршрутизация", 400)
		return
	}
	protocolXrayMu.Lock()
	defer protocolXrayMu.Unlock()
	old, err := loadXrayConfigRaw()
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	var cfg map[string]interface{}
	if err = json.Unmarshal([]byte(old), &cfg); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	for _, key := range []string{"outbounds", "routing", "dns", "policy"} {
		if value, exists := update[key]; exists {
			cfg[key] = value
		}
	}
	ensureXrayStatsAPI(cfg)
	encoded, err := json.Marshal(cfg)
	if err == nil {
		err = writeXrayConfig(string(encoded))
	}
	if err == nil {
		err = serviceRestart(xrayServiceUnit)
	}
	if err != nil {
		_ = writeXrayConfig(old)
		_ = serviceRestart(xrayServiceUnit)
		jsonError(w, err.Error(), 400)
		return
	}
	jsonOK(w, map[string]bool{"applied": true})
}
