package panel

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrontendTLS(t *testing.T) {
	previous := wdttConfigDir
	wdttConfigDir = t.TempDir()
	t.Cleanup(func() { wdttConfigDir = previous })
	for _, mode := range []string{"nginx", "caddy", "local", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(wdttConfigDir, "frontend.json"), []byte(`{"mode":"`+mode+`","domain":"panel.example"}`), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &PanelConfig{WebCertFile: "cert.pem", WebKeyFile: "key.pem", SubCertFile: "cert.pem", SubKeyFile: "key.pem"}
			proxy := mode == "nginx" || mode == "caddy"
			normalizePanelConfig(cfg)
			state := panelCertPanelMap(cfg)
			if state["proxyTLS"] != proxy || state["tlsActive"] != proxy {
				t.Fatalf("unexpected TLS status: %v", state)
			}
			if proxy {
				if cfg.WebCertFile != "" || cfg.WebKeyFile != "" || cfg.SubCertFile != "" || cfg.SubKeyFile != "" || state["webDomain"] != "panel.example" {
					t.Fatalf("proxy must keep its upstream HTTP: %#v", cfg)
				}
				if err := applyPanelCert(cfg, "cert.pem", "key.pem", false); err == nil {
					t.Fatal("direct TLS must not replace the proxy's HTTP upstream")
				}
				request := httptest.NewRequest("POST", "/", strings.NewReader(`{"webPort":8000,"webCertFile":"cert.pem","webKeyFile":"key.pem"}`))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				(&App{cfg: cfg}).handleSettingUpdate(response, request)
				if response.Code != 400 || cfg.Port == 8000 || cfg.WebCertFile != "" {
					t.Fatal("settings must reject backend TLS before mutating the running configuration")
				}
			} else if cfg.WebCertFile != "cert.pem" || cfg.SubCertFile != "cert.pem" {
				t.Fatal("standalone TLS configuration changed")
			}
		})
	}
	for _, data := range []string{`{`, `{"mode":"nginx"}`} {
		if err := os.WriteFile(filepath.Join(wdttConfigDir, "frontend.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if proxy, _ := panelProxyTLS(); proxy != "" {
			t.Fatal("invalid frontend metadata must not enable proxy TLS")
		}
	}
}
