package panel

import (
	"encoding/json"
	"testing"
)

func TestProtocolRuleIncludesUserFallbackWithoutChangingTheTable(t *testing.T) {
	isolateFleetPlan(t)
	raw := `{"inbounds":[{"tag":"vpn-qwdtt"},{"tag":"vpn-qwdtt-user-abc"},{"tag":"vpn-wdtt-user-def"}],"routing":{"rules":[{"inboundTag":["vpn-qwdtt-user-abc"],"domain":["example.com"],"outboundTag":"blocked"},{"inboundTag":["vpn-qwdtt"],"outboundTag":"proxy"}]}}`
	compiled, err := compileProtocolRouting(raw)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Routing struct {
			Rules []struct {
				InboundTag []string `json:"inboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(compiled), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routing.Rules[1].InboundTag) != 1 {
		t.Fatal("user rule changed")
	}
	tags := cfg.Routing.Rules[2].InboundTag
	if len(tags) != 2 || tags[1] != "vpn-qwdtt-user-abc" {
		t.Fatalf("protocol fallback=%v", tags)
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routing.Rules[1].InboundTag) != 1 {
		t.Fatal("original routing table mutated")
	}
}

func TestSOCKSRoutingGuardsResolvedPrivateNamesAndKeepsQuotaCounters(t *testing.T) {
	isolateFleetPlan(t)
	compiled, err := compileProtocolRouting(`{"inbounds":[{"tag":"vpn-edge-dnstt-test-user-abc","protocol":"socks"}],"routing":{"domainStrategy":"AsIs","rules":[]},"policy":{"system":{"statsInboundUplink":false}}}`)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(compiled), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["routing"].(map[string]interface{})["domainStrategy"] != "IPOnDemand" {
		t.Fatal("SOCKS private destinations must be resolved before routing")
	}
	system := cfg["policy"].(map[string]interface{})["system"].(map[string]interface{})
	if system["statsInboundUplink"] != true || system["statsInboundDownlink"] != true {
		t.Fatal("quota counters must stay enabled")
	}
}

func isolateFleetPlan(t *testing.T) {
	t.Helper()
	previous := fleetDirectory
	fleetDirectory = t.TempDir()
	t.Cleanup(func() { fleetDirectory = previous })
}
