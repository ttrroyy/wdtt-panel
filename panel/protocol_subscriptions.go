package panel

import (
	"encoding/json"
	"github.com/ildarmaga/wdtt/pkg/paneldb"
	"os"
)

type protocolSubscriptionConnection struct {
	Protocol string `json:"protocol"`
	Title    string `json:"title"`
	Link     string `json:"link"`
	WGConfig string `json:"wg_config"`
}

type protocolSubscription struct {
	Connections []protocolSubscriptionConnection `json:"connections"`
	UpBytes     int64                            `json:"up_bytes"`
	DownBytes   int64                            `json:"down_bytes"`
}

func loadProtocolSubscription(id string) (protocolSubscription, bool) {
	var all map[string]protocolSubscription
	data, err := os.ReadFile("/etc/wdtt/protocol-subscriptions.json")
	if err != nil || json.Unmarshal(data, &all) != nil {
		return protocolSubscription{}, false
	}
	value, ok := all[id]
	return value, ok
}

func userHasProtocol(id, protocol string) bool {
	protocols, err := paneldb.UserProtocols(panelDB, id)
	if err != nil {
		return false
	}
	for _, name := range protocols {
		if name == protocol {
			return true
		}
	}
	return false
}
