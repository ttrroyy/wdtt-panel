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
	Connections      []protocolSubscriptionConnection `json:"connections"`
	UpBytes          int64                            `json:"up_bytes"`
	DownBytes        int64                            `json:"down_bytes"`
	RemoteUpOffset   int64                            `json:"remote_up_offset"`
	RemoteDownOffset int64                            `json:"remote_down_offset"`
}

func loadProtocolSubscription(id string) (protocolSubscription, bool) {
	var all map[string]protocolSubscription
	data, err := os.ReadFile("/etc/wdtt/protocol-subscriptions.json")
	if err == nil {
		_ = json.Unmarshal(data, &all)
	}
	value, ok := all[id]
	var remoteUp, remoteDown int64
	var snapshots map[string]struct {
		Subscriptions map[string]protocolSubscription `json:"subscriptions"`
		NativeLinks   map[string]string               `json:"native_links"`
		Users         struct {
			Rows []struct {
				SubID string `json:"sub_id"`
				Up    int64  `json:"up_bytes"`
				Down  int64  `json:"down_bytes"`
			} `json:"rows"`
		} `json:"users"`
	}
	if data, err = os.ReadFile(fleetDirectory + "/snapshots.json"); err == nil && json.Unmarshal(data, &snapshots) == nil {
		state, _ := readFleet()
		names := map[string]string{}
		for _, n := range state.Nodes {
			names[n.ID] = n.Name
		}
		for nodeID, snapshot := range snapshots {
			name, exists := names[nodeID]
			if !exists {
				continue
			}
			bundle := snapshot.Subscriptions[id]
			remoteUp += bundle.UpBytes
			remoteDown += bundle.DownBytes
			for _, u := range snapshot.Users.Rows {
				if u.SubID == id {
					remoteUp += u.Up
					remoteDown += u.Down
				}
			}
			for _, connection := range bundle.Connections {
				connection.Protocol = nodeID + "--" + connection.Protocol
				if userHasProtocol(id, connection.Protocol) {
					connection.Title = name + " · " + connection.Title
					value.Connections = append(value.Connections, connection)
					ok = true
				}
			}
			if link := snapshot.NativeLinks[id]; link != "" && userHasProtocol(id, nodeID+"--wdtt") {
				value.Connections = append(value.Connections, protocolSubscriptionConnection{Protocol: nodeID + "--wdtt", Title: name + " · WDTT", Link: link})
				ok = true
			}
		}
	}
	if remoteUp > value.RemoteUpOffset {
		value.UpBytes += remoteUp - value.RemoteUpOffset
	}
	if remoteDown > value.RemoteDownOffset {
		value.DownBytes += remoteDown - value.RemoteDownOffset
	}
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
