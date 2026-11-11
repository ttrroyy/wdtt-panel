package server

import (
	"crypto/sha256"
	"fmt"
)

func protocolUserIPs() map[string][]string {
	result := map[string][]string{}
	add := func(password, ip string) {
		if password == "" || ip == "" {
			return
		}
		id := fmt.Sprintf("%x", sha256.Sum256([]byte("wdtt\x00"+password)))[:20]
		for _, existing := range result[id] {
			if existing == ip {
				return
			}
		}
		result[id] = append(result[id], ip)
	}
	dbMutex.Lock()
	if db != nil {
		for deviceID, dev := range db.Devices {
			add(passwordForDeviceLocked(deviceID), dev.IP)
		}
	}
	dbMutex.Unlock()
	rawSessionsByIP.Range(func(_, value any) bool {
		group, ok := value.(*rawSessionGroup)
		if !ok {
			return true
		}
		group.mu.Lock()
		for _, session := range group.sessions {
			add(session.password, group.ip)
		}
		group.mu.Unlock()
		return true
	})
	return result
}
