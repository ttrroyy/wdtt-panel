package server

import (
	"fmt"
	"net"
	"testing"
)

func TestExpandedPoolPreservesLegacyAndAllocatesBeyond24(t *testing.T) {
	previous := db
	db = &Database{Devices: map[string]*ClientDevice{}}
	defer func() { db = previous }()
	if first := getNextIP(); first != "10.66.66.2" {
		t.Fatalf("first=%s", first)
	}
	seen := map[string]bool{}
	for i := 0; i < 600; i++ {
		address := getNextIP()
		ip := net.ParseIP(address).To4()
		if ip == nil || ip[0] != 10 || ip[1] != 66 || address == wgServerAddr || seen[address] {
			t.Fatalf("invalid allocation %q", address)
		}
		seen[address] = true
		db.Devices[fmt.Sprint(i)] = &ClientDevice{IP: address}
	}
	if !seen["10.66.0.1"] {
		t.Fatal("pool never expanded beyond the legacy /24")
	}
}

func TestTrafficClassIDsDoNotCollideAcross16(t *testing.T) {
	seen := map[int]string{}
	for third := 0; third < 256; third++ {
		for fourth := 1; fourth <= 254; fourth++ {
			address := fmt.Sprintf("10.66.%d.%d", third, fourth)
			if address == wgServerAddr {
				continue
			}
			id, err := ipClassID(address)
			if err != nil || id <= 1 || id >= 65535 {
				t.Fatalf("class(%s)=%d: %v", address, id, err)
			}
			if old, exists := seen[id]; exists {
				t.Fatalf("%s and %s collide", old, address)
			}
			seen[id] = address
		}
	}
}
