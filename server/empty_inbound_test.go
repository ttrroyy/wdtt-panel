package server

import (
	"net"
	"testing"
)

func TestEmptyInboundCanWaitForUsers(t *testing.T) {
	keys := newWrapKeyStore()
	listener, err := listenWrapped(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if keys.Count() != 0 {
		t.Fatal("listener created an implicit access key")
	}
	if _, err := listenWrapped(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil); err == nil {
		t.Fatal("missing key store accepted")
	}
}
