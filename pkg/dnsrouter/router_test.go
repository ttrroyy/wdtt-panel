package dnsrouter

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, domain string, kind dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(domain)
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAuthorityAndNoRecursion(t *testing.T) {
	c := Config{Zones: []Zone{{Domain: "t.example.org", NS: "ns.example.org"}}, Routes: []Route{{Domain: "u1.dnstt.t.example.org", Target: "127.0.0.1:5300"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		kind    dnsmessage.Type
		code    dnsmessage.RCode
		answers int
	}{
		{"t.example.org.", dnsmessage.TypeNS, dnsmessage.RCodeSuccess, 1},
		{"t.example.org.", dnsmessage.TypeSOA, dnsmessage.RCodeSuccess, 1},
		{"dnstt.t.example.org.", dnsmessage.TypeNS, dnsmessage.RCodeSuccess, 0},
		{"absent.t.example.org.", dnsmessage.TypeTXT, dnsmessage.RCodeNameError, 0},
		{"google.com.", dnsmessage.TypeA, dnsmessage.RCodeRefused, 0},
		{"nott.example.org.", dnsmessage.TypeA, dnsmessage.RCodeRefused, 0},
	} {
		var response dnsmessage.Message
		if err := response.Unpack(c.Exchange(context.Background(), query(t, tc.name, tc.kind))); err != nil {
			t.Fatal(err)
		}
		if response.ID != 42 || response.RecursionAvailable || response.RCode != tc.code || len(response.Answers) != tc.answers {
			t.Fatalf("%s: %+v", tc.name, response)
		}
		if tc.code == dnsmessage.RCodeSuccess && !response.Authoritative {
			t.Fatal("not authoritative")
		}
	}
	for _, invalid := range [][]byte{nil, {1, 2, 3}, make([]byte, 12)} {
		_ = c.Exchange(context.Background(), invalid)
	}
	c.Routes[0].Target = "8.8.8.8:53"
	if c.Validate() == nil {
		t.Fatal("accepted public recursive upstream")
	}
	c.Routes[0] = Route{Domain: "elsewhere.example.org", Target: "127.0.0.1:53"}
	if c.Validate() == nil {
		t.Fatal("accepted undelegated route")
	}
}

func TestLongestSuffixForwardingPreservesWire(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	wire := query(t, "data.user.t.example.org.", dnsmessage.TypeTXT)
	expected := append([]byte(nil), wire...)
	expected[2] |= 0x80
	done := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(time.Second * 3))
		buffer := make([]byte, 4096)
		n, peer, err := server.ReadFrom(buffer)
		if err == nil && !bytes.Equal(buffer[:n], wire) {
			t.Error("modified tunnel query")
		}
		if err == nil {
			_, err = server.WriteTo(expected, peer)
		}
		done <- err
	}()
	c := Config{Zones: []Zone{{"t.example.org", "ns.example.org"}}, Routes: []Route{{"t.example.org", "127.0.0.1:1"}, {"user.t.example.org", server.LocalAddr().String()}}}
	if response := c.Exchange(context.Background(), wire); !bytes.Equal(response, expected) {
		t.Fatalf("modified tunnel reply: %x", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
