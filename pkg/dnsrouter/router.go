// Package dnsrouter shares an authoritative DNS listener between unmodified tunnel servers.
package dnsrouter

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Zone struct {
	Domain string `json:"domain"`
	NS     string `json:"ns"`
}

type Route struct {
	Domain string `json:"domain"`
	Target string `json:"target"`
}

type Config struct {
	Zones  []Zone  `json:"zones"`
	Routes []Route `json:"routes"`
}

func canonical(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) + "." }

func within(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func (c *Config) Validate() error {
	seen := map[string]bool{}
	validName := func(value string) bool {
		if len(value) > 253 || !strings.Contains(value, ".") {
			return false
		}
		for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return false
				}
			}
		}
		return true
	}
	for _, z := range c.Zones {
		if len(z.Domain) > 220 || !validName(z.Domain) || !validName(z.NS) || seen[canonical(z.Domain)] {
			return fmt.Errorf("invalid or duplicate DNS zone: %q", z.Domain)
		}
		seen[canonical(z.Domain)] = true
	}
	seen = map[string]bool{}
	for _, r := range c.Routes {
		if !validName(r.Domain) || seen[canonical(r.Domain)] {
			return fmt.Errorf("invalid or duplicate DNS route: %q", r.Domain)
		}
		seen[canonical(r.Domain)] = true
		found := false
		for _, z := range c.Zones {
			if within(canonical(r.Domain), canonical(z.Domain)) {
				found = true
			}
		}
		host, _, err := net.SplitHostPort(r.Target)
		ip := net.ParseIP(host)
		if !found || err != nil || ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
			return fmt.Errorf("DNS route must target an internal address in a configured zone: %q", r.Domain)
		}
		if _, err := net.ResolveUDPAddr("udp", r.Target); err != nil {
			return err
		}
	}
	return nil
}

func failure(wire []byte, code dnsmessage.RCode) []byte {
	if len(wire) < 12 {
		return nil
	}
	response := make([]byte, 12)
	copy(response, wire[:2])
	response[2] = 0x80 | wire[2]&1
	response[3] = byte(code)
	return response
}

// Exchange never recurses: only configured tunnel zones can reach private servers.
func (c *Config) Exchange(ctx context.Context, wire []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return failure(wire, dnsmessage.RCodeFormatError)
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone || h.OpCode != 0 || q.Class != dnsmessage.ClassINET {
		return failure(wire, dnsmessage.RCodeFormatError)
	}
	name := canonical(q.Name.String())
	var zone *Zone
	for i := range c.Zones {
		if within(name, canonical(c.Zones[i].Domain)) && (zone == nil || len(c.Zones[i].Domain) > len(zone.Domain)) {
			zone = &c.Zones[i]
		}
	}
	if zone == nil {
		return failure(wire, dnsmessage.RCodeRefused)
	}
	var route *Route
	for i := range c.Routes {
		if within(name, canonical(c.Routes[i].Domain)) && (route == nil || len(c.Routes[i].Domain) > len(route.Domain)) {
			route = &c.Routes[i]
		}
	}
	if route != nil && name != canonical(zone.Domain) {
		upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", route.Target)
		if err != nil {
			return failure(wire, dnsmessage.RCodeServerFailure)
		}
		defer upstream.Close()
		_ = upstream.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err = upstream.Write(wire); err != nil {
			return failure(wire, dnsmessage.RCodeServerFailure)
		}
		response := make([]byte, 65535)
		n, err := upstream.Read(response)
		if err != nil || n < 12 || binary.BigEndian.Uint16(response) != h.ID || response[2]&0x80 == 0 {
			return failure(wire, dnsmessage.RCodeServerFailure)
		}
		return response[:n]
	}
	// Empty non-terminals exist so QNAME-minimising recursive resolvers keep descending.
	exists := name == canonical(zone.Domain)
	for _, r := range c.Routes {
		if within(canonical(r.Domain), name) {
			exists = true
		}
	}
	code := dnsmessage.RCodeSuccess
	if !exists {
		code = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RCode: code})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(q)
	zname, _ := dnsmessage.NewName(canonical(zone.Domain))
	ns, _ := dnsmessage.NewName(canonical(zone.NS))
	hostmaster, _ := dnsmessage.NewName("hostmaster." + canonical(zone.Domain))
	soa := dnsmessage.SOAResource{NS: ns, MBox: hostmaster, Serial: 1, Refresh: 300, Retry: 60, Expire: 86400, MinTTL: 30}
	soaHead := dnsmessage.ResourceHeader{Name: zname, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 30}
	_ = b.StartAnswers()
	answered := false
	if name == canonical(zone.Domain) && (q.Type == dnsmessage.TypeNS || q.Type == dnsmessage.TypeALL) {
		_ = b.NSResource(dnsmessage.ResourceHeader{Name: zname, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.NSResource{NS: ns})
		answered = true
	}
	if name == canonical(zone.Domain) && (q.Type == dnsmessage.TypeSOA || q.Type == dnsmessage.TypeALL) {
		_ = b.SOAResource(soaHead, soa)
		answered = true
	}
	_ = b.StartAuthorities()
	if !answered {
		_ = b.SOAResource(soaHead, soa)
	}
	response, err := b.Finish()
	if err != nil {
		return failure(wire, dnsmessage.RCodeServerFailure)
	}
	return response
}

// Serve binds UDP and TCP before serving either, and bounds concurrent work.
func Serve(ctx context.Context, address string, config func() *Config) error {
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer tcp.Close()
	go func() { <-ctx.Done(); _ = udp.Close(); _ = tcp.Close() }()
	work := make(chan struct{}, 1024)
	connections := make(chan struct{}, 128)
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			select {
			case connections <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			go func() {
				defer func() { _ = conn.Close(); <-connections }()
				for {
					_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
					var size [2]byte
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						return
					}
					wire := make([]byte, binary.BigEndian.Uint16(size[:]))
					if len(wire) < 12 {
						return
					}
					if _, err := io.ReadFull(conn, wire); err != nil {
						return
					}
					select {
					case work <- struct{}{}:
					case <-ctx.Done():
						return
					}
					response := config().Exchange(ctx, wire)
					<-work
					if len(response) == 0 {
						return
					}
					binary.BigEndian.PutUint16(size[:], uint16(len(response)))
					if _, err := io.Copy(conn, strings.NewReader(string(append(size[:], response...)))); err != nil {
						return
					}
				}
			}()
		}
	}()
	for {
		wire := make([]byte, 65535)
		n, peer, err := udp.ReadFrom(wire)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case work <- struct{}{}:
		default:
			continue
		}
		go func(wire []byte, peer net.Addr) {
			defer func() { <-work }()
			if response := config().Exchange(ctx, wire); len(response) != 0 {
				_, _ = udp.WriteTo(response, peer)
			}
		}(wire[:n], peer)
	}
}
