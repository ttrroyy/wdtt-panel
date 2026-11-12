// The original Soar SDK handles the wire protocol; its Dial hook identifies a panel user in Xray.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getlantern/soar"
	"golang.org/x/net/proxy"
)

type config struct {
	Zone       string   `json:"zone"`
	Listen     string   `json:"listen"`
	KeyFile    string   `json:"key_file"`
	SOCKS      string   `json:"socks"`
	User       string   `json:"user"`
	Password   string   `json:"password"`
	AllowPorts []string `json:"allow_ports"`
}

func run(c config) error {
	raw, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid Soar private seed")
	}
	dialer, err := proxy.SOCKS5("tcp", c.SOCKS, &proxy.Auth{User: c.User, Password: c.Password}, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return err
	}
	dial := dialer.(proxy.ContextDialer)
	pc, err := net.ListenPacket("udp", c.Listen)
	if err != nil {
		return err
	}
	defer pc.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return soar.Serve(ctx, pc, soar.ServerConfig{Zone: c.Zone, PrivateKey: ed25519.NewKeyFromSeed(seed), Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		allowed := false
		for _, p := range c.AllowPorts {
			if p == "any" || p == port {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("Soar destination port is not allowed")
		}
		return dial.DialContext(ctx, network, address)
	}})
}

func main() {
	file := flag.String("config", "", "private panel configuration file")
	flag.Parse()
	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		log.Fatal(err)
	}
	if err := run(c); err != nil {
		log.Fatal(err)
	}
}
