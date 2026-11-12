package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ildarmaga/wdtt/pkg/dnsrouter"
)

func main() {
	file := flag.String("config", "/etc/wdtt/dns-router.json", "authoritative zones and private tunnel servers")
	listen := flag.String("listen", ":53", "UDP and TCP listener")
	flag.Parse()
	var current atomic.Pointer[dnsrouter.Config]
	var last string
	load := func() error {
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		if string(data) == last {
			return nil
		}
		var cfg dnsrouter.Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		current.Store(&cfg)
		last = string(data)
		return nil
	}
	if err := load(); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var previous string
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := load(); err != nil {
					if err.Error() != previous {
						log.Printf("keeping previous DNS config: %v", err)
						previous = err.Error()
					}
				} else {
					previous = ""
				}
			}
		}
	}()
	if err := dnsrouter.Serve(ctx, *listen, current.Load); err != nil {
		log.Fatal(err)
	}
}
