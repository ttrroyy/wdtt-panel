package main

import (
	"fmt"
	"log"
	"os"

	"wdtt-panel"
	"wdtt-server"
)

func main() {
	noPanel := false
	panelOnly := false
	initPanel := false
	createKey := false
	filtered := make([]string, 0, len(os.Args))
	for _, arg := range os.Args {
		switch arg {
		case "-no-panel":
			noPanel = true
		case "-node-only":
			noPanel = true
		case "-panel-only":
			panelOnly = true
		case "-init-panel":
			initPanel = true
		case "-create-node-key":
			createKey = true
		case "-version", "--version":
			fmt.Println(panel.FormatPanelVersion())
			os.Exit(0)
		default:
			filtered = append(filtered, arg)
		}
	}
	os.Args = filtered

	if err := panel.BootstrapDB(); err != nil {
		log.Fatalf("[PANEL] bootstrap: %v", err)
	}
	if initPanel {
		if err := panel.ConfigureInstallation(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if createKey {
		if err := panel.CreateNodeAPIKey(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if !noPanel {
		panel.InitUnifiedLogSink()
		if panelOnly {
			if err := panel.Run(); err != nil {
				log.Fatal(err)
			}
			return
		}
		go func() {
			if err := panel.Run(); err != nil {
				log.Fatalf("[PANEL] %v", err)
			}
		}()
		log.Println("[PANEL] веб-панель запущена в том же процессе")
	}
	go func() {
		if err := panel.RunNodeAgent(); err != nil {
			log.Fatalf("[NODE] %v", err)
		}
	}()

	server.Run()
}
