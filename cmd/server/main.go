package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/skyquakers/dynamic-port-forwarder/internal/cert"
	"github.com/skyquakers/dynamic-port-forwarder/internal/config"
	"github.com/skyquakers/dynamic-port-forwarder/internal/proxy"
)

// Variables that can be mocked for testing
var (
	osExit = os.Exit
)

func main() {
	runServer()
}

// runServer contains the main logic of the application
func runServer() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Printf("Failed to load configuration: %v", err)
		osExit(1)
		return
	}

	// Load certificates
	certManager := cert.NewManager(cfg.CertFile, cfg.KeyFile)
	tlsConfig, err := certManager.GetTLSConfig()
	if err != nil {
		log.Printf("Failed to load TLS configuration: %v", err)
		osExit(1)
		return
	}

	// Start hot-reload loop for certificates.
	// This swaps the cert used for NEW TLS handshakes without restarting listeners.
	// Existing connections keep using the cert they negotiated with.
	reloadCtx, reloadCancel := context.WithCancel(context.Background())
	certManager.StartAutoReload(reloadCtx, 30*time.Second, func(reloaded bool, err error) {
		if err != nil {
			log.Printf("TLS certificate reload failed (keeping previous): %v", err)
			return
		}
		if reloaded {
			log.Printf("TLS certificate reloaded")
		}
	})

	// Create proxy
	p := proxy.NewProxy(cfg.NodeIPs, tlsConfig)

	// Start proxy servers for each port in the range
	for port := cfg.MinPort; port <= cfg.MaxPort; port++ {
		err := p.StartServer(port)
		if err != nil {
			log.Printf("Failed to start server on port %d: %v", port, err)
		}
	}

	// Wait for signals (SIGHUP triggers immediate cert reload; SIGINT/SIGTERM exit)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			if err := certManager.LoadAndStore(); err != nil {
				log.Printf("TLS certificate reload (SIGHUP) failed (keeping previous): %v", err)
			} else {
				log.Printf("TLS certificate reloaded (SIGHUP)")
			}
			continue
		}
		log.Printf("Received signal: %v, shutting down...", sig)
		break
	}

	// Create a context with a timeout for graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop the hot-reload loop.
	reloadCancel()

	// Stop all servers using the context
	p.StopAll(shutdownCtx)

	log.Println("Shutdown completed")
}
