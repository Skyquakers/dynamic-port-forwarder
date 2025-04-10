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

	// Create proxy
	p := proxy.NewProxy(cfg.NodeIPs, tlsConfig)

	// Start proxy servers for each port in the range
	for port := cfg.MinPort; port <= cfg.MaxPort; port++ {
		err := p.StartServer(port)
		if err != nil {
			log.Printf("Failed to start server on port %d: %v", port, err)
		}
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Block until signal is received
	sig := <-sigCh
	log.Printf("Received signal: %v, shutting down...", sig)

	// Create a context with a timeout for graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop all servers using the context
	p.StopAll(shutdownCtx)

	log.Println("Shutdown completed")
}
