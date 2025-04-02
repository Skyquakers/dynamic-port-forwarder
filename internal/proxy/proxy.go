package proxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// Proxy handles the SSL termination and forwarding
type Proxy struct {
	nodeIPs       []string
	tlsConfig     *tls.Config
	servers       map[int]*http.Server
	serversLock   sync.Mutex
	activeServers sync.WaitGroup
}

// NewProxy creates a new proxy instance
func NewProxy(nodeIPs []string, tlsConfig *tls.Config) *Proxy {
	return &Proxy{
		nodeIPs:   nodeIPs,
		tlsConfig: tlsConfig,
		servers:   make(map[int]*http.Server),
	}
}

// StartServer starts an HTTPS server on the given port
func (p *Proxy) StartServer(port int) error {
	p.serversLock.Lock()
	defer p.serversLock.Unlock()

	// Check if server already exists for this port
	if _, exists := p.servers[port]; exists {
		return fmt.Errorf("server already running on port %d", port)
	}

	// Create a new server
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	// Create a clone of the TLS config for each server to avoid race conditions
	serverTLSConfig := p.tlsConfig.Clone()

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		Handler:   mux,
		TLSConfig: serverTLSConfig,
	}

	p.servers[port] = server
	p.activeServers.Add(1)

	// Start the server in a goroutine
	go func() {
		defer p.activeServers.Done()
		log.Printf("Starting server on port %d", port)

		err := server.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			log.Printf("Server on port %d failed: %v", port, err)
		}

		log.Printf("Server on port %d stopped", port)
		p.serversLock.Lock()
		delete(p.servers, port)
		p.serversLock.Unlock()
	}()

	return nil
}

// StopServer stops the server running on the given port
func (p *Proxy) StopServer(port int) error {
	p.serversLock.Lock()
	server, exists := p.servers[port]
	p.serversLock.Unlock()

	if !exists {
		return fmt.Errorf("no server running on port %d", port)
	}

	err := server.Close()
	if err != nil {
		return fmt.Errorf("failed to stop server on port %d: %v", port, err)
	}

	return nil
}

// StopAll stops all running servers
func (p *Proxy) StopAll() {
	p.serversLock.Lock()
	for port, server := range p.servers {
		log.Printf("Stopping server on port %d", port)
		server.Close()
	}
	p.serversLock.Unlock()

	// Wait for all servers to stop
	p.activeServers.Wait()
}

// getNodeIP returns a node IP for load balancing (simple round-robin)
func (p *Proxy) getNodeIP() string {
	// Basic load balancing just returns the first node for simplicity
	// In a real-world scenario, you'd want a more sophisticated approach
	if len(p.nodeIPs) == 0 {
		return "127.0.0.1"
	}
	return p.nodeIPs[0]
}

// handleRequest handles incoming HTTP/WebSocket requests
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Get host and port from request
	_, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		// If no port in host (rare case), use default port based on scheme
		if r.TLS != nil {
			port = "443"
		} else {
			port = "80"
		}
	}

	nodeIP := p.getNodeIP()
	targetURL := ""

	// Check if it's a WebSocket request
	if isWebSocketRequest(r) {
		// Handle WebSocket
		targetURL = fmt.Sprintf("ws://%s:%s%s", nodeIP, port, r.URL.Path)
		p.handleWebSocketRequest(w, r, targetURL)
		return
	}

	// Regular HTTP request
	targetURL = fmt.Sprintf("http://%s:%s", nodeIP, port)
	p.handleHTTPRequest(w, r, targetURL)
}

// isWebSocketRequest checks if a request is a WebSocket upgrade request
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// handleHTTPRequest handles regular HTTP requests
func (p *Proxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request, targetURL string) {
	// Parse the target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Create the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Add an error handler for more detailed logging
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("Reverse proxy error: %v", err)
		// Check if the error is specifically a connection reset
		if ne, ok := err.(*net.OpError); ok {
			if se, ok := ne.Err.(*os.SyscallError); ok {
				// Check for specific errno, e.g., syscall.ECONNRESET on Linux/Darwin
				log.Printf("Syscall error details: %v", se.Err)
			}
		}
		http.Error(rw, "Proxy Error", http.StatusBadGateway)
	}

	// Update the request Host header to match the target host
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	// Forward the request to the target
	log.Printf("Forwarding HTTP request for %s to %s", r.URL.Path, targetURL)
	proxy.ServeHTTP(w, r)
}

// Configure WebSocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins
		return true
	},
}

// handleWebSocketRequest handles WebSocket upgrade and proxying
func (p *Proxy) handleWebSocketRequest(w http.ResponseWriter, r *http.Request, targetURL string) {
	// Parse the target URL
	targetWsURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid WebSocket URL", http.StatusInternalServerError)
		return
	}

	// Create dialer for target WebSocket server
	dialer := &websocket.Dialer{}

	// Copy headers for the handshake
	requestHeader := http.Header{}
	for k, v := range r.Header {
		if k != "Upgrade" && k != "Connection" && k != "Sec-Websocket-Key" &&
			k != "Sec-Websocket-Version" && k != "Sec-Websocket-Extensions" {
			requestHeader[k] = v
		}
	}

	// Connect to the target WebSocket server
	targetConn, resp, err := dialer.Dial(targetWsURL.String(), requestHeader)
	if err != nil {
		log.Printf("WebSocket dial error: %v, response: %v", err, resp)
		http.Error(w, "Failed to connect to backend WebSocket", http.StatusInternalServerError)
		return
	}
	defer targetConn.Close()

	// Upgrade client connection to WebSocket
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer clientConn.Close()

	// Bidirectional copy of data
	copyDone := make(chan bool, 2)

	// Forward messages from client to target
	go func() {
		for {
			messageType, message, err := clientConn.ReadMessage()
			if err != nil {
				log.Printf("Error reading from client: %v", err)
				break
			}
			err = targetConn.WriteMessage(messageType, message)
			if err != nil {
				log.Printf("Error writing to target: %v", err)
				break
			}
		}
		copyDone <- true
	}()

	// Forward messages from target to client
	go func() {
		for {
			messageType, message, err := targetConn.ReadMessage()
			if err != nil {
				log.Printf("Error reading from target: %v", err)
				break
			}
			err = clientConn.WriteMessage(messageType, message)
			if err != nil {
				log.Printf("Error writing to client: %v", err)
				break
			}
		}
		copyDone <- true
	}()

	// Wait for either of the copy goroutines to exit
	<-copyDone
}
