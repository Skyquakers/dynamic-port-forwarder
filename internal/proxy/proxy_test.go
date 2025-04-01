package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Mock TLS config for testing
func mockTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func TestNewProxy(t *testing.T) {
	nodeIPs := []string{"192.168.1.1", "192.168.1.2"}
	tlsConfig := mockTLSConfig()

	p := NewProxy(nodeIPs, tlsConfig)

	if len(p.nodeIPs) != len(nodeIPs) {
		t.Errorf("Expected %d node IPs, got %d", len(nodeIPs), len(p.nodeIPs))
	}

	if p.tlsConfig != tlsConfig {
		t.Error("TLS config not set correctly")
	}

	if p.servers == nil {
		t.Error("Servers map not initialized")
	}
}

func TestIsWebSocketRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "WebSocket Request",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			expected: true,
		},
		{
			name: "WebSocket Request Mixed Case",
			headers: map[string]string{
				"Upgrade": "WebSocket",
			},
			expected: true,
		},
		{
			name: "Regular HTTP Request",
			headers: map[string]string{
				"Accept": "text/html",
			},
			expected: false,
		},
		{
			name: "Different Upgrade",
			headers: map[string]string{
				"Upgrade": "h2c",
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://example.com", nil)
			for k, v := range test.headers {
				r.Header.Set(k, v)
			}

			result := isWebSocketRequest(r)
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestGetNodeIP(t *testing.T) {
	tests := []struct {
		name     string
		nodeIPs  []string
		expected string
	}{
		{
			name:     "Single IP",
			nodeIPs:  []string{"192.168.1.1"},
			expected: "192.168.1.1",
		},
		{
			name:     "Multiple IPs",
			nodeIPs:  []string{"192.168.1.1", "192.168.1.2"},
			expected: "192.168.1.1", // Current implementation returns first IP
		},
		{
			name:     "Empty IPs",
			nodeIPs:  []string{},
			expected: "127.0.0.1", // Default localhost
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := NewProxy(test.nodeIPs, mockTLSConfig())
			result := p.getNodeIP()

			if result != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, result)
			}
		})
	}
}

func TestStartAndStopServer(t *testing.T) {
	p := NewProxy([]string{"127.0.0.1"}, mockTLSConfig())

	// Start a server on a random high port
	port := 50000
	err := p.StartServer(port)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Check if server exists in map
	p.serversLock.Lock()
	_, exists := p.servers[port]
	p.serversLock.Unlock()

	if !exists {
		t.Errorf("Server not found in servers map")
	}

	// Try to start server on same port (should fail)
	err = p.StartServer(port)
	if err == nil {
		t.Error("Expected error when starting server on same port, got none")
	}

	// Stop the server
	err = p.StopServer(port)
	if err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	// Wait a bit for the server to shut down
	time.Sleep(100 * time.Millisecond)

	// Check if server was removed from map
	p.serversLock.Lock()
	_, exists = p.servers[port]
	p.serversLock.Unlock()

	if exists {
		t.Error("Server should have been removed from servers map")
	}

	// Try to stop non-existent server
	err = p.StopServer(port)
	if err == nil {
		t.Error("Expected error when stopping non-existent server, got none")
	}
}

func TestStopAll(t *testing.T) {
	p := NewProxy([]string{"127.0.0.1"}, mockTLSConfig())

	// Start multiple servers
	ports := []int{50001, 50002, 50003}
	for _, port := range ports {
		err := p.StartServer(port)
		if err != nil {
			t.Fatalf("Failed to start server on port %d: %v", port, err)
		}
	}

	// Check if servers exist in map
	p.serversLock.Lock()
	serverCount := len(p.servers)
	p.serversLock.Unlock()

	if serverCount != len(ports) {
		t.Errorf("Expected %d servers, got %d", len(ports), serverCount)
	}

	// Stop all servers
	p.StopAll()

	// Wait a bit for servers to shut down
	time.Sleep(100 * time.Millisecond)

	// Check if all servers were removed from map
	p.serversLock.Lock()
	serverCount = len(p.servers)
	p.serversLock.Unlock()

	if serverCount != 0 {
		t.Errorf("Expected 0 servers after StopAll, got %d", serverCount)
	}
}

// Test HTTP handlers with mock backend servers
func TestHTTPHandlers(t *testing.T) {
	// Mock backend HTTP server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "test-value")
		fmt.Fprintln(w, "Hello from backend server")
	}))
	defer backendServer.Close()

	// Extract host and port from backend URL
	backendURL := backendServer.URL
	parts := strings.Split(strings.TrimPrefix(backendURL, "http://"), ":")
	backendHost := parts[0]

	// Create proxy with the backend server's host
	p := NewProxy([]string{backendHost}, mockTLSConfig())

	// Create request with Host header matching the backend server's port
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	req.Host = "example.com:" + parts[1] // Use the backend server's port

	// Record the response
	w := httptest.NewRecorder()

	// Call the handler
	p.handleHTTPRequest(w, req, backendURL)

	// Check response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Status)
	}

	if resp.Header.Get("X-Test-Header") != "test-value" {
		t.Errorf("Expected test header value, not found")
	}
}

// Test WebSocket handlers with mock backend servers
func TestWebSocketHandlers(t *testing.T) {
	// This is a more complex test that would require a full WebSocket server and client
	// For simplicity, we'll just test the isWebSocketRequest function again
	t.Skip("WebSocket handler tests would require a full WebSocket setup; skipping.")
}

func TestProxy(t *testing.T) {
	// Create a mock backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Backend received: " + r.URL.Path))
	}))
	defer backendServer.Close()

	// Create mock TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Node IP Selection test
	t.Run("Node IP Selection", func(t *testing.T) {
		// Test with no nodes
		emptyProxy := NewProxy([]string{}, tlsConfig)
		nodeIP := emptyProxy.getNodeIP()
		if nodeIP != "127.0.0.1" {
			t.Errorf("Expected default nodeIP 127.0.0.1, got %s", nodeIP)
		}

		// Test with multiple nodes (currently just returns first one)
		multiNodeProxy := NewProxy([]string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}, tlsConfig)
		nodeIP = multiNodeProxy.getNodeIP()
		if nodeIP != "192.168.1.1" {
			t.Errorf("Expected first nodeIP 192.168.1.1, got %s", nodeIP)
		}
	})

	t.Run("WebSocket Detection", func(t *testing.T) {
		// Test with WebSocket upgrade request
		wsReq := httptest.NewRequest("GET", "https://example.com/ws", nil)
		wsReq.Header.Set("Upgrade", "websocket")
		wsReq.Header.Set("Connection", "upgrade")

		if !isWebSocketRequest(wsReq) {
			t.Error("Failed to identify WebSocket request")
		}

		// Test with normal HTTP request
		httpReq := httptest.NewRequest("GET", "https://example.com/path", nil)

		if isWebSocketRequest(httpReq) {
			t.Error("Incorrectly identified normal HTTP request as WebSocket")
		}

		// Test with mixed case header
		mixedCaseReq := httptest.NewRequest("GET", "https://example.com/ws", nil)
		mixedCaseReq.Header.Set("Upgrade", "WebSocket")

		if !isWebSocketRequest(mixedCaseReq) {
			t.Error("Failed to identify WebSocket request with mixed case header")
		}
	})
}
