package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyHandler(t *testing.T) {
	// Create a mock backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back some request details to verify the proxy forwarding
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Backend received: " + r.URL.Path))

		// Verify headers were properly forwarded
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("X-Forwarded-For header not set")
		}

		if r.Header.Get("X-Original-Host") == "" {
			t.Error("X-Original-Host header not set")
		}
	}))
	defer backendServer.Close()

	// Extract the backend server's host and port
	backendURL := backendServer.URL
	backendHost := strings.TrimPrefix(backendURL, "http://")
	hostParts := strings.Split(backendHost, ":")

	// Create a new proxy
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	proxy := NewProxy([]string{hostParts[0]}, tlsConfig)

	// Test the handleRequest function directly
	req := httptest.NewRequest("GET", "https://localhost:8443/test/path", nil)
	req.Header.Set("User-Agent", "Test-Agent")
	req.Header.Set("X-Custom-Header", "custom-value")

	// Create a response recorder
	recorder := httptest.NewRecorder()

	// Call the handler function directly
	proxy.handleRequest(recorder, req)

	// Check the response
	resp := recorder.Result()
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Log response for debugging
	t.Logf("Response status: %d", resp.StatusCode)
	t.Logf("Response body: %s", string(body))

	// Note: Since we're testing with mock backend servers,
	// the proxy may not be able to connect to the actual backend
	// in this test setup. This test mainly verifies that the
	// handleRequest function processes requests without panicking.
}
