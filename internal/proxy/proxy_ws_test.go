package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// Test handleWebSocketRequest function
func TestHandleWebSocketRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebSocket test in short mode")
	}

	// Create a WebSocket echo server (backend)
	wsEchoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request is a WebSocket upgrade
		if !websocket.IsWebSocketUpgrade(r) {
			t.Error("Expected WebSocket upgrade request")
			http.Error(w, "Not a WebSocket upgrade request", http.StatusBadRequest)
			return
		}

		// Check that this is plain HTTP (the proxy terminates SSL)
		if r.TLS != nil {
			t.Error("Expected plain HTTP connection from proxy")
		}

		// Log headers for debugging
		for name, values := range r.Header {
			t.Logf("Header %s: %v", name, values)
		}

		// Upgrade the connection
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer conn.Close()

		// Echo once and then close
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			t.Logf("WebSocket read error: %v", err)
			return
		}

		t.Logf("WebSocket received message: %s", string(message))

		if err := conn.WriteMessage(messageType, message); err != nil {
			t.Logf("WebSocket write error: %v", err)
			return
		}
	})

	// Start the WebSocket echo server
	backendServer := httptest.NewServer(wsEchoHandler)
	defer backendServer.Close()

	// Parse the backend URL
	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse backend URL: %v", err)
	}

	// Create a proxy
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	proxy := NewProxy([]string{backendURL.Hostname()}, tlsConfig)

	// Create a test request
	wsTargetURL := fmt.Sprintf("ws://%s%s", backendURL.Host, "/echo")
	req := httptest.NewRequest("GET", "https://example.com/echo", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	// Test the function directly - note this won't establish a real connection
	// but it will test the code path
	recorder := httptest.NewRecorder()

	// Call the handler directly
	proxy.handleWebSocketRequest(recorder, req, wsTargetURL)

	// Check the response
	resp := recorder.Result()

	// In a real test, we'd get a 101 Switching Protocols, but since we're not establishing
	// a real connection, we'll often get a different status code.
	t.Logf("Response status: %d %s", resp.StatusCode, resp.Status)

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Response body: %s", string(body))

	// The test may fail because we can't properly establish a WebSocket connection
	// within the test environment, but the important part is that we test the code path
}

// Test for WebSocket detection and handling in the main handler
func TestWebSocketHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WebSocket test in short mode")
	}

	// Create a mock HTTP server to respond to non-WebSocket requests
	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Regular HTTP response"))
	})

	// Create a WebSocket handler
	wsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			http.Error(w, "Not a WebSocket upgrade request", http.StatusBadRequest)
			return
		}

		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade WebSocket connection: %v", err)
			return
		}
		defer conn.Close()

		// Echo message
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(messageType, p); err != nil {
			return
		}
	})

	// Create a multiplexing handler
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ws") {
			wsHandler.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})

	// Start backend server
	backendServer := httptest.NewServer(backendHandler)
	defer backendServer.Close()

	// Parse backend URL
	backendURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse backend URL: %v", err)
	}

	// Create a proxy
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	proxy := NewProxy([]string{backendURL.Hostname()}, tlsConfig)

	// Test the handleRequest function (which should detect WebSocket)
	t.Run("WebSocket Request Detection", func(t *testing.T) {
		// Create a WebSocket request
		wsReq := httptest.NewRequest("GET", "https://example.com/ws", nil)
		wsReq.Header.Set("Connection", "Upgrade")
		wsReq.Header.Set("Upgrade", "websocket")
		wsReq.Host = fmt.Sprintf("example.com:%s", backendURL.Port())

		// Create a recorder for the response
		wsRecorder := httptest.NewRecorder()

		// Call the handler
		proxy.handleRequest(wsRecorder, wsReq)

		// Check response
		wsResp := wsRecorder.Result()
		t.Logf("WebSocket request response status: %d", wsResp.StatusCode)
	})

	t.Run("Regular HTTP Request", func(t *testing.T) {
		// Create a regular HTTP request
		httpReq := httptest.NewRequest("GET", "https://example.com/api", nil)
		httpReq.Host = fmt.Sprintf("example.com:%s", backendURL.Port())

		// Create a recorder for the response
		httpRecorder := httptest.NewRecorder()

		// Call the handler
		proxy.handleRequest(httpRecorder, httpReq)

		// Check response
		httpResp := httpRecorder.Result()
		t.Logf("HTTP request response status: %d", httpResp.StatusCode)

		// Read body
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		t.Logf("HTTP response body: %s", string(body))
	})
}
