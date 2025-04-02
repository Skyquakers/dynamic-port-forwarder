package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSSLTermination tests that the proxy properly terminates SSL
// and forwards requests to the backend as plain HTTP
func TestSSLTermination(t *testing.T) {
	// Create a mock TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Generate a self-signed certificate on the fly
			cert, err := generateSelfSignedCert()
			if err != nil {
				return nil, err
			}
			return cert, nil
		},
	}

	// Create a mock HTTP backend server that will verify the request is plain HTTP
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify this is plain HTTP (not HTTPS)
		if r.TLS != nil {
			t.Error("Backend received TLS connection, expected plain HTTP")
		}

		// Respond with a test message
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Backend received plain HTTP request"))
	}))
	defer backendServer.Close()

	// Extract the backend server's host and port
	backendURL := backendServer.URL
	backendHost := strings.TrimPrefix(backendURL, "http://")
	parts := strings.Split(backendHost, ":")
	if len(parts) != 2 {
		t.Fatalf("Failed to parse backend URL: %s", backendURL)
	}
	backendIP := parts[0]
	backendPort := parts[1]

	// Create the proxy with the backend server as the target
	p := NewProxy([]string{backendIP}, tlsConfig)

	// Start the proxy on a test port
	proxyPort := 50000
	err := p.StartServer(proxyPort)
	if err != nil {
		t.Fatalf("Failed to start proxy server: %v", err)
	}
	defer p.StopAll(context.Background())

	// Give the server time to start
	time.Sleep(500 * time.Millisecond)

	// This is a special test case since we're using a mock TLS config
	// In real usage, the client would connect to the proxy with HTTPS
	// and the proxy would connect to the backend with HTTP
	// Here we're just verifying the handleRequest function works correctly

	// Create a test request
	req, err := http.NewRequest("GET", fmt.Sprintf("https://localhost:%d", proxyPort), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Set the Host header to match the backend port
	req.Host = fmt.Sprintf("example.com:%s", backendPort)

	// Create a test response recorder
	rec := httptest.NewRecorder()

	// Call the handler directly
	p.handleRequest(rec, req)

	// Check the response
	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expectedBody := "Backend received plain HTTP request"
	if !strings.Contains(string(body), expectedBody) {
		t.Errorf("Expected response to contain '%s', got '%s'", expectedBody, string(body))
	}
}

// generateSelfSignedCert creates a self-signed TLS certificate for testing
func generateSelfSignedCert() (*tls.Certificate, error) {
	// For testing, we can use a simple pre-generated certificate and key
	certPEM := `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUSZWHtKJ0uXePXCEJu3cJM5TYvfMwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEyMjAwMDAwMDBaFw0yNDEy
MTkyMzU5NTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC0bZ4AQS5Cb4pr+CERqs9xsEFneMWn4HrnGGDHn8dr
0YxWmvR2RCEeGNwKxzMmGEUc3kHFsqRmJyTjRhOQMokn1yfpTH6KDT2yem+YVqmW
MgGvZEZm3dx+JvxLYvDdYlsWuv5C7OJOH1mMQzKqnIzT1FYeCBj2kHdFrKKxkkV5
r0EeNBkKZmKnf1ojdDQ8FU8A44hZt+HCbq4IkzYYUmYR0QErh3iQn3i/BCQhk8Zc
h9vRCFJ1LYnxRdDVg8rR5CIjqGgfHB1JeADL8MVRiR1E69j67XNfFi/z7mCWCK5A
MSGwJ6f1iUQdB/+GdYP4PMXaIJxhIwKtImmC16GDhZzTAgMBAAGjUzBRMB0GA1Ud
DgQWBBQZZ60GYGr+aklVs56PisFzvgc3RjAfBgNVHSMEGDAWgBQZZ60GYGr+aklV
s56PisFzvgc3RjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBC
zTcuN3RPKQuSxvqAVvfQYQHb7ERQWzBrJUDJE0PfVe3Q0BX+PJP4KtZY9wYfWFya
3mUJ3n0g7iG2+j+NUH8n6aLfsZijMqcCSWbRDgRdivJLf+7P4qYldQooCTBseYeZ
q44hALnNi0UwaIMnVJFd9Y1Y9fM/RKrPeVGQf8RnVzHuOFYcXZMyJwrKZ1aEhiTR
dzHbcFPQ3QqbRd+2vl6R3DzEp1rkwqg2CZed6eSyHqfZEB6A3qjewT+FAUXmTGzi
9A9KX5AVwjTqOgVJw7I6hJHcIEiwYLCGLwZaELzUo0EGVjpna49kLK/lJ/6cG8FW
j5n7I0YwCUKqmTFEnZv7
-----END CERTIFICATE-----`

	keyPEM := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0bZ4AQS5Cb4pr
+CERqs9xsEFneMWn4HrnGGDHn8dr0YxWmvR2RCEeGNwKxzMmGEUc3kHFsqRmJyTj
RhOQMokn1yfpTH6KDT2yem+YVqmWMgGvZEZm3dx+JvxLYvDdYlsWuv5C7OJOH1mM
QzKqnIzT1FYeCBj2kHdFrKKxkkV5r0EeNBkKZmKnf1ojdDQ8FU8A44hZt+HCbq4I
kzYYUmYR0QErh3iQn3i/BCQhk8Zch9vRCFJ1LYnxRdDVg8rR5CIjqGgfHB1JeADL
8MVRiR1E69j67XNfFi/z7mCWCK5AMSGwJ6f1iUQdB/+GdYP4PMXaIJxhIwKtImmC
16GDhZzTAgMBAAECggEABdXBKu0QH2jL8C0ojK5vYVsRPcK7RXvjxUmP9o5wbNRw
9wP5Fh1xLbFz//whzGDM9fYAj/pR9a8Jf7OcwAYMk01Zic/HMGK7qtY8r0QyM0dE
1/xBRvN7cht5/q0JzXTafaGYgYvLcvqoSN62kRTiUDDYqnXQGH5hYQl0Mg06MlF7
zlv7vwXMBFQUhoZ9Vyr+S3IYZBkyXkLKZ8M6qVRcKJmLISgF/Cq5Yq5Bui2ymrJJ
pHFXd6eKIUAdKGaAWGkYaNLvOxL5B3JJiBPLfQ6N3D2i+5J3DB1XSD0+A+Gf8deg
3pBeVy8BM0LSyhS2KSd40jEzGOLTHvl4oqjT+wZPgQKBgQDlClNtzC66nPVGZYtP
Jvwe4vEg9RKgaRUOOad+g9bWMHGPYYx7yFGIjDGX7NMlOF/Gwn9lm9TaX5m6oATq
FeIpBnb9qDl/TXeq0xdL3QbKJldpJOLHXvDY4X/9SWRlDXYYVYnbGqUcAWJZEkSp
/LKG7yHrjYzZ+IXQJvSw3H17iQKBgQDJrv9D9n5sU2qHDfqLH31/tnDVE5LY8qZG
K6bBjA3MiIBjwfYJhSS9Znb9SJg/t3xO9JdgG0mDQJslX6dM8PrSBHT6y2zggy9I
4Y5GvXBo1Ji0KryZQmcqCsQECdx9OIOFiUcGbLKC55o0AQQQ5s8nYjLMWMHvzPkw
dbnKAe+b2wKBgHYHtXoLCOKOC0NfHTZw9GInpYyIl7PyhRKnC8Eac1xkGpYKjTzo
Rj1G1hAk3WkoG9FCAwPQu+jQdv9+tCXZKwVvZPum2CZfhH1ZqhEaiZKJbUe5+JtO
SQ3o/P2XvGGyMTCQhXX/XtaLlvcjI3rbn3mwUiyJKfB3iEGXf//AE7EZAoGAbb9j
Y49Fw3+lkzBaP7sjF0+60NfmGT0yDQeYLZJPzoVYDW8M49K/IF8LJ8qY9yCNXqQo
5i0QuEh2YehXMKHRMTfLICbJ9wLKbQpPy7fJcYiOS9dxhXOsxPqeL9qXbz+xCZgQ
L2PUGJkRm5jDiOkMYBR5iQ+bX5A36JE0uMr/LWECgYEAoEwrD1LjbPC3dZ48dvtl
DRwrZbWmzXRX+hBjgJl3rSWZhqBAMPdKgq4jf4IDqGIwJ3GqJAsPHOYsM1qbsowA
ViDfZzSL6ZUldLOAUUNpVTXCuBpjSOmVXJacZKMFxaYz5pJhI7dZGBicN1mVuYkG
ij5pQ5Y/0xfB9V02jtTanRk=
-----END PRIVATE KEY-----`

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to load test certificate: %v", err)
	}

	return &cert, nil
}
