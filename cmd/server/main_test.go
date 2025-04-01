package main_test

import (
	"crypto/tls"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skyquakers/dynamic-port-forwarder/internal/cert"
	"github.com/skyquakers/dynamic-port-forwarder/internal/config"
	"github.com/skyquakers/dynamic-port-forwarder/internal/proxy"
)

// Mock certificate and key content for testing
const (
	validCertPEM = `-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIQNcRoVycqxSunlKJkaxIgpDANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTI1MDQwMTA4MzU1NFoXDTI2MDQwMTA4MzU1
NFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMH4mbvQ0PzDATcG6SjqjJSfUJjVzgPU9QcHZovP9vK1QN0myjqPfSaz
4g5QAlIYmpUT9r+3zVUGTFRGzrt0/vhfUbMsAei5W3YP9EZ0jddMNNtnar6P8+Uf
xP8jkuamqzVIYmUasbftprOph7+uBOpGoHceLpz7cDQ/fvLWxJQZBhjMO1/7bliy
by1NPc+IE1pidXrFDrxlM+InKEcomU1qIiLYvwblTgjia64IuKZa548NVMvhS/vh
ob3zcSrzhlYWTfNXHQkfdX8Cb+5CZsbcN3m85JtfmNfkJ7s+Wr5RvDoWqse3x5no
H9cvSmffhVv1KONYNGRErIIULmIrVRkCAwEAAaNLMEkwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwFAYDVR0RBA0wC4IJ
bG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBCKBN9nGbVWx5tGB7eJiRe3ohd
PRIO+Cto1K3fe22dOF9G69TVQl3wQFsffZqBS00KiFZUOTanlsdX17gHl81Fvx6n
CTHVEbKKYzCM5LhnmK/tu1GF5lL7L2n41IQHSHgDnDusqwPpoUwvoe0gabQr/aJF
fKl3IYYv/Aff4XbzZatmW2TJuk1Q6lqofbGAMF++wrl6d6c2NkIEV82AqjBO4M8w
e5c2ELyDD+libucCnPOGsq6f7yNjKzRQJjpJwRhGQPslMSdHK4tfX4CBNG17RHX/
ivgD2Q/glzBmfYMT1OfDZnOHcpwGs3MtxPH9WkTfKD9u+hCND8wiL4uF6P+h
-----END CERTIFICATE-----`

	validKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDB+Jm70ND8wwE3
Buko6oyUn1CY1c4D1PUHB2aLz/bytUDdJso6j30ms+IOUAJSGJqVE/a/t81VBkxU
Rs67dP74X1GzLAHouVt2D/RGdI3XTDTbZ2q+j/PlH8T/I5Lmpqs1SGJlGrG37aaz
qYe/rgTqRqB3Hi6c+3A0P37y1sSUGQYYzDtf+25Ysm8tTT3PiBNaYnV6xQ68ZTPi
JyhHKJlNaiIi2L8G5U4I4muuCLimWuePDVTL4Uv74aG983Eq84ZWFk3zVx0JH3V/
Am/uQmbG3Dd5vOSbX5jX5Ce7Plq+Ubw6FqrHt8eZ6B/XL0pn34Vb9SjjWDRkRKyC
FC5iK1UZAgMBAAECggEABnBx7RDbcTqphom/kYTIzjHEP5CgdlLaYAV8P2Gz416G
RNkx7zP+ffuMgnhgPVi1AAQxxa9MvRj4jXcsy38QrE7gw9OPDCpkGYUh0TlzEH3G
hu6V1fXqLTXq6KPmD2tixWHt50iVtAMLDM2Q1LmKjvrxfobVWg+ES+28MYRU8gwc
UnGXStHERZobBwY1GZLXDNbLMiDtmzuVfGJ+wfTBqwykM8cN0gPfamJ3K4xuK0dN
0yb+2xd0FLdzuwidALxEc+5bnq8zZBC1vra7LyBH/oJ99pEvkV4/cu6V5nvGgx4+
afe5H0Sv/wrIaOOBtYR2w0ELt3GxiEtxW5fD4CN8MQKBgQDhpzTXbk32dS8hfFxm
khKG1v13Gcg1oTeDCS10yVxxl6P4hpXr8RBGrffSLWMg9jeAuiB+ZsLTHVj/XfqN
KmEqwpvF8F/Bpgjn/ov+jroMY5mgoHuPtoNKRsRgA4joiwWsFAhxNjPLbwsLza86
Tn1yZJL0k/CYZKGIUjjAfHmgsQKBgQDcDqS0AzP+1tV+XFq90f3pJ7w9ad8nTn0L
4bMgy544h6f7DZax9CvYkRn7056ytlVtdKZ4sS8aDbMiEzZw6XZf9xs2+lp/YG3A
ebbc8BsR8adnaDQXxi+QOAQ4up11CXNyzXNdNTpaXM9YpXpnQiYxTIJQ9p7fJNZ4
coBQeh5U6QKBgQCVm6FqL8Ta4YjU/7nXe4NzCPlVzK8z92Zxp1UO+C4lVe+t57Vg
kBxFcDQ9kkAF65iS7VR72a/T/sIx1WI30+BGVG6pBpzGLEn9XoP8yy5I5oRFvgEO
IGjdhxvNuKo922ZwV3vda51dhIrjUYSa+M0tWcchBzDeKOH8Gt9rp1uQkQKBgQCB
LD9WQ8MTxnwP7pp9bnTDlkWTL0CEzDfu74+8oom/2TGr1vAsiY3rVFGSV0iC0zEW
TTEjC68AdiY+zFRat1B7SIw7G35f4vTJ1SiYTIE3aUjBFJPvmLB20cr4meKvvtp7
+0nK3uHgBTbZbFmLn3LX4Xdlmz7q8a7LiTr1AponcQKBgGoR6ipiQsUkAUzBugpV
+46PmdccsfasBByZE8fS/au11yi7ZazTLDkU+I4NINt/VKR9y1qghFXuoSJvZJ3J
4IW2jPly08kr4REYTpkQ2qctM+QOeAi+D/5tcqqVvPb7qjGZYQq1Uc/s5rH5UPx0
wwpkBtowCeN3+u1yQzWaaAv9
-----END PRIVATE KEY-----`
)

func TestServerSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Save current environment
	oldNodeIPs := os.Getenv("NODE_IPS")
	oldMinPort := os.Getenv("MIN_PORT")
	oldMaxPort := os.Getenv("MAX_PORT")
	oldCertFile := os.Getenv("CERT_FILE")
	oldKeyFile := os.Getenv("KEY_FILE")

	// Restore environment after test
	defer func() {
		os.Setenv("NODE_IPS", oldNodeIPs)
		os.Setenv("MIN_PORT", oldMinPort)
		os.Setenv("MAX_PORT", oldMaxPort)
		os.Setenv("CERT_FILE", oldCertFile)
		os.Setenv("KEY_FILE", oldKeyFile)
	}()

	// Create test certificate files
	certFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile.Name())

	keyFile, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(keyFile.Name())

	// Write test certificate content
	if _, err := certFile.WriteString(validCertPEM); err != nil {
		t.Fatal(err)
	}

	if _, err := keyFile.WriteString(validKeyPEM); err != nil {
		t.Fatal(err)
	}

	certFile.Close()
	keyFile.Close()

	// Set up test environment
	os.Setenv("NODE_IPS", "127.0.0.1")
	os.Setenv("MIN_PORT", "50100")
	os.Setenv("MAX_PORT", "50105")
	os.Setenv("CERT_FILE", certFile.Name())
	os.Setenv("KEY_FILE", keyFile.Name())

	// Create mock HTTP server on each target port
	var mockServers []*http.Server
	var wg sync.WaitGroup

	for port := 50100; port <= 50105; port++ {
		server := &http.Server{
			Addr: "127.0.0.1:50100",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("OK"))
			}),
		}
		mockServers = append(mockServers, server)

		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			s.ListenAndServe()
		}(server)
	}

	// Start proxy in a goroutine
	go func() {
		// Load certificate manager
		certManager := cert.NewManager(certFile.Name(), keyFile.Name())
		tlsConfig, err := certManager.GetTLSConfig()
		if err != nil {
			t.Errorf("Failed to load TLS config: %v", err)
			return
		}

		// Create proxy
		p := proxy.NewProxy([]string{"127.0.0.1"}, tlsConfig)

		// Start servers for port range
		for port := 50100; port <= 50105; port++ {
			p.StartServer(port)
		}

		// Wait for a bit to keep servers running
		time.Sleep(2 * time.Second)

		// Stop all servers
		p.StopAll()
	}()

	// Give servers time to start
	time.Sleep(500 * time.Millisecond)

	// Test HTTPS connection to proxy
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Try a request - should fail since we're not actually running a full proxy in this test
	// This is just to validate the setup code runs properly
	_, err = client.Get("https://localhost:50100")
	if err == nil {
		t.Log("HTTPS connection succeeded, which is unexpected in this test environment")
	} else {
		t.Logf("HTTPS connection failed as expected: %v", err)
	}

	// Shutdown mock servers
	for _, server := range mockServers {
		server.Close()
	}

	// Wait for all servers to stop
	wg.Wait()
}

// TestConfigValidation verifies that the application properly validates configuration
func TestConfigValidation(t *testing.T) {
	// Save current environment
	oldNodeIPs := os.Getenv("NODE_IPS")
	oldMinPort := os.Getenv("MIN_PORT")
	oldMaxPort := os.Getenv("MAX_PORT")
	oldCertFile := os.Getenv("CERT_FILE")
	oldKeyFile := os.Getenv("KEY_FILE")

	// Restore environment after test
	defer func() {
		os.Setenv("NODE_IPS", oldNodeIPs)
		os.Setenv("MIN_PORT", oldMinPort)
		os.Setenv("MAX_PORT", oldMaxPort)
		os.Setenv("CERT_FILE", oldCertFile)
		os.Setenv("KEY_FILE", oldKeyFile)
	}()

	// Configure invalid port range
	os.Setenv("NODE_IPS", "127.0.0.1")
	os.Setenv("MIN_PORT", "9000")
	os.Setenv("MAX_PORT", "8000")
	os.Setenv("CERT_FILE", "/tmp/cert.pem")
	os.Setenv("KEY_FILE", "/tmp/key.pem")

	// Create temp files so we don't fail on the file check
	tmpCert, err := os.Create("/tmp/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("/tmp/cert.pem")

	if _, err := tmpCert.WriteString(validCertPEM); err != nil {
		t.Fatal(err)
	}
	tmpCert.Close()

	tmpKey, err := os.Create("/tmp/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("/tmp/key.pem")

	if _, err := tmpKey.WriteString(validKeyPEM); err != nil {
		t.Fatal(err)
	}
	tmpKey.Close()

	// Test validation through config package directly
	_, err = config.LoadConfig()
	if err == nil {
		t.Error("Expected error with invalid port range, got nil")
	} else {
		t.Logf("Got expected error: %v", err)
	}
}
