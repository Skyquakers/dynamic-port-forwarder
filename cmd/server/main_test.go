package main_test

import (
	"os"
	"strconv"
	"strings"
	"testing"

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

// TestServerSetup tests the basic setup of the server and config loading.
// In CI environments, the test is skipped to avoid port binding issues.
// In local environments, it verifies configuration loading and proxy setup
// without starting the actual proxy servers to avoid test flakiness.
func TestServerSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Skip in CI environment to avoid port binding issues
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping in CI environment")
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

	// Set up test environment with port range
	os.Setenv("NODE_IPS", "127.0.0.1")
	os.Setenv("MIN_PORT", "60100")
	os.Setenv("MAX_PORT", "60105")
	os.Setenv("CERT_FILE", certFile.Name())
	os.Setenv("KEY_FILE", keyFile.Name())

	// Instead of running an actual test with proxy and backend servers,
	// we'll just verify that the setup and configuration loading works correctly
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Check if config was loaded correctly
	if cfg.MinPort != 60100 || cfg.MaxPort != 60105 {
		t.Errorf("Expected port range 60100-60105, got %d-%d", cfg.MinPort, cfg.MaxPort)
	}

	if len(cfg.NodeIPs) != 1 || cfg.NodeIPs[0] != "127.0.0.1" {
		t.Errorf("Expected NodeIPs [127.0.0.1], got %v", cfg.NodeIPs)
	}

	// Test certificate loading
	certManager := cert.NewManager(cfg.CertFile, cfg.KeyFile)
	tlsConfig, err := certManager.GetTLSConfig()
	if err != nil {
		t.Fatalf("Failed to load TLS config: %v", err)
	}

	if tlsConfig == nil {
		t.Error("TLS config should not be nil")
	}

	// Create proxy instance to test proxy creation
	p := proxy.NewProxy(cfg.NodeIPs, tlsConfig)
	if p == nil {
		t.Error("Proxy should not be nil")
	}

	// We won't actually start the servers since that can
	// lead to port binding issues in shared environments.
	// The actual server logic is tested in the proxy package tests.
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

	// Create temp files for certificate and key
	createTempCertFiles := func(t *testing.T) (certPath, keyPath string) {
		tmpCert, err := os.CreateTemp("", "cert-*.pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tmpCert.WriteString(validCertPEM); err != nil {
			t.Fatal(err)
		}
		tmpCert.Close()

		tmpKey, err := os.CreateTemp("", "key-*.pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tmpKey.WriteString(validKeyPEM); err != nil {
			t.Fatal(err)
		}
		tmpKey.Close()

		return tmpCert.Name(), tmpKey.Name()
	}

	// Helper to clean up temp files
	cleanupFiles := func(paths ...string) {
		for _, path := range paths {
			os.Remove(path)
		}
	}

	// Test cases
	testCases := []struct {
		name          string
		nodeIPs       string
		minPort       string
		maxPort       string
		expectError   bool
		errorContains string
	}{
		{
			name:          "Invalid port range (min > max)",
			nodeIPs:       "127.0.0.1",
			minPort:       "9000",
			maxPort:       "8000",
			expectError:   true,
			errorContains: "MIN_PORT must be less than MAX_PORT",
		},
		{
			name:          "Invalid min port format",
			nodeIPs:       "127.0.0.1",
			minPort:       "invalid",
			maxPort:       "9000",
			expectError:   true,
			errorContains: "invalid MIN_PORT",
		},
		{
			name:          "Invalid max port format",
			nodeIPs:       "127.0.0.1",
			minPort:       "8000",
			maxPort:       "invalid",
			expectError:   true,
			errorContains: "invalid MAX_PORT",
		},
		{
			name:          "Equal min and max ports",
			nodeIPs:       "127.0.0.1",
			minPort:       "8000",
			maxPort:       "8000",
			expectError:   true,
			errorContains: "MIN_PORT must be less than MAX_PORT",
		},
		{
			name:          "Valid configuration",
			nodeIPs:       "127.0.0.1",
			minPort:       "8000",
			maxPort:       "8100",
			expectError:   false,
			errorContains: "",
		},
		{
			name:          "Multiple node IPs",
			nodeIPs:       "127.0.0.1,192.168.1.1",
			minPort:       "8000",
			maxPort:       "8100",
			expectError:   false,
			errorContains: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temporary certificate files
			certPath, keyPath := createTempCertFiles(t)
			defer cleanupFiles(certPath, keyPath)

			// Set environment for this test case
			os.Setenv("NODE_IPS", tc.nodeIPs)
			os.Setenv("MIN_PORT", tc.minPort)
			os.Setenv("MAX_PORT", tc.maxPort)
			os.Setenv("CERT_FILE", certPath)
			os.Setenv("KEY_FILE", keyPath)

			// Try to load config
			config, err := config.LoadConfig()

			// Check results
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error containing %q, but got no error", tc.errorContains)
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing %q, but got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}

				// Validate the config values when no error is expected
				if config != nil {
					// Check node IPs
					expectedIPCount := 1
					if strings.Contains(tc.nodeIPs, ",") {
						expectedIPCount = len(strings.Split(tc.nodeIPs, ","))
					}
					if len(config.NodeIPs) != expectedIPCount {
						t.Errorf("Expected %d node IPs, got %d", expectedIPCount, len(config.NodeIPs))
					}

					// Check min/max ports
					expectedMinPort, _ := strconv.Atoi(tc.minPort)
					if config.MinPort != expectedMinPort {
						t.Errorf("Expected min port %d, got %d", expectedMinPort, config.MinPort)
					}

					expectedMaxPort, _ := strconv.Atoi(tc.maxPort)
					if config.MaxPort != expectedMaxPort {
						t.Errorf("Expected max port %d, got %d", expectedMaxPort, config.MaxPort)
					}
				} else {
					t.Error("Expected config to be non-nil when no error is returned")
				}
			}
		})
	}
}
