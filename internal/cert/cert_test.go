package cert

import (
	"crypto/tls"
	"os"
	"testing"
	"time"
)

// Mock certificate and key content for testing
// This is a properly formatted self-signed certificate and key pair
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

	invalidCertContent = "This is not a valid certificate"
	invalidKeyContent  = "This is not a valid private key"
)

func setupTestCerts(t *testing.T, certContent, keyContent string) (certPath, keyPath string, cleanup func()) {
	// Create temporary certificate and key files
	certFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.CreateTemp("", "key-*.pem")
	if err != nil {
		os.Remove(certFile.Name())
		t.Fatal(err)
	}

	// Write test certificate and key content
	if _, err := certFile.WriteString(certContent); err != nil {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
		t.Fatal(err)
	}

	if _, err := keyFile.WriteString(keyContent); err != nil {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
		t.Fatal(err)
	}

	// Close files
	certFile.Close()
	keyFile.Close()

	cleanup = func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	}

	return certFile.Name(), keyFile.Name(), cleanup
}

func TestNewManager(t *testing.T) {
	certPath := "/path/to/cert.pem"
	keyPath := "/path/to/key.pem"

	manager := NewManager(certPath, keyPath)

	if manager.certFile != certPath {
		t.Errorf("Expected certFile to be %s, got %s", certPath, manager.certFile)
	}

	if manager.keyFile != keyPath {
		t.Errorf("Expected keyFile to be %s, got %s", keyPath, manager.keyFile)
	}
}

func TestLoadCertificate(t *testing.T) {
	// Test with valid certificate and key
	t.Run("Valid Certificate", func(t *testing.T) {
		certPath, keyPath, cleanup := setupTestCerts(t, validCertPEM, validKeyPEM)
		defer cleanup()

		manager := NewManager(certPath, keyPath)
		cert, err := manager.LoadCertificate()

		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if cert == nil {
			t.Error("Expected certificate, got nil")
		}
	})

	// Test with non-existent certificate
	t.Run("Non-existent Certificate", func(t *testing.T) {
		manager := NewManager("/non/existent/cert.pem", "/non/existent/key.pem")
		cert, err := manager.LoadCertificate()

		if err == nil {
			t.Fatal("Expected error for non-existent certificate, got none")
		}

		if cert != nil {
			t.Error("Expected nil certificate, got one")
		}
	})

	// Test with invalid certificate content
	t.Run("Invalid Certificate Content", func(t *testing.T) {
		certPath, keyPath, cleanup := setupTestCerts(t, invalidCertContent, invalidKeyContent)
		defer cleanup()

		manager := NewManager(certPath, keyPath)
		cert, err := manager.LoadCertificate()

		if err == nil {
			t.Fatal("Expected error for invalid certificate content, got none")
		}

		if cert != nil {
			t.Error("Expected nil certificate, got one")
		}
	})
}

func TestGetTLSConfig(t *testing.T) {
	// Test with valid certificate and key
	t.Run("Valid Certificate", func(t *testing.T) {
		certPath, keyPath, cleanup := setupTestCerts(t, validCertPEM, validKeyPEM)
		defer cleanup()

		manager := NewManager(certPath, keyPath)
		tlsConfig, err := manager.GetTLSConfig()

		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if tlsConfig == nil {
			t.Error("Expected TLS config, got nil")
		}

		if tlsConfig.GetCertificate == nil {
			t.Fatalf("Expected GetCertificate to be set on TLS config")
		}

		gotCert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatalf("Expected GetCertificate to succeed, got error: %v", err)
		}
		if gotCert == nil {
			t.Fatalf("Expected GetCertificate to return a cert, got nil")
		}

		if tlsConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("Expected TLS version TLS1.2, got %d", tlsConfig.MinVersion)
		}
	})

	// Test with invalid certificate
	t.Run("Invalid Certificate", func(t *testing.T) {
		manager := NewManager("/non/existent/cert.pem", "/non/existent/key.pem")
		tlsConfig, err := manager.GetTLSConfig()

		if err == nil {
			t.Fatal("Expected error for invalid certificate, got none")
		}

		if tlsConfig != nil {
			t.Error("Expected nil TLS config, got one")
		}
	})
}

func TestReloadIfChanged(t *testing.T) {
	certPath, keyPath, cleanup := setupTestCerts(t, validCertPEM, validKeyPEM)
	defer cleanup()

	manager := NewManager(certPath, keyPath)
	tlsConfig, err := manager.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}

	c1, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || c1 == nil {
		t.Fatalf("initial GetCertificate failed: %v (cert=%v)", err, c1)
	}

	// First reload check without changes should be a no-op.
	reloaded, err := manager.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged failed: %v", err)
	}
	if reloaded {
		t.Fatalf("Expected no reload when files unchanged")
	}

	// Force mtime change to simulate certificate refresh.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("Failed to chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatalf("Failed to chtimes key: %v", err)
	}

	reloaded, err = manager.ReloadIfChanged()
	if err != nil {
		t.Fatalf("ReloadIfChanged after change failed: %v", err)
	}
	if !reloaded {
		t.Fatalf("Expected reload after mtime change")
	}

	c2, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || c2 == nil {
		t.Fatalf("post-reload GetCertificate failed: %v (cert=%v)", err, c2)
	}
	if c1 == c2 {
		t.Fatalf("Expected certificate pointer to change after reload")
	}
}
