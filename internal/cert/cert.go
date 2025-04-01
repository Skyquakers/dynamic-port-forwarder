package cert

import (
	"crypto/tls"
	"fmt"
	"os"
)

// Manager handles SSL certificates
type Manager struct {
	certFile string
	keyFile  string
}

// NewManager creates a new certificate manager
func NewManager(certFile, keyFile string) *Manager {
	return &Manager{
		certFile: certFile,
		keyFile:  keyFile,
	}
}

// LoadCertificate loads the TLS certificate and key
func (m *Manager) LoadCertificate() (*tls.Certificate, error) {
	// Check if cert files exist
	if _, err := os.Stat(m.certFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", m.certFile)
	}
	if _, err := os.Stat(m.keyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("key file not found: %s", m.keyFile)
	}

	// Load the certificate
	cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	return &cert, nil
}

// GetTLSConfig returns a TLS config with the loaded certificate
func (m *Manager) GetTLSConfig() (*tls.Config, error) {
	cert, err := m.LoadCertificate()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
