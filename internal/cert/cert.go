package cert

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Manager handles SSL certificates
type Manager struct {
	certFile string
	keyFile  string

	current atomic.Pointer[tls.Certificate]

	mu              sync.Mutex
	lastCertMTimeNS int64
	lastKeyMTimeNS  int64
	lastCertSize    int64
	lastKeySize     int64
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

// LoadAndStore loads the certificate from disk and stores it as the "current" certificate.
// It also snapshots the cert/key file mtimes for change detection.
func (m *Manager) LoadAndStore() error {
	cert, err := m.LoadCertificate()
	if err != nil {
		return err
	}

	certInfo, err := os.Stat(m.certFile)
	if err != nil {
		return fmt.Errorf("failed to stat certificate file %s: %v", filepath.Clean(m.certFile), err)
	}
	keyInfo, err := os.Stat(m.keyFile)
	if err != nil {
		return fmt.Errorf("failed to stat key file %s: %v", filepath.Clean(m.keyFile), err)
	}

	// Store cert first so GetCertificate can serve it even if mtimes are zeroed later.
	m.current.Store(cert)

	m.mu.Lock()
	m.lastCertMTimeNS = certInfo.ModTime().UnixNano()
	m.lastKeyMTimeNS = keyInfo.ModTime().UnixNano()
	m.lastCertSize = certInfo.Size()
	m.lastKeySize = keyInfo.Size()
	m.mu.Unlock()

	return nil
}

// ReloadIfChanged reloads the certificate only if the cert/key files changed since the last successful load.
// It returns (true, nil) if a reload happened, (false, nil) if nothing changed.
func (m *Manager) ReloadIfChanged() (bool, error) {
	certInfo, err := os.Stat(m.certFile)
	if err != nil {
		return false, fmt.Errorf("failed to stat certificate file %s: %v", filepath.Clean(m.certFile), err)
	}
	keyInfo, err := os.Stat(m.keyFile)
	if err != nil {
		return false, fmt.Errorf("failed to stat key file %s: %v", filepath.Clean(m.keyFile), err)
	}

	certMTime := certInfo.ModTime().UnixNano()
	keyMTime := keyInfo.ModTime().UnixNano()
	certSize := certInfo.Size()
	keySize := keyInfo.Size()

	m.mu.Lock()
	changed := certMTime != m.lastCertMTimeNS ||
		keyMTime != m.lastKeyMTimeNS ||
		certSize != m.lastCertSize ||
		keySize != m.lastKeySize
	m.mu.Unlock()

	if !changed {
		return false, nil
	}

	if err := m.LoadAndStore(); err != nil {
		return false, err
	}
	return true, nil
}

// GetTLSConfig returns a TLS config that uses the manager's current certificate.
// Certificates are served via GetCertificate so the cert can be hot-reloaded without restarting listeners.
func (m *Manager) GetTLSConfig() (*tls.Config, error) {
	// Ensure we have an initial certificate loaded.
	if m.current.Load() == nil {
		if err := m.LoadAndStore(); err != nil {
			return nil, err
		}
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Called on every handshake; must be concurrency-safe.
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := m.current.Load()
			if c == nil {
				return nil, fmt.Errorf("no TLS certificate loaded")
			}
			return c, nil
		},
	}, nil
}

// StartAutoReload starts a background loop that periodically calls ReloadIfChanged until ctx is cancelled.
// This is intentionally polling-based (not fsnotify) to work reliably with Docker/Kubernetes secret updates.
//
// If onTick is non-nil, it will be called after each attempt.
func (m *Manager) StartAutoReload(ctx context.Context, interval time.Duration, onTick func(reloaded bool, err error)) {
	if interval <= 0 {
		interval = 30 * time.Second
	}

	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reloaded, err := m.ReloadIfChanged() // best-effort; keep serving last good cert
				if onTick != nil {
					onTick(reloaded, err)
				}
			}
		}
	}()
}
