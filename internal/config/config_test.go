package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
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

	// Test valid configuration
	t.Run("Valid Config", func(t *testing.T) {
		// Set test environment
		os.Setenv("NODE_IPS", "192.168.1.1,192.168.1.2")
		os.Setenv("MIN_PORT", "8000")
		os.Setenv("MAX_PORT", "9000")
		os.Setenv("CERT_FILE", "/tmp/cert.pem")
		os.Setenv("KEY_FILE", "/tmp/key.pem")

		// Create dummy cert files
		tmpCert, err := os.Create("/tmp/cert.pem")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove("/tmp/cert.pem")
		defer tmpCert.Close()

		tmpKey, err := os.Create("/tmp/key.pem")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove("/tmp/key.pem")
		defer tmpKey.Close()

		// Test
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// Verify values
		if len(cfg.NodeIPs) != 2 {
			t.Errorf("Expected 2 node IPs, got: %d", len(cfg.NodeIPs))
		}
		if cfg.NodeIPs[0] != "192.168.1.1" {
			t.Errorf("Expected first node IP 192.168.1.1, got: %s", cfg.NodeIPs[0])
		}
		if cfg.MinPort != 8000 {
			t.Errorf("Expected min port 8000, got: %d", cfg.MinPort)
		}
		if cfg.MaxPort != 9000 {
			t.Errorf("Expected max port 9000, got: %d", cfg.MaxPort)
		}
		if cfg.CertFile != "/tmp/cert.pem" {
			t.Errorf("Expected cert file /tmp/cert.pem, got: %s", cfg.CertFile)
		}
		if cfg.KeyFile != "/tmp/key.pem" {
			t.Errorf("Expected key file /tmp/key.pem, got: %s", cfg.KeyFile)
		}
	})

	// Test invalid min/max port
	t.Run("Invalid Port Range", func(t *testing.T) {
		os.Setenv("MIN_PORT", "9000")
		os.Setenv("MAX_PORT", "8000")
		os.Setenv("CERT_FILE", "/tmp/cert.pem")
		os.Setenv("KEY_FILE", "/tmp/key.pem")

		_, err := LoadConfig()
		if err == nil {
			t.Fatal("Expected error for invalid port range, got none")
		}
	})

	// Test invalid port format
	t.Run("Invalid Port Format", func(t *testing.T) {
		os.Setenv("MIN_PORT", "not-a-number")
		os.Setenv("MAX_PORT", "9000")
		os.Setenv("CERT_FILE", "/tmp/cert.pem")
		os.Setenv("KEY_FILE", "/tmp/key.pem")

		_, err := LoadConfig()
		if err == nil {
			t.Fatal("Expected error for invalid port format, got none")
		}
	})

	// Test missing cert/key files
	t.Run("Missing Cert/Key Files", func(t *testing.T) {
		os.Setenv("MIN_PORT", "8000")
		os.Setenv("MAX_PORT", "9000")
		os.Setenv("CERT_FILE", "")
		os.Setenv("KEY_FILE", "")

		_, err := LoadConfig()
		if err == nil {
			t.Fatal("Expected error for missing cert/key files, got none")
		}
	})
}

func TestParseNodeIPs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single IP",
			input:    "192.168.1.1",
			expected: []string{"192.168.1.1"},
		},
		{
			name:     "Multiple IPs",
			input:    "192.168.1.1,192.168.1.2,192.168.1.3",
			expected: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name:     "IPs with Spaces",
			input:    " 192.168.1.1 , 192.168.1.2 ",
			expected: []string{"192.168.1.1", "192.168.1.2"},
		},
		{
			name:     "Empty String",
			input:    "",
			expected: []string{},
		},
		{
			name:     "Only Spaces",
			input:    " , ",
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := parseNodeIPs(test.input)

			if len(result) != len(test.expected) {
				t.Fatalf("Expected %d IPs, got %d", len(test.expected), len(result))
			}

			for i, ip := range result {
				if ip != test.expected[i] {
					t.Errorf("Expected IP %s at index %d, got %s", test.expected[i], i, ip)
				}
			}
		})
	}
}
