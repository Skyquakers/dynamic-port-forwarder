package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the application configuration
type Config struct {
	// List of target node IPs
	NodeIPs []string
	// Port range
	MinPort int
	MaxPort int
	// Certificate and key file paths
	CertFile string
	KeyFile  string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	nodeIPs := getEnv("NODE_IPS", "127.0.0.1")
	minPortStr := getEnv("MIN_PORT", "8000")
	maxPortStr := getEnv("MAX_PORT", "9000")
	certFile := getEnv("CERT_FILE", "")
	keyFile := getEnv("KEY_FILE", "")

	minPort, err := strconv.Atoi(minPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MIN_PORT: %v", err)
	}

	maxPort, err := strconv.Atoi(maxPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_PORT: %v", err)
	}

	if minPort >= maxPort {
		return nil, fmt.Errorf("MIN_PORT must be less than MAX_PORT")
	}

	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("CERT_FILE and KEY_FILE must be provided")
	}

	return &Config{
		NodeIPs:  parseNodeIPs(nodeIPs),
		MinPort:  minPort,
		MaxPort:  maxPort,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, nil
}

// parseNodeIPs splits the comma-separated list of IPs
func parseNodeIPs(nodeIPsStr string) []string {
	ips := strings.Split(nodeIPsStr, ",")
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		trimmed := strings.TrimSpace(ip)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
