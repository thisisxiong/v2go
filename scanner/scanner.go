package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConfigInfo represents a parsed configuration
type ConfigInfo struct {
	Link    string
	Remark  string
	Latency int
	Host    string
	Port    int
}

// Scanner handles the scanning of configuration files
type Scanner struct {
	timeout       time.Duration
	results       map[string][]ConfigInfo
	mu            sync.RWMutex
	enableLatency bool
}

// NewScanner creates a new scanner instance
func NewScanner(timeout time.Duration) *Scanner {
	return &Scanner{
		timeout:       timeout,
		results:       make(map[string][]ConfigInfo),
		enableLatency: false, // Default to false for speed
	}
}

// SetLatencyMeasurement enables or disables latency measurement
func (s *Scanner) SetLatencyMeasurement(enable bool) {
	s.enableLatency = enable
}

// ScanDirectory scans all sub*.txt files in the given directory
func (s *Scanner) ScanDirectory(dirPath string) error {
	fmt.Printf("🔍 Scanning directory: %s\n", dirPath)

	// Find all sub*.txt and Sub*.txt files
	patterns := []string{
		filepath.Join(dirPath, "sub*.txt"),
		filepath.Join(dirPath, "Sub*.txt"),
	}

	var allMatches []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("error finding files: %v", err)
		}
		allMatches = append(allMatches, matches...)
	}

	if len(allMatches) == 0 {
		return fmt.Errorf("no files found matching sub*.txt or Sub*.txt pattern")
	}

	matches := allMatches

	fmt.Printf("📄 Found %d files to scan\n", len(matches))

	// Process each file
	for _, filePath := range matches {
		fmt.Printf("📁 Scanning file: %s\n", filepath.Base(filePath))
		if err := s.scanFile(filePath); err != nil {
			fmt.Printf("⚠️ Error scanning %s: %v\n", filePath, err)
			continue
		}
	}

	return nil
}

// scanFile processes a single configuration file
func (s *Scanner) scanFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	linkRegex := regexp.MustCompile(`(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Extract links from the line
		matches := linkRegex.FindAllString(line, -1)
		for _, link := range matches {
			s.processLink(link)
		}
	}

	return scanner.Err()
}

// processLink processes a single configuration link
func (s *Scanner) processLink(link string) {
	host, port, remark, protocol := s.decodeLink(link)
	if host == "" || port == 0 {
		return
	}

	latency := 0
	if s.enableLatency {
		// Measure latency only if enabled
		latency = s.measureLatency(host, port)
		if latency == -1 || latency > 800 {
			return // Skip if latency measurement failed or too slow
		}
	}

	config := ConfigInfo{
		Link:    link,
		Remark:  remark,
		Latency: latency,
		Host:    host,
		Port:    port,
	}

	s.mu.Lock()
	s.results[protocol] = append(s.results[protocol], config)
	s.mu.Unlock()
}

// decodeLink decodes a configuration link and returns host, port, remark, and protocol
func (s *Scanner) decodeLink(link string) (host string, port int, remark string, protocol string) {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		return s.decodeVMess(link)
	case strings.HasPrefix(link, "vless://"):
		return s.decodeVLess(link)
	case strings.HasPrefix(link, "trojan://"):
		return s.decodeTrojan(link)
	case strings.HasPrefix(link, "ss://"):
		return s.decodeSS(link)
	default:
		return "", 0, "", ""
	}
}

// decodeVMess decodes a VMess configuration
func (s *Scanner) decodeVMess(link string) (host string, port int, remark string, protocol string) {
	protocol = "vmess"

	// Remove vmess:// prefix
	encoded := strings.TrimPrefix(link, "vmess://")

	// Add padding if necessary
	if len(encoded)%4 != 0 {
		encoded += strings.Repeat("=", 4-len(encoded)%4)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", 0, "", protocol
	}

	var config map[string]interface{}
	if err := json.Unmarshal(decoded, &config); err != nil {
		return "", 0, "", protocol
	}

	host, _ = config["add"].(string)

	// Handle port as both string and number
	if portFloat, ok := config["port"].(float64); ok {
		port = int(portFloat)
	} else if portStr, ok := config["port"].(string); ok {
		port, _ = strconv.Atoi(portStr)
	}

	remark, _ = config["ps"].(string)

	return host, port, remark, protocol
}

// decodeVLess decodes a VLess configuration
func (s *Scanner) decodeVLess(link string) (host string, port int, remark string, protocol string) {
	protocol = "vless"
	return s.decodeGeneric(link, "vless://")
}

// decodeTrojan decodes a Trojan configuration
func (s *Scanner) decodeTrojan(link string) (host string, port int, remark string, protocol string) {
	protocol = "trojan"
	return s.decodeGeneric(link, "trojan://")
}

// decodeSS decodes a Shadowsocks configuration
func (s *Scanner) decodeSS(link string) (host string, port int, remark string, protocol string) {
	protocol = "ss"
	return s.decodeGeneric(link, "ss://")
}

// decodeGeneric decodes generic URL-based configurations
func (s *Scanner) decodeGeneric(link, prefix string) (host string, port int, remark string, protocol string) {
	// Extract protocol from prefix
	protocol = strings.TrimSuffix(prefix, "://")

	parsedURL, err := url.Parse(link)
	if err != nil {
		return "", 0, "", protocol
	}

	host = parsedURL.Hostname()
	portStr := parsedURL.Port()
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}

	remark = parsedURL.Fragment
	if remark == "" {
		remark = "NoRemark"
	}

	return host, port, remark, protocol
}

// measureLatency measures the latency to a host:port
func (s *Scanner) measureLatency(host string, port int) int {
	address := fmt.Sprintf("%s:%d", host, port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return -1
	}
	defer conn.Close()

	latency := int(time.Since(start).Milliseconds())
	return latency
}

// SaveResults saves the scan results to files
func (s *Scanner) SaveResults() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for protocol, configs := range s.results {
		if len(configs) == 0 {
			continue
		}

		// Sort by latency
		sort.Slice(configs, func(i, j int) bool {
			return configs[i].Latency < configs[j].Latency
		})

		// Split into fast and normal (or all if no latency measured)
		var fast, normal []string
		for _, config := range configs {
			line := fmt.Sprintf("%s # %s", config.Link, config.Remark)
			if config.Latency > 0 {
				line = fmt.Sprintf("%s - %d ms", line, config.Latency)
				if config.Latency < 200 {
					fast = append(fast, line)
				} else {
					normal = append(normal, line)
				}
			} else {
				// No latency measured, put in normal category
				normal = append(normal, line)
			}
		}

		// Save fast configs
		if len(fast) > 0 {
			filename := fmt.Sprintf("fast_%s.txt", protocol)
			if err := s.writeFile(filename, fast); err != nil {
				return fmt.Errorf("error writing fast %s file: %v", protocol, err)
			}
			fmt.Printf("✅ Saved %d fast %s configs to %s\n", len(fast), protocol, filename)
		}

		// Save normal configs
		if len(normal) > 0 {
			filename := fmt.Sprintf("%s.txt", protocol)
			if err := s.writeFile(filename, normal); err != nil {
				return fmt.Errorf("error writing %s file: %v", protocol, err)
			}
			fmt.Printf("✅ Saved %d normal %s configs to %s\n", len(normal), protocol, filename)
		}
	}

	return nil
}

// writeFile writes a slice of strings to a file
func (s *Scanner) writeFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// GetResults returns the current scan results
func (s *Scanner) GetResults() map[string][]ConfigInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[string][]ConfigInfo)
	for protocol, configs := range s.results {
		result[protocol] = make([]ConfigInfo, len(configs))
		copy(result[protocol], configs)
	}

	return result
}

// PrintSummary prints a summary of the scan results
func (s *Scanner) PrintSummary() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fmt.Println("\n📊 Scan Summary:")
	total := 0
	for protocol, configs := range s.results {
		count := len(configs)
		total += count
		fmt.Printf("  %s: %d configs\n", protocol, count)
	}
	fmt.Printf("  Total: %d configs\n", total)
}
