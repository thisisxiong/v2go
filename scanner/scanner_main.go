package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	// Command line flags
	var (
		dir           = flag.String("dir", ".", "Directory to scan for sub*.txt files")
		timeout       = flag.Duration("timeout", 3*time.Second, "Timeout for latency measurements")
		measureLatency = flag.Bool("latency", false, "Enable latency measurement (slower but more accurate)")
		help          = flag.Bool("help", false, "Show help message")
	)

	flag.Parse()

	if *help {
		fmt.Println("VPN Config Scanner")
		fmt.Println("Usage: go run scanner_main.go [options]")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		return
	}

	fmt.Println("🛰 VPN Config Scanner")
	fmt.Println("===================")

	// Create scanner instance
	scanner := NewScanner(*timeout)
	
	// Set latency measurement flag
	scanner.SetLatencyMeasurement(*measureLatency)

	// Check if directory exists
	if _, err := os.Stat(*dir); os.IsNotExist(err) {
		fmt.Printf("❌ Directory does not exist: %s\n", *dir)
		os.Exit(1)
	}

	// Start scanning
	fmt.Printf("📂 Scanning directory: %s\n", *dir)
	fmt.Printf("⏱️ Timeout: %v\n", *timeout)
	fmt.Println()

	start := time.Now()
	err := scanner.ScanDirectory(*dir)
	scanDuration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Scan failed: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	scanner.PrintSummary()
	fmt.Printf("⏱️ Scan completed in: %v\n", scanDuration)

	// Save results
	fmt.Println("\n💾 Saving results...")
	err = scanner.SaveResults()
	if err != nil {
		fmt.Printf("❌ Failed to save results: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Results saved successfully!")
}
