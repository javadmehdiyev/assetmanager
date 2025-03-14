package ui

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"network-asset-manager/internal/discovery"
	"network-asset-manager/internal/osfp"
	"network-asset-manager/internal/portscan"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "network-asset-manager",
		Short: "A tool for discovering and managing network assets",
		Long: `Network Asset Manager is a comprehensive tool for discovering hosts on a network
using various techniques including ICMP, TCP, UDP, and ARP.`,
	}

	scanCmd = &cobra.Command{
		Use:   "scan [cidr]",
		Short: "Scan a network range and discover open ports",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}

	cidrFlag           string
	timeoutFlag        int
	parallelFlag       int
	portRangeFlag      string
	scanTypeFlag       string
	enablePortScanFlag bool
	enableOSScanFlag   bool
	jsonOutputFlag     bool
)

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().IntVarP(&timeoutFlag, "timeout", "t", 2, "Timeout in seconds for each probe")
	scanCmd.Flags().IntVarP(&parallelFlag, "parallel", "p", 100, "Number of parallel scans")

	// Port scanning related flags
	scanCmd.Flags().BoolVarP(&enablePortScanFlag, "ports", "P", false, "Enable port scanning on discovered hosts")
	scanCmd.Flags().StringVarP(&portRangeFlag, "port-range", "r", "1-1024", "Port range to scan (e.g., 80,443,8080 or 1-1024)")
	scanCmd.Flags().StringVarP(&scanTypeFlag, "scan-type", "s", "connect", "Port scan type (connect, syn, fin, null, xmas, ack, udp)")

	// OS scanning flag
	scanCmd.Flags().BoolVarP(&enableOSScanFlag, "os-detection", "O", false, "Enable OS detection on discovered hosts")

	// Output format flag
	scanCmd.Flags().BoolVarP(&jsonOutputFlag, "json", "j", false, "Output results in JSON format")
}

// Combined results structure for JSON output
type ScanOutput struct {
	HostDiscovery []HostResult                 `json:"hosts"`
	PortScans     map[string][]PortResult      `json:"port_scans,omitempty"`
	OSDetection   map[string]OSDetectionResult `json:"os_detection,omitempty"`
	ScanTime      time.Time                    `json:"scan_time"`
}

type HostResult struct {
	IP              string `json:"ip"`
	MAC             string `json:"mac,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	IsUp            bool   `json:"is_up"`
	DiscoveryMethod string `json:"discovery_method,omitempty"`
}

type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Status   string `json:"status"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

type OSDetectionResult struct {
	Name        string   `json:"name"`
	Family      string   `json:"family"`
	Probability float64  `json:"probability"`
	Methods     []string `json:"methods,omitempty"`
}

func runScan(cmd *cobra.Command, args []string) error {
	cidr := args[0]

	// Create a new scanner
	scanner := discovery.NewScanner()
	scanner.Timeout = time.Duration(timeoutFlag) * time.Second
	scanner.Parallel = parallelFlag

	// Prepare output data structure for JSON
	output := ScanOutput{
		ScanTime:    time.Now(),
		PortScans:   make(map[string][]PortResult),
		OSDetection: make(map[string]OSDetectionResult),
	}

	if !jsonOutputFlag {
		fmt.Printf("Scanning network %s...\n", cidr)
	}

	// Perform the network scan
	results, err := scanner.DiscoverHosts(cidr)
	if err != nil {
		return err
	}

	// Prepare host results for output
	for _, result := range results {
		output.HostDiscovery = append(output.HostDiscovery, HostResult{
			IP:              result.IP,
			MAC:             result.MAC,
			Hostname:        result.Hostname,
			IsUp:            result.IsUp,
			DiscoveryMethod: result.Method,
		})
	}

	// Display host discovery results in desired format
	if !jsonOutputFlag {
		// Display host discovery results in human-readable format
		fmt.Printf("\nDiscovered %d hosts:\n\n", len(results))
		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("%-20s | %-20s | %-30s | %-10s\n", "IP", "MAC", "Hostname", "Method")
		fmt.Println(strings.Repeat("-", 80))
		for _, host := range results {
			if host.IsUp {
				fmt.Printf("%-20s | %-20s | %-30s | %-10s\n",
					host.IP, host.MAC, host.Hostname, host.Method)
			}
		}
		fmt.Println(strings.Repeat("-", 80))
	}

	// If port scanning is enabled, scan ports on discovered hosts
	if enablePortScanFlag && len(results) > 0 {
		if !jsonOutputFlag {
			fmt.Println("\nPerforming port scans on discovered hosts...")
		}

		// Parse port range
		portRange, err := parsePortRange(portRangeFlag)
		if err != nil {
			return err
		}

		// Determine scan type
		var scanType portscan.ScanType
		switch strings.ToLower(scanTypeFlag) {
		case "syn":
			scanType = portscan.ScanSYN
		case "fin":
			scanType = portscan.ScanFIN
		case "null":
			scanType = portscan.ScanNULL
		case "xmas":
			scanType = portscan.ScanXMAS
		case "ack":
			scanType = portscan.ScanACK
		case "udp":
			scanType = portscan.ScanUDP
		default:
			scanType = portscan.ScanConnect
		}

		// Scan each host
		for _, host := range results {
			if !host.IsUp {
				continue
			}

			if !jsonOutputFlag {
				fmt.Printf("\nScanning %s (%s) ports %s with %s scan...\n",
					host.IP, host.Hostname, portRangeFlag, scanTypeFlag)
			}

			// Create port scanner
			portScanner := portscan.NewScanner(host.IP, portRange, scanType)
			portScanner.Timeout = time.Duration(timeoutFlag) * time.Second
			portScanner.Parallel = parallelFlag

			// Perform the port scan
			portResults, err := portScanner.Scan()
			if err != nil {
				if !jsonOutputFlag {
					fmt.Printf("Error scanning %s: %s\n", host.IP, err)
				}
				continue
			}

			// Convert port scan results for output
			var hostPortResults []PortResult
			for _, result := range portResults {
				hostPortResults = append(hostPortResults, PortResult{
					Port:     result.Port,
					Protocol: result.Protocol,
					Status:   result.Status,
					Service:  result.Service,
					Banner:   result.Banner,
				})
			}
			output.PortScans[host.IP] = hostPortResults

			// Display port scan results in human-readable format if not JSON
			if !jsonOutputFlag {
				if len(portResults) > 0 {
					fmt.Printf("Found %d open ports on %s:\n", len(portResults), host.IP)
					fmt.Println(strings.Repeat("-", 100))
					fmt.Printf("%-10s | %-15s | %-15s | %-50s\n", "Port", "Service", "Status", "Banner")
					fmt.Println(strings.Repeat("-", 100))

					for _, portResult := range portResults {
						// Truncate banner if too long
						banner := portResult.Banner
						if len(banner) > 50 {
							banner = banner[:47] + "..."
						}

						fmt.Printf("%-10d | %-15s | %-15s | %-50s\n",
							portResult.Port,
							portResult.Service,
							portResult.Status,
							banner)
					}
					fmt.Println(strings.Repeat("-", 100))
				} else {
					fmt.Printf("No open ports found on %s\n", host.IP)
				}
			}
		}
	}

	// If OS detection is enabled, fingerprint OS on discovered hosts
	if enableOSScanFlag && len(results) > 0 {
		if !jsonOutputFlag {
			fmt.Println("\nPerforming OS detection on discovered hosts...")
		}

		// Scan each host
		for _, host := range results {
			if !host.IsUp {
				continue
			}

			if !jsonOutputFlag {
				fmt.Printf("\nDetecting OS for %s (%s)...\n", host.IP, host.Hostname)
			}

			// Create OS fingerprinter
			fingerprinter := osfp.NewOSFingerprinter(host.IP)
			fingerprinter.Timeout = time.Duration(timeoutFlag) * time.Second

			// Perform OS detection
			osInfo, err := fingerprinter.FingerprintOS()
			if err != nil {
				if !jsonOutputFlag {
					fmt.Printf("Error detecting OS on %s: %s\n", host.IP, err)
				}
				continue
			}

			// Save results
			output.OSDetection[host.IP] = OSDetectionResult{
				Name:        osInfo.Name,
				Family:      osInfo.Family,
				Probability: osInfo.Probability,
				Methods:     osInfo.Methods,
			}

			// Display OS detection results in human-readable format if not JSON
			if !jsonOutputFlag {
				if osInfo.Name != osfp.OSUnknown {
					fmt.Printf("\nOS Detection Results for %s:\n", host.IP)
					fmt.Println(strings.Repeat("-", 80))
					fmt.Printf("%-25s | %-15s | %-12s | %-30s\n", "OS Name", "OS Family", "Probability", "Detection Methods")
					fmt.Println(strings.Repeat("-", 80))
					fmt.Printf("%-25s | %-15s | %-12.1f%% | %s\n",
						osInfo.Name,
						osInfo.Family,
						osInfo.Probability*100,
						strings.Join(osInfo.Methods, ", "))
					fmt.Println(strings.Repeat("-", 80))
				} else {
					fmt.Printf("Could not detect OS on %s\n", host.IP)
				}
			}
		}
	}

	// Output JSON data if requested
	if jsonOutputFlag {
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("JSON marshaling error: %v", err)
		}
		fmt.Println(string(jsonData))
	}

	return nil
}

// Helper function to parse port range string
func parsePortRange(portRangeStr string) ([]int, error) {
	var ports []int

	// Split by comma
	rangeParts := strings.Split(portRangeStr, ",")

	for _, part := range rangeParts {
		// Check if it's a range (contains "-")
		if strings.Contains(part, "-") {
			rangeLimits := strings.Split(part, "-")
			if len(rangeLimits) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeLimits[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeLimits[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeLimits[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeLimits[1])
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			// It's a single port
			port, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// Execute is the entry point for the CLI
func Execute() error {
	return rootCmd.Execute()
}
