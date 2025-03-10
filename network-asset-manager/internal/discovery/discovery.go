package discovery

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Scanner represents a network scanner that can discover hosts
type Scanner struct {
	Timeout  time.Duration
	Retries  int
	Parallel int
}

// ScanResult represents the result of a host discovery scan
type ScanResult struct {
	IP        string
	Hostname  string
	MAC       string
	IsUp      bool
	Method    string
	OpenPorts []int
	Timestamp time.Time
}

// NewScanner creates a new Scanner with default settings
func NewScanner() *Scanner {
	return &Scanner{
		Timeout:  2 * time.Second,
		Retries:  2,
		Parallel: 100,
	}
}

// DiscoverHosts performs host discovery on the given network range
func (s *Scanner) DiscoverHosts(cidr string) ([]ScanResult, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %v", err)
	}

	var hosts []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		// Skip network and broadcast addresses for IPv4
		if ip.To4() != nil && (isNetworkAddress(ip, ipnet) || isBroadcastAddress(ip, ipnet)) {
			continue
		}
		hosts = append(hosts, copyIP(ip))
	}

	results := make([]ScanResult, 0, len(hosts))
	resultChan := make(chan ScanResult, len(hosts))
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent scans
	semaphore := make(chan struct{}, s.Parallel)

	for _, host := range hosts {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			result := s.scanHost(ip.String())
			if result.IsUp {
				resultChan <- result
			}
		}(host)
	}

	// Close result channel when all goroutines are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results, nil
}

// scanHost scans a single host using all available methods
func (s *Scanner) scanHost(host string) ScanResult {
	result := ScanResult{
		IP:        host,
		IsUp:      false,
		Timestamp: time.Now(),
	}

	// Try ARP first for local networks
	if isLocalNetwork(host) {
		if isUp, mac := s.ARPPing(host); isUp {
			result.IsUp = true
			result.MAC = mac
			result.Method = "ARP"
			return result
		}
	}

	// Try ICMP Echo (Ping)
	if isUp := s.ICMPEcho(host); isUp {
		result.IsUp = true
		result.Method = "ICMP Echo"
		return result
	}

	// Try TCP SYN Ping on common ports
	commonPorts := []int{80, 443, 22, 25, 3389}
	for _, port := range commonPorts {
		if isUp := s.TCPSYNPing(host, port); isUp {
			result.IsUp = true
			result.Method = fmt.Sprintf("TCP SYN on port %d", port)
			result.OpenPorts = append(result.OpenPorts, port)
			return result
		}
	}

	// Try TCP ACK Ping
	if isUp := s.TCPACKPing(host, 80); isUp {
		result.IsUp = true
		result.Method = "TCP ACK"
		return result
	}

	// Try UDP Ping
	if isUp := s.UDPPing(host, 53); isUp {
		result.IsUp = true
		result.Method = "UDP"
		return result
	}

	// Try ICMP Timestamp Request
	if isUp := s.ICMPTimestamp(host); isUp {
		result.IsUp = true
		result.Method = "ICMP Timestamp"
		return result
	}

	// Try ICMP Address Mask Request
	if isUp := s.ICMPAddressMask(host); isUp {
		result.IsUp = true
		result.Method = "ICMP Address Mask"
		return result
	}

	return result
}

// Helper functions
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func isNetworkAddress(ip net.IP, ipnet *net.IPNet) bool {
	return ip.Equal(ip.Mask(ipnet.Mask))
}

func isBroadcastAddress(ip net.IP, ipnet *net.IPNet) bool {
	// Get the last IP in the range (broadcast)
	mask := ipnet.Mask
	broadcast := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return ip.Equal(broadcast)
}

func isLocalNetwork(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check if it's in a private network range
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}
