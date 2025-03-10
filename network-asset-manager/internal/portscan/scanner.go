package portscan

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ScanType represents the type of port scan to perform
type ScanType string

const (
	ScanSYN        ScanType = "SYN"
	ScanConnect    ScanType = "Connect"
	ScanACK        ScanType = "ACK"
	ScanFIN        ScanType = "FIN"
	ScanXMAS       ScanType = "XMAS"
	ScanNULL       ScanType = "NULL"
	ScanUDP        ScanType = "UDP"
	ScanIPProtocol ScanType = "IPProtocol"
)

// Scanner represents a port scanner
type Scanner struct {
	Target    string
	PortRange []int
	ScanType  ScanType
	Timeout   time.Duration
	Parallel  int
}

// ScanResult represents the result of a port scan
type ScanResult struct {
	Port     int
	Protocol string
	Status   string
	Service  string
	Banner   string
}

// NewScanner creates a new port scanner
func NewScanner(target string, portRange []int, scanType ScanType) *Scanner {
	return &Scanner{
		Target:    target,
		PortRange: portRange,
		ScanType:  scanType,
		Timeout:   2 * time.Second,
		Parallel:  100,
	}
}

// Scan performs a port scan
func (s *Scanner) Scan() ([]ScanResult, error) {
	var results []ScanResult
	var wg sync.WaitGroup
	resultChan := make(chan ScanResult, len(s.PortRange))

	// Use a semaphore to limit concurrent scans
	semaphore := make(chan struct{}, s.Parallel)

	for _, port := range s.PortRange {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			result := ScanResult{Port: port, Protocol: "tcp"}

			isOpen, err := s.scanPort(port)
			if err != nil {
				return
			}

			if isOpen {
				result.Status = "open"
				// Get banner if port is open
				banner, service := s.getBanner(port)
				result.Banner = banner
				result.Service = service
				resultChan <- result
			}
		}(port)
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

// scanPort scans a single port using the specified scan type
func (s *Scanner) scanPort(port int) (bool, error) {
	switch s.ScanType {
	case ScanConnect:
		return s.connectScan(port)
	case ScanSYN:
		return s.synScan(port)
	case ScanACK:
		return s.ackScan(port)
	case ScanFIN:
		return s.finScan(port)
	case ScanXMAS:
		return s.xmasScan(port)
	case ScanNULL:
		return s.nullScan(port)
	case ScanUDP:
		return s.udpScan(port)
	default:
		return s.connectScan(port) // Default to connect scan
	}
}

// connectScan performs a full TCP connect scan
func (s *Scanner) connectScan(port int) (bool, error) {
	address := fmt.Sprintf("%s:%d", s.Target, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false, nil
	}
	conn.Close()
	return true, nil
}

// synScan performs a TCP SYN scan (half-open scan)
func (s *Scanner) synScan(port int) (bool, error) {
	// First try the high-level approach as fallback
	isOpen, err := s.connectScan(port)
	if err == nil && isOpen {
		return true, nil
	}

	// Create a raw socket for SYN scanning
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false, fmt.Errorf("raw socket creation failed: %v", err)
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(s.Target)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", s.Target)
	}

	// Get outbound interface IP
	localIP := getOutboundIP()

	// Create packet layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	// Create TCP layer with SYN flag set
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(getEphemeralPort()),
		DstPort: layers.TCPPort(port),
		SYN:     true, // Set SYN flag
		Window:  14600,
		Seq:     1000,
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return false, fmt.Errorf("packet serialization failed: %v", err)
	}

	// Send packet
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		return false, fmt.Errorf("packet send failed: %v", err)
	}

	// Set read timeout
	tv := syscall.Timeval{
		Sec:  int64(s.Timeout / time.Second),
		Usec: int32((s.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Read response
	recvBuf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, recvBuf, 0)
	if err != nil {
		return false, nil // Timeout or error means closed port
	}

	// Parse response
	packet := gopacket.NewPacket(recvBuf[:n], layers.LayerTypeIPv4, gopacket.Default)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// Check for SYN-ACK flags
		return tcp.SYN && tcp.ACK, nil
	}

	return false, nil
}

// ackScan performs a TCP ACK scan to detect filtered ports
func (s *Scanner) ackScan(port int) (bool, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false, fmt.Errorf("raw socket creation failed: %v", err)
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(s.Target)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", s.Target)
	}

	// Get outbound interface IP
	localIP := getOutboundIP()

	// Create packet layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	// Create TCP layer with ACK flag set
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(getEphemeralPort()),
		DstPort: layers.TCPPort(port),
		ACK:     true, // Set ACK flag
		Window:  14600,
		Seq:     1000,
		Ack:     1000, // Some arbitrary ACK number
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return false, fmt.Errorf("packet serialization failed: %v", err)
	}

	// Send packet
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		return false, fmt.Errorf("packet send failed: %v", err)
	}

	// Set read timeout
	tv := syscall.Timeval{
		Sec:  int64(s.Timeout / time.Second),
		Usec: int32((s.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Read response
	recvBuf := make([]byte, 4096)
	_, _, err = syscall.Recvfrom(fd, recvBuf, 0)

	// If we get an RST back, the port is unfiltered (but not necessarily open)
	// In ACK scan, we're checking if port is filtered by a firewall
	// If we get a response, port is unfiltered
	// No response or ICMP unreachable means it's filtered

	// Here we return "open" if the port is unfiltered
	// In reality ACK scan can't really distinguish between open and closed, just filtered vs unfiltered
	return err == nil, nil
}

// finScan performs a TCP FIN scan (stealthy)
func (s *Scanner) finScan(port int) (bool, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false, fmt.Errorf("raw socket creation failed: %v", err)
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(s.Target)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", s.Target)
	}

	// Get outbound interface IP
	localIP := getOutboundIP()

	// Create packet layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	// Create TCP layer with FIN flag set
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(getEphemeralPort()),
		DstPort: layers.TCPPort(port),
		FIN:     true, // Set FIN flag
		Window:  14600,
		Seq:     1000,
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return false, fmt.Errorf("packet serialization failed: %v", err)
	}

	// Send packet
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		return false, fmt.Errorf("packet send failed: %v", err)
	}

	// Set read timeout
	tv := syscall.Timeval{
		Sec:  int64(s.Timeout / time.Second),
		Usec: int32((s.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Read response
	recvBuf := make([]byte, 4096)
	_, _, err = syscall.Recvfrom(fd, recvBuf, 0)

	// Per RFC, closed ports should respond with RST
	// Open or filtered ports should not respond
	// So if we get no response (timeout), the port might be open
	return err != nil, nil
}

// xmasScan performs a TCP XMAS scan (with FIN, PSH, URG flags set)
func (s *Scanner) xmasScan(port int) (bool, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false, fmt.Errorf("raw socket creation failed: %v", err)
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(s.Target)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", s.Target)
	}

	// Get outbound interface IP
	localIP := getOutboundIP()

	// Create packet layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	// Create TCP layer with FIN, PSH, URG flags set (XMAS scan)
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(getEphemeralPort()),
		DstPort: layers.TCPPort(port),
		FIN:     true, // Set FIN flag
		PSH:     true, // Set PSH flag
		URG:     true, // Set URG flag
		Window:  14600,
		Seq:     1000,
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return false, fmt.Errorf("packet serialization failed: %v", err)
	}

	// Send packet
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		return false, fmt.Errorf("packet send failed: %v", err)
	}

	// Set read timeout
	tv := syscall.Timeval{
		Sec:  int64(s.Timeout / time.Second),
		Usec: int32((s.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Read response
	recvBuf := make([]byte, 4096)
	_, _, err = syscall.Recvfrom(fd, recvBuf, 0)

	// Similar to FIN scan, no response suggests the port may be open
	return err != nil, nil
}

// nullScan performs a TCP NULL scan (no flags set)
func (s *Scanner) nullScan(port int) (bool, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false, fmt.Errorf("raw socket creation failed: %v", err)
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(s.Target)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", s.Target)
	}

	// Get outbound interface IP
	localIP := getOutboundIP()

	// Create packet layers
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Create IP layer
	ipLayer := &layers.IPv4{
		SrcIP:    localIP,
		DstIP:    ip,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}

	// Create TCP layer with no flags set (NULL scan)
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(getEphemeralPort()),
		DstPort: layers.TCPPort(port),
		Window:  14600,
		Seq:     1000,
		// No flags set
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return false, fmt.Errorf("packet serialization failed: %v", err)
	}

	// Send packet
	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		return false, fmt.Errorf("packet send failed: %v", err)
	}

	// Set read timeout
	tv := syscall.Timeval{
		Sec:  int64(s.Timeout / time.Second),
		Usec: int32((s.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Read response
	recvBuf := make([]byte, 4096)
	_, _, err = syscall.Recvfrom(fd, recvBuf, 0)

	// Similar to FIN and XMAS scans, no response suggests the port may be open
	return err != nil, nil
}

// udpScan performs a UDP scan
func (s *Scanner) udpScan(port int) (bool, error) {
	// For UDP, we'll use a simpler approach - try to establish a connection
	// and send a small packet, then see if we get ICMP Unreachable back

	address := fmt.Sprintf("%s:%d", s.Target, port)
	conn, err := net.DialTimeout("udp", address, s.Timeout)
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	// Write a simple payload
	// For well-known UDP services, we could craft specific payloads
	_, err = conn.Write([]byte("HELLO\r\n"))
	if err != nil {
		return false, nil
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// Try to read response
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)

	// If we get a response, the port is definitely open
	if err == nil && n > 0 {
		return true, nil
	}

	// For UDP, lack of response doesn't necessarily mean the port is closed
	// But we'll consider it "potentially open"
	// This is a simplification - proper UDP scanning is more complex
	return true, nil
}

// Helper function to get outbound IP address
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// getEphemeralPort returns a random ephemeral port number
func getEphemeralPort() int {
	// Simple random port in ephemeral range
	// In production, you'd want to check if the port is already in use
	return 32768 + (time.Now().Nanosecond() % 28232)
}
