package osfp

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// OSFingerprinter represents an OS fingerprinting engine
type OSFingerprinter struct {
	Target  string
	Timeout time.Duration
}

// OSInfo represents the information about an operating system
type OSInfo struct {
	Name        string   `json:"name"`
	Family      string   `json:"family"`
	Probability float64  `json:"probability"`
	Methods     []string `json:"methods"`
}

// Common OS families
const (
	OSWindows = "Windows"
	OSLinux   = "Linux"
	OSMacOS   = "macOS"
	OSFreeBSD = "FreeBSD"
	OSSolaris = "Solaris"
	OSAndroid = "Android"
	OSiOS     = "iOS"
	OSUnknown = "Unknown"
)

// TTL signatures for various operating systems
var ttlSignatures = map[int][]string{
	64:  {OSLinux, OSAndroid, "FreeBSD", "MacOS"},
	128: {OSWindows},
	255: {OSSolaris, "AIX", "Cisco", "Network Equipment"},
}

// TCP Window signatures
var windowSignatures = map[int][]string{
	5840:  {OSLinux},
	8192:  {OSWindows + " XP/2003"},
	16384: {OSWindows + " 7/8/10"},
	65535: {OSWindows + " Vista/Server 2008"},
}

// NewOSFingerprinter creates a new OS fingerprinter
func NewOSFingerprinter(target string) *OSFingerprinter {
	return &OSFingerprinter{
		Target:  target,
		Timeout: 2 * time.Second,
	}
}

// FingerprintOS attempts to identify the OS of the target
func (f *OSFingerprinter) FingerprintOS() (*OSInfo, error) {
	osInfo := &OSInfo{
		Name:        OSUnknown,
		Family:      OSUnknown,
		Probability: 0.0,
		Methods:     []string{},
	}

	// Run different fingerprinting techniques and aggregate results
	methods := []func() (*OSInfo, error){
		f.fingerprintTTL,
		f.fingerprintTCPWindow,
		f.fingerprintTCPOptions,
		f.fingerprintICMP,
		f.fingerprintHTTPHeaders,
		f.fingerprintSSHBanner,
	}

	var osResults []*OSInfo
	for _, method := range methods {
		result, err := method()
		if err == nil && result != nil && result.Name != OSUnknown {
			osResults = append(osResults, result)
		}
	}

	// No methods were successful
	if len(osResults) == 0 {
		return osInfo, nil
	}

	// Count OS occurrences to determine the most likely
	osCounter := make(map[string]int)
	osMethodMap := make(map[string][]string)

	for _, result := range osResults {
		osCounter[result.Family]++
		osMethodMap[result.Family] = append(osMethodMap[result.Family], result.Methods...)
	}

	// Find the most frequent OS
	var maxCount int
	var mostLikelyOS string

	for os, count := range osCounter {
		if count > maxCount {
			maxCount = count
			mostLikelyOS = os
		}
	}

	// Calculate probability
	probability := float64(maxCount) / float64(len(osResults))

	// Find the most specific name from the results
	var bestName string
	for _, result := range osResults {
		if result.Family == mostLikelyOS && len(result.Name) > len(bestName) {
			bestName = result.Name
		}
	}

	if bestName == "" {
		bestName = mostLikelyOS
	}

	osInfo.Name = bestName
	osInfo.Family = mostLikelyOS
	osInfo.Probability = probability
	osInfo.Methods = osMethodMap[mostLikelyOS]

	return osInfo, nil
}

// fingerprintTTL attempts to identify the OS by TTL value
func (f *OSFingerprinter) fingerprintTTL() (*OSInfo, error) {
	// Create a TCP connection to get TTL
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", f.Target), f.Timeout)
	if err != nil {
		// Try ICMP if TCP fails
		return f.fingerprintICMPTTL()
	}
	defer conn.Close()

	// Get TCP connection info
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get TTL from socket options
	fd := int(file.Fd())
	ttl, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL)
	if err != nil {
		return nil, err
	}

	// Normalize TTL (TTLs are typically 32, 64, 128, or 255)
	normalizedTTL := 0
	if ttl <= 32 {
		normalizedTTL = 32
	} else if ttl <= 64 {
		normalizedTTL = 64
	} else if ttl <= 128 {
		normalizedTTL = 128
	} else {
		normalizedTTL = 255
	}

	// Match TTL to OS
	osList, found := ttlSignatures[normalizedTTL]
	if !found {
		return nil, fmt.Errorf("unknown TTL: %d", ttl)
	}

	return &OSInfo{
		Name:        strings.Join(osList, "/"),
		Family:      osList[0],
		Probability: 0.7,
		Methods:     []string{"TTL Analysis"},
	}, nil
}

// fingerprintICMPTTL attempts to identify the OS by ICMP TTL
func (f *OSFingerprinter) fingerprintICMPTTL() (*OSInfo, error) {
	// Implement ICMP echo request and analyze TTL of response
	// This is a fallback when TCP connection fails

	// This is a simplified implementation
	return nil, fmt.Errorf("ICMP TTL analysis not implemented")
}

// fingerprintTCPWindow attempts to identify the OS by TCP window size
func (f *OSFingerprinter) fingerprintTCPWindow() (*OSInfo, error) {
	// Create a raw socket to send a SYN packet and look at the window size in the response
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(f.Target)
	if ip == nil {
		ips, err := net.LookupIP(f.Target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("could not resolve IP: %s", f.Target)
		}
		ip = ips[0]
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

	// Create TCP layer with SYN flag
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(getEphemeralPort()),
		DstPort: layers.TCPPort(80), // Use HTTP port
		SYN:     true,               // Set SYN flag
		Window:  14600,
		Seq:     1000,
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buf, opts, ipLayer, tcpLayer)
	if err != nil {
		return nil, fmt.Errorf("packet serialization failed: %v", err)
	}

	// Send packet
	addr := syscall.SockaddrInet4{Port: 80}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		return nil, fmt.Errorf("packet send failed: %v", err)
	}

	// Set read timeout
	tv := syscall.Timeval{
		Sec:  int64(f.Timeout / time.Second),
		Usec: int32((f.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Read response
	recvBuf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, recvBuf, 0)
	if err != nil {
		return nil, err
	}

	// Parse response to get window size
	packet := gopacket.NewPacket(recvBuf[:n], layers.LayerTypeIPv4, gopacket.Default)

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		// If we got a SYN-ACK, check window size
		if tcp.SYN && tcp.ACK {
			windowSize := int(tcp.Window)

			// Match window size to OS
			osList, found := windowSignatures[windowSize]
			if !found {
				// If not an exact match, find closest
				closest := 0
				for size := range windowSignatures {
					if closest == 0 || (abs(size-windowSize) < abs(closest-windowSize)) {
						closest = size
					}
				}

				if closest != 0 {
					osList = windowSignatures[closest]
				} else {
					return nil, fmt.Errorf("unknown window size: %d", windowSize)
				}
			}

			return &OSInfo{
				Name:        strings.Join(osList, "/"),
				Family:      extractFamily(osList[0]),
				Probability: 0.8,
				Methods:     []string{"TCP Window Size Analysis"},
			}, nil
		}
	}

	return nil, fmt.Errorf("no SYN-ACK response received")
}

// fingerprintTCPOptions attempts to identify the OS by TCP options
func (f *OSFingerprinter) fingerprintTCPOptions() (*OSInfo, error) {
	// This is a more complex fingerprinting method that requires analyzing
	// TCP options pattern, order, and values

	// Simplified implementation
	return nil, fmt.Errorf("TCP options analysis not implemented")
}

// fingerprintICMP attempts to identify the OS by ICMP behavior
func (f *OSFingerprinter) fingerprintICMP() (*OSInfo, error) {
	// This involves sending ICMP packets and analyzing response patterns

	// Simplified implementation
	return nil, fmt.Errorf("ICMP analysis not implemented")
}

// fingerprintHTTPHeaders attempts to identify the OS by HTTP headers
func (f *OSFingerprinter) fingerprintHTTPHeaders() (*OSInfo, error) {
	// Connect to HTTP port and analyze response headers
	client := &http.Client{
		Timeout: f.Timeout,
	}

	resp, err := client.Get(fmt.Sprintf("http://%s/", f.Target))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check server header
	server := resp.Header.Get("Server")
	if server != "" {
		// Extract OS hints from server header
		osInfo := analyzeServerHeader(server)
		if osInfo.Name != OSUnknown {
			return osInfo, nil
		}
	}

	// Look for other OS-indicating headers
	for header, value := range resp.Header {
		if strings.ToLower(header) == "x-powered-by" {
			if strings.Contains(strings.ToLower(value[0]), "php") {
				// PHP often runs on Linux
				return &OSInfo{
					Name:        OSLinux,
					Family:      OSLinux,
					Probability: 0.6,
					Methods:     []string{"HTTP Header Analysis"},
				}, nil
			}

			if strings.Contains(strings.ToLower(value[0]), "asp.net") {
				// ASP.NET runs on Windows
				return &OSInfo{
					Name:        OSWindows,
					Family:      OSWindows,
					Probability: 0.9,
					Methods:     []string{"HTTP Header Analysis"},
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no OS-indicating HTTP headers found")
}

// fingerprintSSHBanner attempts to identify the OS by SSH banner
func (f *OSFingerprinter) fingerprintSSHBanner() (*OSInfo, error) {
	// Connect to SSH port and analyze the banner
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", f.Target), f.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(f.Timeout))

	// Read the SSH banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	banner := string(buffer[:n])

	// Look for OS indicators in the banner
	return analyzeSSHBanner(banner), nil
}

// analyzeServerHeader extracts OS information from HTTP Server header
func analyzeServerHeader(server string) *OSInfo {
	server = strings.ToLower(server)

	if strings.Contains(server, "microsoft-iis") {
		return &OSInfo{
			Name:        OSWindows,
			Family:      OSWindows,
			Probability: 0.9,
			Methods:     []string{"HTTP Server Header"},
		}
	}

	if strings.Contains(server, "apache") {
		if strings.Contains(server, "win") {
			return &OSInfo{
				Name:        OSWindows,
				Family:      OSWindows,
				Probability: 0.8,
				Methods:     []string{"HTTP Server Header"},
			}
		}

		return &OSInfo{
			Name:        OSLinux,
			Family:      OSLinux,
			Probability: 0.7,
			Methods:     []string{"HTTP Server Header"},
		}
	}

	if strings.Contains(server, "nginx") {
		return &OSInfo{
			Name:        OSLinux,
			Family:      OSLinux,
			Probability: 0.7,
			Methods:     []string{"HTTP Server Header"},
		}
	}

	return &OSInfo{
		Name:        OSUnknown,
		Family:      OSUnknown,
		Probability: 0.0,
		Methods:     []string{},
	}
}

// analyzeSSHBanner extracts OS information from SSH banner
func analyzeSSHBanner(banner string) *OSInfo {
	banner = strings.ToLower(banner)

	// Look for common SSH implementations and their OS associations
	if strings.Contains(banner, "openssh") {
		if strings.Contains(banner, "ubuntu") || strings.Contains(banner, "debian") {
			return &OSInfo{
				Name:        "Ubuntu/Debian Linux",
				Family:      OSLinux,
				Probability: 0.9,
				Methods:     []string{"SSH Banner Analysis"},
			}
		}

		if strings.Contains(banner, "centos") || strings.Contains(banner, "redhat") || strings.Contains(banner, "rhel") {
			return &OSInfo{
				Name:        "CentOS/RHEL Linux",
				Family:      OSLinux,
				Probability: 0.9,
				Methods:     []string{"SSH Banner Analysis"},
			}
		}

		if strings.Contains(banner, "freebsd") {
			return &OSInfo{
				Name:        OSFreeBSD,
				Family:      OSFreeBSD,
				Probability: 0.9,
				Methods:     []string{"SSH Banner Analysis"},
			}
		}

		return &OSInfo{
			Name:        OSLinux,
			Family:      OSLinux,
			Probability: 0.7,
			Methods:     []string{"SSH Banner Analysis"},
		}
	}

	// Windows SSH often uses different implementations
	if strings.Contains(banner, "ssh server") && strings.Contains(banner, "windows") {
		return &OSInfo{
			Name:        OSWindows,
			Family:      OSWindows,
			Probability: 0.9,
			Methods:     []string{"SSH Banner Analysis"},
		}
	}

	return &OSInfo{
		Name:        OSUnknown,
		Family:      OSUnknown,
		Probability: 0.0,
		Methods:     []string{},
	}
}

// Helper function to get absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// extractFamily extracts the OS family from a full OS name
func extractFamily(osName string) string {
	if strings.Contains(osName, OSWindows) {
		return OSWindows
	}
	if strings.Contains(osName, OSLinux) {
		return OSLinux
	}
	if strings.Contains(osName, OSMacOS) {
		return OSMacOS
	}
	if strings.Contains(osName, OSFreeBSD) {
		return OSFreeBSD
	}
	if strings.Contains(osName, OSSolaris) {
		return OSSolaris
	}
	if strings.Contains(osName, OSAndroid) {
		return OSAndroid
	}
	if strings.Contains(osName, OSiOS) {
		return OSiOS
	}
	return OSUnknown
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
