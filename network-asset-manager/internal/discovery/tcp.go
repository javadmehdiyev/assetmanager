package discovery

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPSYNPing performs a TCP SYN ping to check if a host is up
func (s *Scanner) TCPSYNPing(host string, port int) bool {
	// First, try a high-level connection which works without raw sockets
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// If the standard connection fails, try a raw socket approach
	// Note: Raw sockets require elevated privileges
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		// If raw socket fails, return false
		return false
	}
	defer syscall.Close(fd)

	// Resolve target IP
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Create a new packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Get local address
	localAddr, err := net.ResolveIPAddr("ip", getOutboundIP().String())
	if err != nil {
		return false
	}

	// Generate random source port
	srcPort := 12345 // Ideally, this should be random

	// Create TCP SYN packet
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    localAddr.IP,
		DstIP:    ip,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(port),
		SYN:     true,
	}

	// Set TCP checksum
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize packet
	err = gopacket.SerializeLayers(buffer, opts, ethernetLayer, ipLayer, tcpLayer)
	if err != nil {
		return false
	}

	// Send packet
	packetData := buffer.Bytes()
	addr := syscall.SockaddrInet4{
		Port: port,
	}
	copy(addr.Addr[:], ip.To4())

	err = syscall.Sendto(fd, packetData, 0, &addr)
	if err != nil {
		return false
	}

	// Wait for response - replace syscall.SetTimeout which doesn't exist
	recvBuf := make([]byte, 4096)

	// Set a deadline using syscall.SetsockoptTimeval instead
	tv := syscall.Timeval{
		Sec:  int64(s.Timeout / time.Second),
		Usec: int32((s.Timeout % time.Second) / time.Microsecond),
	}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	n, _, err := syscall.Recvfrom(fd, recvBuf, 0)
	if err != nil {
		return false
	}

	// Parse response
	packet := gopacket.NewPacket(recvBuf[:n], layers.LayerTypeIPv4, gopacket.Default)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.SYN && tcp.ACK
	}

	return false
}

// TCPACKPing performs a TCP ACK ping to check if a host is up
func (s *Scanner) TCPACKPing(host string, port int) bool {
	// Similar implementation to TCPSYNPing, but sending ACK instead of SYN
	// This is more advanced and requires raw sockets

	// For simplicity and since this requires similar raw socket handling,
	// we'll just use a placeholder implementation that returns false
	// In a real implementation, you would create a TCP packet with the ACK flag
	// set and check for RST responses

	return false
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
