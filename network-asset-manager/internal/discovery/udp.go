package discovery

import (
	"fmt"
	"net"
	"time"
)

// UDPPing sends a UDP packet to check if a host is up
func (s *Scanner) UDPPing(host string, port int) bool {
	// Resolve target address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set deadlines
	err = conn.SetDeadline(time.Now().Add(s.Timeout))
	if err != nil {
		return false
	}

	// Send UDP packet
	_, err = conn.Write([]byte("PING"))
	if err != nil {
		return false
	}

	// Wait for response or ICMP error
	buf := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buf)

	// If there's any response, the host is up
	// Even a Port Unreachable ICMP error means the host is up
	return true
}
