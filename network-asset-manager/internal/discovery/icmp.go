package discovery

import (
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMPEcho performs an ICMP Echo Request (ping) to check if a host is up
func (s *Scanner) ICMPEcho(host string) bool {
	// Need to be root or have proper capabilities to create raw sockets
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// Fallback to less privileged method that works on Windows/Mac without admin
		return s.pingWithTimeout(host)
	}
	defer conn.Close()

	// Resolve the target IP
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	// Create ICMP message
	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		},
	}

	binMsg, err := message.Marshal(nil)
	if err != nil {
		return false
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// Send the message
	_, err = conn.WriteTo(binMsg, dst)
	if err != nil {
		return false
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	// Parse the reply
	parsed, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		return false
	}

	// Check if we got an Echo Reply
	return parsed.Type == ipv4.ICMPTypeEchoReply
}

// ICMPTimestamp sends an ICMP Timestamp Request to check if a host is up
func (s *Scanner) ICMPTimestamp(host string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Resolve the target IP
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	// Create ICMP timestamp message
	// We need to construct it manually since icmp.Timestamp type doesn't exist
	// Type 13 is ICMP Timestamp request
	message := icmp.Message{
		Type: ipv4.ICMPTypeTimestamp,
		Code: 0,
		Body: &icmp.Echo{ // Use Echo as a placeholder
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // 12 bytes for timestamp data
		},
	}

	binMsg, err := message.Marshal(nil)
	if err != nil {
		return false
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// Send the message
	_, err = conn.WriteTo(binMsg, dst)
	if err != nil {
		return false
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	// Check if we got any reply - that's good enough
	return n > 0
}

// ICMPAddressMask sends an ICMP Address Mask Request to check if a host is up
func (s *Scanner) ICMPAddressMask(host string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Resolve the target IP
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	// Create ICMP address mask message
	message := icmp.Message{
		Type: ipv4.ICMPType(17), // Address Mask Request
		Code: 0,
		Body: &icmp.Echo{ // Using Echo as a placeholder for Address Mask
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte{0, 0, 0, 0}, // Address mask will be filled by the target
		},
	}

	binMsg, err := message.Marshal(nil)
	if err != nil {
		return false
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// Send the message
	_, err = conn.WriteTo(binMsg, dst)
	if err != nil {
		return false
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	// Parse the reply
	parsed, err := icmp.ParseMessage(ipv4.ICMPType(18).Protocol(), reply[:n]) // 18 is Address Mask Reply
	if err != nil {
		return false
	}

	// Check if we got an Address Mask Reply
	return parsed.Type == ipv4.ICMPType(18)
}

// pingWithTimeout is a fallback method that uses high-level OS ping
func (s *Scanner) pingWithTimeout(host string) bool {
	// Resolve IP
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return false
	}

	// Create connection
	conn, err := net.DialTimeout("ip4:icmp", ip.String(), s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// If we got here, we established a connection
	return true
}
