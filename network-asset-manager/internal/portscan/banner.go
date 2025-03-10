package portscan

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// Common service probes
var serviceProbes = map[int][]byte{
	21:   []byte("USER anonymous\r\n"),
	22:   []byte("SSH-2.0-OpenSSH_7.6p1\r\n"),
	25:   []byte("HELO example.com\r\n"),
	80:   []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
	443:  []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
	110:  []byte("USER user\r\n"),
	143:  []byte("a1 LOGIN user password\r\n"),
	3306: []byte{10, 0, 0, 0, 0x85},      // MySQL greeting
	5432: []byte{0, 0, 0, 8, 0, 0, 0, 0}, // PostgreSQL
}

// Service signatures for identification
var serviceSignatures = map[string]string{
	"SSH-":                 "SSH",
	"HTTP/":                "HTTP",
	"220 ":                 "SMTP/FTP",
	"*OK ":                 "IMAP",
	"+OK ":                 "POP3",
	"5.":                   "SMTP",
	"FTP":                  "FTP",
	"MySQL":                "MySQL",
	"PostgreSQL":           "PostgreSQL",
	"530 Login incorrect":  "FTP",
	"220 ProFTPD":          "FTP",
	"220 FileZilla Server": "FTP",
}

// getBanner attempts to grab a service banner from the specified port
func (s *Scanner) getBanner(port int) (string, string) {
	address := fmt.Sprintf("%s:%d", s.Target, port)

	// Connect to the port
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return "", "unknown"
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	// Some services send banners immediately upon connection
	reader := bufio.NewReader(conn)
	initialBanner, _ := reader.ReadString('\n')

	// If no initial banner, try sending a probe
	if initialBanner == "" && serviceProbes[port] != nil {
		conn.Write(serviceProbes[port])
		initialBanner, _ = reader.ReadString('\n')
	}

	// Try to identify the service
	service := identifyService(initialBanner, port)

	return strings.TrimSpace(initialBanner), service
}

// identifyService tries to identify a service based on its banner
func identifyService(banner string, port int) string {
	// First check against known signatures
	for signature, service := range serviceSignatures {
		if strings.Contains(banner, signature) {
			return service
		}
	}

	// If no match, try common port assignments
	commonPorts := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		465:  "SMTPS",
		587:  "Submission",
		993:  "IMAPS",
		995:  "POP3S",
		1433: "MSSQL",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		8080: "HTTP-Proxy",
	}

	if service, ok := commonPorts[port]; ok {
		return service
	}

	return "unknown"
}
