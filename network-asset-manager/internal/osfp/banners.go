package osfp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Common FTP banner patterns for OS fingerprinting
var ftpBannerOSPatterns = map[string]string{
	`\bWindows\b`:                   OSWindows,
	`\bMicrosoft\b`:                 OSWindows,
	`\bFileZilla Server\b`:          OSWindows,
	`\bDebian\b`:                    OSLinux,
	`\bUbuntu\b`:                    OSLinux,
	`\bCentOS\b`:                    OSLinux,
	`\bRedHat\b`:                    OSLinux,
	`\bRHEL\b`:                      OSLinux,
	`\bFedora\b`:                    OSLinux,
	`\bSUSE\b`:                      OSLinux,
	`\bFreeBSD\b`:                   OSFreeBSD,
	`\bNetBSD\b`:                    "NetBSD",
	`\bOpenBSD\b`:                   "OpenBSD",
	`\bDarwin\b`:                    OSMacOS,
	`\bmacOS\b`:                     OSMacOS,
	`\bOS X\b`:                      OSMacOS,
	`\bSolaris\b`:                   OSSolaris,
	`\bSunOS\b`:                     OSSolaris,
	`\bAIX\b`:                       "AIX",
	`\bHP-UX\b`:                     "HP-UX",
	`\bIRIX\b`:                      "IRIX",
	`\bAndroid\b`:                   OSAndroid,
	`\biOS\b`:                       OSiOS,
	`\biPhone\b`:                    OSiOS,
	`\biPad\b`:                      OSiOS,
	`\bProFTPD\b`:                   OSLinux,
	`\bvsFTPd\b`:                    OSLinux,
	`\bPure-FTPd\b`:                 OSLinux,
	`\bWU-FTPD\b`:                   "Unix",
	`\bBFTPD\b`:                     "Unix",
	`\bFTP Server \(Version 6.0\)`:  "Windows Server 2003",
	`\bFTP Server \(Version 5.0\)`:  "Windows 2000",
	`\bFTP Server \(Version 10.0\)`: "Windows Server 2008",
	`\bMicrosoft FTP Service\b`:     OSWindows,
	`\bWINSock FTP Server\b`:        OSWindows,
	`\bTITAN FTP Server\b`:          OSWindows,
	`\bCrushFTP\b`:                  "Java-based (Cross-platform)",
	`\bCerberus FTP Server\b`:       OSWindows,
	`\bCompleteFTP\b`:               OSWindows,
	`\bGolden FTP Server\b`:         OSWindows,
	`\bWingFTP Server\b`:            OSWindows,
	`\bXlight FTP Server\b`:         OSWindows,
	`\bIIS\b`:                       OSWindows,
	`\bServ-U FTP Server\b`:         OSWindows,
}

// FingerprintFTPBanner identifies the OS from an FTP banner
func (f *OSFingerprinter) FingerprintFTPBanner() (*OSInfo, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:21", f.Target), f.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(f.Timeout))

	// Read the FTP banner
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	// Check for OS indicators in the banner
	for pattern, os := range ftpBannerOSPatterns {
		matched, err := regexp.MatchString(pattern, response)
		if err != nil {
			continue
		}

		if matched {
			return &OSInfo{
				Name:        os,
				Family:      extractFamily(os),
				Probability: 0.8,
				Methods:     []string{"FTP Banner Analysis"},
			}, nil
		}
	}

	return nil, fmt.Errorf("no OS indicators found in FTP banner")
}

// FingerprintHTTPHeaders identifies the OS from HTTP headers
func (f *OSFingerprinter) FingerprintHTTPHeaders() (*OSInfo, error) {
	client := &http.Client{
		Timeout: f.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate validation
			},
		},
	}

	// Try both HTTP and HTTPS
	urls := []string{
		fmt.Sprintf("http://%s/", f.Target),
		fmt.Sprintf("https://%s/", f.Target),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for Server header
		serverHeader := resp.Header.Get("Server")
		if serverHeader != "" {
			for pattern, os := range ftpBannerOSPatterns {
				matched, err := regexp.MatchString(pattern, serverHeader)
				if err != nil {
					continue
				}

				if matched {
					return &OSInfo{
						Name:        os,
						Family:      extractFamily(os),
						Probability: 0.8,
						Methods:     []string{"HTTP Server Header Analysis"},
					}, nil
				}
			}

			// Check for common server software
			if strings.Contains(serverHeader, "IIS") {
				return &OSInfo{
					Name:        OSWindows,
					Family:      OSWindows,
					Probability: 0.9,
					Methods:     []string{"HTTP Server Header Analysis"},
				}, nil
			}

			if strings.Contains(serverHeader, "Apache") {
				probability := 0.6 // Default probability for Apache
				osName := OSLinux  // Default OS for Apache

				if strings.Contains(serverHeader, "Win") {
					osName = OSWindows
					probability = 0.8
				}

				return &OSInfo{
					Name:        osName,
					Family:      extractFamily(osName),
					Probability: probability,
					Methods:     []string{"HTTP Server Header Analysis"},
				}, nil
			}

			if strings.Contains(serverHeader, "nginx") {
				return &OSInfo{
					Name:        OSLinux,
					Family:      OSLinux,
					Probability: 0.7,
					Methods:     []string{"HTTP Server Header Analysis"},
				}, nil
			}
		}

		// Check for X-Powered-By header
		poweredBy := resp.Header.Get("X-Powered-By")
		if poweredBy != "" {
			if strings.Contains(poweredBy, "ASP.NET") {
				return &OSInfo{
					Name:        OSWindows,
					Family:      OSWindows,
					Probability: 0.9,
					Methods:     []string{"HTTP X-Powered-By Header Analysis"},
				}, nil
			}

			if strings.Contains(poweredBy, "PHP") {
				// PHP is more common on Linux but can run on any OS
				return &OSInfo{
					Name:        OSLinux,
					Family:      OSLinux,
					Probability: 0.6,
					Methods:     []string{"HTTP X-Powered-By Header Analysis"},
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no OS indicators found in HTTP headers")
}
