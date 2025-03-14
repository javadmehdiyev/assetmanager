# Network Asset Manager

Network Asset Manager is a comprehensive command-line tool for network discovery, port scanning, and operating system detection. It helps security professionals and network administrators identify active hosts, open services, and operating system details on their networks.

## Features

- **Network Host Discovery**: Identify active hosts on a network using multiple techniques
- **Port Scanning**: Detect open ports and services using various scanning methods
- **OS Detection**: Identify operating systems using TCP/IP stack fingerprinting
- **Service Banner Grabbing**: Retrieve and analyze service banners
- **JSON Output**: Export results in structured JSON format
- **Customizable Scans**: Configure scan parameters including timeout and parallelism

## Installation

### Prerequisites

- Go 1.16 or higher
- Root/Administrator privileges (for certain scan types)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/network-asset-manager.git
cd network-asset-manager

# Build the project
go build -o nam

# Move to a directory in your PATH (optional)
sudo mv nam /usr/local/bin/
```

## Usage

### Basic Network Discovery

```bash
# Scan a network range
./nam scan 192.168.1.0/24

# Adjust timeout and parallelism
./nam scan 10.0.0.0/16 --timeout 5 --parallel 50
```

### Port Scanning

```bash
# Discover hosts and scan default ports
./nam scan 192.168.1.0/24 --ports

# Scan specific port range
./nam scan 192.168.1.0/24 --ports --port-range 22,80,443,8080-8090

# Use a specific scan type
./nam scan 192.168.1.0/24 --ports --scan-type syn
```

### OS Detection

```bash
# Enable OS detection
./nam scan 192.168.1.0/24 --os-detection

# Combine with port scanning
./nam scan 192.168.1.0/24 --ports --os-detection
```

### JSON Output

```bash
# Output results in JSON format
./nam scan 192.168.1.0/24 --json

# Combine all features with JSON output
./nam scan 192.168.1.0/24 --ports --os-detection --json > results.json
```

## Scan Types

The tool supports various port scanning techniques:

- **connect**: Full TCP connections (default, reliable but easily detected)
- **syn**: TCP SYN scan (half-open, less likely to be logged)
- **fin**: TCP FIN scan (stealthy, can bypass simple firewalls)
- **null**: TCP NULL scan (sends packet with no flags set)
- **xmas**: TCP XMAS scan (sends packet with FIN, PSH, URG flags)
- **ack**: TCP ACK scan (useful for mapping firewall rules)
- **udp**: UDP scan (for discovering UDP services)

## OS Detection Methods

Operating system detection uses multiple techniques:

- TCP/IP stack fingerprinting (TTL values, window sizes, TCP options)
- ICMP-based fingerprinting
- Application layer banner analysis (HTTP, FTP, SSH)
- Active TCP SYN/FIN/ACK probing

## Output Formats

### Human-Readable Output

The default output is formatted for easy reading in the terminal:

```
Discovered 5 hosts:

--------------------------------------------------------------------------------
IP                   | MAC                  | Hostname                        | Method
--------------------------------------------------------------------------------
192.168.1.1          | 00:11:22:33:44:55    | router.local                    | ARP
192.168.1.10         | aa:bb:cc:dd:ee:ff    | desktop.local                   | ARP
--------------------------------------------------------------------------------

OS Detection Results for 192.168.1.10:
--------------------------------------------------------------------------------
OS Name                    | OS Family       | Probability  | Detection Methods
--------------------------------------------------------------------------------
Windows 10                 | Windows         | 85.0%        | TTL Analysis, TCP Window Analysis
--------------------------------------------------------------------------------
```

### JSON Output

JSON output provides structured data for further processing:

```json
{
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "hostname": "router.local",
      "is_up": true,
      "discovery_method": "ARP"
    }
  ],
  "port_scans": {
    "192.168.1.1": [
      {
        "port": 80,
        "protocol": "tcp",
        "status": "open",
        "service": "HTTP",
        "banner": "nginx/1.18.0"
      }
    ]
  },
  "os_detection": {
    "192.168.1.1": {
      "name": "Linux 5.x",
      "family": "Linux",
      "probability": 0.85,
      "methods": ["TTL Analysis", "TCP Window Analysis"]
    }
  },
  "scan_time": "2023-06-01T15:04:05Z"
}
```

## Legal and Ethical Considerations

This tool should only be used on networks you own or have explicit permission to scan. Unauthorized network scanning may be illegal in many jurisdictions and violate acceptable use policies.

## Limitations

- Some scan types (SYN, FIN, NULL, XMAS) require root/administrator privileges
- OS detection accuracy varies depending on network conditions and target configuration
- Firewalls and security devices may block scans or produce false results
- High scan rates may impact network performance

## License

[MIT License](LICENSE)
