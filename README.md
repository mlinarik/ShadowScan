
# ShadowScan - Security Scanning Suite

ShadowScan is a comprehensive web-based security scanning platform featuring multiple reconnaissance and analysis tools. It provides an intuitive interface for network discovery, vulnerability assessment, web crawling, DNS analysis, SSL/TLS scanning, and IP/domain lookup. All results are downloadable in JSON format.

## Features

### Nmap Network Scanner
- TCP SYN, UDP, and other scan types
- Custom port selection
- Background scan management (start, cancel, status)
- Downloadable scan results

### Web Vulnerability Scanner
- XSS (Cross-Site Scripting) detection
- SQL injection vulnerability testing
- Misconfiguration checks for sensitive files
- Real-time vulnerability results

### Web Crawler & Directory Discovery
- Crawls websites, discovers URLs, forms, and technologies
- Directory and file brute-forcing (common paths/files)
- Robots.txt and sitemap analysis
- Security headers and cookie analysis
- Downloadable crawl results

### DNS Toolkit
- DNS record lookup (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
- Nameserver analysis and response time
- Zone transfer attempts
- Subdomain enumeration (common names)
- DNSSEC, CAA, SPF, DMARC, DKIM checks
- DNS propagation and reverse DNS lookup
- Downloadable DNS analysis results

### SSL/TLS Scanner
- Certificate information (expiry, key size)
- Supported protocol detection (SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3)
- Cipher suite enumeration
- Vulnerability checks (expired/weak certs, weak protocols/ciphers)
- Security rating calculation
- Downloadable SSL scan results

### IP/Domain Lookup
- IP/domain type detection
- Geolocation (free API)
- DNS and WHOIS info
- Downloadable lookup results

### Web Interface Features
- Modern, responsive UI
- Real-time scan progress monitoring
- Tool dashboard for easy navigation
- Detailed result visualization
- Export results as JSON
- Scan history tracking

## Backend Tools & Libraries

- **Flask**: Web framework for API and UI
- **Nmap**: Network scanning (via Python bindings or subprocess)
- **BeautifulSoup (bs4)**: HTML parsing for crawling
- **dnspython**: DNS queries and analysis
- **cryptography**: SSL/TLS certificate parsing
- **requests**: HTTP requests for crawling and analysis
- **concurrent.futures**: Threading for fast scans/enumeration
- **uuid, threading, os, json, time, datetime, socket, re**: Standard Python libraries for scan management, file handling, and data processing

## Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd ShadowScan
    ```
2. **Run with Docker Compose:**
    ```bash
    docker compose up -d
    ```
3. **Or use the helper scripts:**
    ```bash
    # Linux/macOS
    ./docker-run.sh

    # Windows PowerShell
    .\docker-run.ps1
    ```
4. Open your browser and go to `http://localhost:8080`

### Using Docker

Build and run the container:

```bash
# Build the image
docker build -t shadowscan .

# Run the container
docker run -d \
  --name shadowscan \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -p 8080:8080 \
  -v $(pwd)/scan_results:/app/scan_results \
  shadowscan
```

### Manual Installation

If you prefer to run without Docker:

1. Install Python 3.8+ and nmap
2. Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Run the application:
    ```bash
    python app.py
    ```
4. Open your browser and go to `http://localhost:8080`

## Usage Guide

### Basic Scan
1. Enter a target (IP address, hostname, or CIDR notation)
2. Select a scan type from the dropdown
3. Optionally specify ports (leave empty for default ports)
4. Click "Start Scan"

### Advanced Configuration
- Timing: Choose from T0 (paranoid) to T5 (insane) for different speed/stealth trade-offs
- Scripts: Enable NSE scripts for vulnerability detection, discovery, etc.
- Evasion: Use packet fragmentation, decoys, or source IP spoofing
- Performance: Adjust timeouts, delays, and retry counts

### Example Targets
- Single IP: `192.168.1.1`
- Hostname: `scanme.nmap.org`
- IP Range: `192.168.1.1-10`
- CIDR Notation: `192.168.1.0/24`
- Multiple targets: `192.168.1.1,192.168.1.5,192.168.1.10`

### Example Port Specifications
- Specific ports: `22,80,443`
- Port range: `1-1000`
- All ports: `1-65535`
- Mixed: `22,80,443,8000-8100`

## Security Considerations

⚠️ **Important Security Notes:**

1. Only scan networks and systems you own or have explicit permission to test
2. Ensure compliance with local laws and regulations
3. The container runs with elevated network capabilities (NET_ADMIN, NET_RAW)
4. Consider implementing authentication if exposing this service to untrusted networks
5. Be mindful of scan frequency to avoid overwhelming target systems

## API Endpoints

The application provides a REST API for programmatic access:

### Nmap Scanner
- `POST /scan` - Start a new nmap scan
- `GET /scan/<scan_id>/status` - Check scan status
- `GET /scan/<scan_id>/result` - Get scan results
- `POST /scan/<scan_id>/cancel` - Cancel a running scan
- `GET /scans` - List all scans
- `GET /scan/<scan_id>/download` - Download nmap scan results

### Web Crawler
- `POST /crawler` - Start web crawl
- `GET /crawler/<crawl_id>/download` - Download crawl result

### DNS Toolkit
- `POST /dns` - Start DNS analysis
- `GET /dns/<dns_id>/download` - Download DNS result

### SSL/TLS Scanner
- `POST /ssl` - Start SSL/TLS scan
- `GET /ssl/<ssl_scan_id>/download` - Download SSL result

### IP/Domain Lookup
- `POST /lookup` - Start IP/domain lookup
- `GET /lookup/<lookup_id>/download` - Download lookup result

### Web Vulnerability Scanner
- `POST /vulnscan` - Start vulnerability scan

### Example API Usage

Start an nmap scan:
```bash
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "scan_type": "tcp_syn",
    "ports": "22,80,443",
    "options": {
      "timing": "4",
      "verbose": true
    }
  }'
```

Check scan status:
```bash
curl http://localhost:8080/scan/<scan_id>/status
```

Get scan results:
```bash
curl http://localhost:8080/scan/<scan_id>/result
```

Start a web crawl:
```bash
curl -X POST http://localhost:8080/crawler \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "options": {
      "crawl_links": true,
      "directory_bruteforce": true,
      "max_depth": 2,
      "max_urls": 50
    }
  }'
```

## File Structure

```
.
├── Dockerfile              # Docker container configuration
├── docker-compose.yml      # Docker Compose setup
├── requirements.txt        # Python dependencies
├── app.py                  # Main Flask application
├── docker-run.sh           # Linux/macOS Docker run script
├── docker-run.ps1          # Windows PowerShell Docker run script
├── run.sh                  # Linux/macOS run script
├── run.ps1                 # Windows PowerShell run script
├── deploy.ps1              # Windows deployment script
├── templates/              # HTML templates for each tool
│   ├── index.html          # Main dashboard
│   ├── home.html           # Home page template
│   ├── nmap.html           # Nmap scanner interface
│   ├── lookup.html         # IP/Domain lookup interface
│   ├── ssl.html            # SSL/TLS scanner interface
│   ├── crawler.html        # Web crawler interface
│   ├── dns.html            # DNS toolkit interface
│   └── vulnscan.html       # Vulnerability scanner interface
├── scan_results/           # Directory for exported scan results
└── README.md               # This file
```

## Troubleshooting

### Common Issues

**Permission Denied Errors**
- Ensure the container has NET_ADMIN and NET_RAW capabilities
- Some scan types require root privileges

**Scans Timing Out**
- Increase host timeout values
- Use faster timing templates (T4, T5)
- Reduce the number of target hosts

**No Results Returned**
- Check if the target is reachable
- Verify firewall settings
- Try a ping scan first to test connectivity

**Container Won't Start**
- Check if port 8080 is available
- Verify Docker is running
- Check container logs: `docker logs shadowscan`

### Debugging

View application logs:
```bash
docker logs -f shadowscan
```

Execute commands in the container:
```bash
docker exec -it shadowscan /bin/bash
```

Test nmap directly:
```bash
docker exec shadowscan nmap -sS -T4 scanme.nmap.org
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for educational and authorized testing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## Disclaimer

This tool is designed for legitimate network security testing and administration. Users must ensure they have proper authorization before scanning any networks or systems. The authors are not responsible for any misuse of this software.
