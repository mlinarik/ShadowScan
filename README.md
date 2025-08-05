# Nmap Web Scanner

A web-based interface for running Nmap scans with a clean, user-friendly UI. This application allows you to configure and execute various types of Nmap scans through a modern web interface.

## Features

### Scan Types
- **TCP SYN Scan** (-sS) - Default, fast and stealthy
- **TCP Connect Scan** (-sT) - Complete TCP connection
- **UDP Scan** (-sU) - Scan UDP ports
- **TCP ACK Scan** (-sA) - Firewall rule detection
- **TCP Window Scan** (-sW) - More advanced ACK scan
- **TCP Maimon Scan** (-sM) - FIN/ACK scan
- **TCP Null Scan** (-sN) - No flags set
- **TCP FIN Scan** (-sF) - FIN flag only
- **TCP XMAS Scan** (-sX) - FIN, PSH, and URG flags
- **Ping Scan** (-sn) - Host discovery only
- **List Scan** (-sL) - List targets without scanning
- **Version Detection** (-sV) - Detect service versions
- **OS Detection** (-O) - Operating system detection
- **Aggressive Scan** (-A) - OS detection, version detection, script scanning

### Advanced Options
- **Timing Templates** (T0-T5) - Control scan speed and stealth
- **Port Specification** - Custom port ranges or specific ports
- **NSE Scripts** - Enable Nmap Scripting Engine with custom scripts
- **Evasion Techniques** - Fragment packets, decoys, source IP spoofing
- **Performance Tuning** - Host timeout, scan delay, max retries
- **Network Interface** - Specify network interface for scanning

### Web Interface Features
- Real-time scan progress monitoring
- Detailed results with host information, open ports, and services
- Scan history and management
- Export results as JSON
- Responsive design for desktop and mobile
- Clean, modern Bootstrap-based UI

## Quick Start

### Using Docker Compose (Recommended)

1. Clone or download this repository
2. Navigate to the project directory
3. Run the application:

```bash
docker-compose up -d
```

4. Open your browser and go to `http://localhost:5000`

### Using Docker

Build and run the container:

```bash
# Build the image
docker build -t nmap-web-scanner .

# Run the container
docker run -d \
  --name nmap-scanner \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -p 5000:5000 \
  -v $(pwd)/scan_results:/app/scan_results \
  nmap-web-scanner
```

### Manual Installation

If you prefer to run without Docker:

1. Install Python 3.11+ and nmap:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip nmap

# CentOS/RHEL
sudo yum install python3 python3-pip nmap

# macOS (with Homebrew)
brew install python nmap
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and go to `http://localhost:5000`

## Usage Guide

### Basic Scan
1. Enter a target (IP address, hostname, or CIDR notation)
2. Select a scan type from the dropdown
3. Optionally specify ports (leave empty for default ports)
4. Click "Start Scan"

### Advanced Configuration
- **Timing**: Choose from T0 (paranoid) to T5 (insane) for different speed/stealth trade-offs
- **Scripts**: Enable NSE scripts for vulnerability detection, discovery, etc.
- **Evasion**: Use packet fragmentation, decoys, or source IP spoofing
- **Performance**: Adjust timeouts, delays, and retry counts

### Example Targets
- Single IP: `192.168.1.1`
- Hostname: `scanme.nmap.org`
- IP Range: `192.168.1.1-10`
- CIDR Notation: `192.168.1.0/24`
- Multiple targets: `192.168.1.1,192.168.1.5,192.168.1.10`

### Example Port Specifications
- Specific ports: `22,80,443`
- Port range: `1-1000`
- All ports: `-` or `1-65535`
- Mixed: `22,80,443,8000-8100`

## Security Considerations

⚠️ **Important Security Notes:**

1. **Network Scanning Ethics**: Only scan networks and systems you own or have explicit permission to test
2. **Legal Compliance**: Ensure compliance with local laws and regulations
3. **Container Security**: The container runs with elevated network capabilities (NET_ADMIN, NET_RAW)
4. **Access Control**: Consider implementing authentication if exposing this service to untrusted networks
5. **Rate Limiting**: Be mindful of scan frequency to avoid overwhelming target systems

## API Endpoints

The application provides a REST API for programmatic access:

- `POST /scan` - Start a new scan
- `GET /scan/<scan_id>/status` - Check scan status
- `GET /scan/<scan_id>/result` - Get scan results
- `GET /scans` - List all scans
- `GET /scan/<scan_id>/download` - Download results as JSON

### Example API Usage

Start a scan:
```bash
curl -X POST http://localhost:5000/scan \
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

Check status:
```bash
curl http://localhost:5000/scan/<scan_id>/status
```

Get results:
```bash
curl http://localhost:5000/scan/<scan_id>/result
```

## File Structure

```
.
├── Dockerfile              # Docker container configuration
├── docker-compose.yml      # Docker Compose setup
├── requirements.txt        # Python dependencies
├── app.py                  # Main Flask application
├── templates/
│   └── index.html          # Web interface template
├── scan_results/           # Directory for exported scan results
└── README.md              # This file
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
- Check if port 5000 is available
- Verify Docker is running
- Check container logs: `docker logs nmap-scanner`

### Debugging

View application logs:
```bash
docker logs -f nmap-scanner
```

Execute commands in the container:
```bash
docker exec -it nmap-scanner /bin/bash
```

Test nmap directly:
```bash
docker exec nmap-scanner nmap -sS -T4 scanme.nmap.org
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
