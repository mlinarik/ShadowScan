#!/usr/bin/env python3
"""
ShadowScan - Security Scanning Suite
Author: mlinarik
"""

from flask import Flask, render_template, request, jsonify, send_file
import nmap
import json
import os
import datetime
import threading
import uuid
from werkzeug.utils import secure_filename
import time
import subprocess
import re
import socket
import requests
import ipaddress
import ssl
import concurrent.futures
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Store scan results and status
scan_results = {}
scan_status = {}
scan_threads = {}
scan_processes = {}

# Store lookup results
lookup_results = {}

# Store SSL scan results
ssl_scan_results = {}

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def run_scan(self, scan_id, target, scan_type, ports=None, options=None):
        """Run nmap scan with specified parameters"""
        try:
            scan_status[scan_id] = {'status': 'running', 'progress': 0, 'current_host': '', 'total_hosts': 0, 'scanned_hosts': 0}
            
            # Build nmap arguments
            arguments = self._build_scan_arguments(scan_type, ports, options)
            
            # Parse target to estimate total hosts for progress tracking
            total_hosts = self._estimate_total_hosts(target)
            scan_status[scan_id]['total_hosts'] = total_hosts
            
            # Start progress simulation in a separate thread
            progress_thread = threading.Thread(target=self._simulate_progress, args=(scan_id, total_hosts))
            progress_thread.daemon = True
            progress_thread.start()
            
            # Run the scan
            result = self.nm.scan(hosts=target, arguments=arguments)
            
            # Check if scan was cancelled
            if scan_status.get(scan_id, {}).get('status') == 'cancelled':
                return
            
            # Process results
            processed_result = self._process_scan_result(result, target)
            
            # Save results
            scan_results[scan_id] = {
                'timestamp': datetime.datetime.now().isoformat(),
                'target': target,
                'scan_type': scan_type,
                'arguments': arguments,
                'result': processed_result,
                'raw_result': result
            }
            
            scan_status[scan_id] = {'status': 'completed', 'progress': 100, 'total_hosts': total_hosts, 'scanned_hosts': total_hosts}
            
        except Exception as e:
            if scan_status.get(scan_id, {}).get('status') != 'cancelled':
                scan_status[scan_id] = {'status': 'error', 'error': str(e)}
    
    def _simulate_progress(self, scan_id, total_hosts):
        """Simulate scan progress for better user experience"""
        progress_steps = [
            (2, "Resolving target..."),
            (5, "Starting host discovery..."),
            (15, "Scanning hosts..."),
            (30, "Port scanning in progress..."),
            (50, "Service detection..."),
            (70, "Finalizing scan..."),
            (85, "Processing results...")
        ]
        
        for progress, message in progress_steps:
            if scan_status.get(scan_id, {}).get('status') in ['cancelled', 'completed', 'error']:
                break
            
            scan_status[scan_id].update({
                'progress': progress,
                'current_host': message,
                'scanned_hosts': min(int((progress / 100) * total_hosts), total_hosts)
            })
            
            # Wait between progress updates, but check for cancellation more frequently
            for _ in range(10):  # Check 10 times per second
                if scan_status.get(scan_id, {}).get('status') in ['cancelled', 'completed', 'error']:
                    return
                time.sleep(0.1)
    
    def _build_scan_arguments(self, scan_type, ports, options):
        """Build nmap command arguments based on scan type and options"""
        args = []
        
        # Scan type arguments
        scan_types = {
            'tcp_syn': '-sS',
            'tcp_connect': '-sT',
            'udp': '-sU',
            'tcp_ack': '-sA',
            'tcp_window': '-sW',
            'tcp_maimon': '-sM',
            'tcp_null': '-sN',
            'tcp_fin': '-sF',
            'tcp_xmas': '-sX',
            'ping': '-sn',
            'list': '-sL',
            'version': '-sV',
            'os_detection': '-O',
            'aggressive': '-A'
        }
        
        if scan_type in scan_types:
            args.append(scan_types[scan_type])
        
        # Port specification
        if ports and ports.strip():
            args.append(f'-p {ports}')
        
        # Additional options
        if options:
            if options.get('timing'):
                args.append(f"-T{options['timing']}")
            
            if options.get('verbose'):
                args.append('-v')
            
            if options.get('script_scan'):
                if options.get('script_name'):
                    args.append(f"--script={options['script_name']}")
                else:
                    args.append('--script=default')
            
            if options.get('fragment'):
                args.append('-f')
            
            if options.get('decoy'):
                args.append(f"-D {options['decoy']}")
            
            if options.get('spoof_source'):
                args.append(f"-S {options['spoof_source']}")
            
            if options.get('interface'):
                args.append(f"-e {options['interface']}")
            
            if options.get('max_retries'):
                args.append(f"--max-retries {options['max_retries']}")
            
            if options.get('host_timeout'):
                args.append(f"--host-timeout {options['host_timeout']}")
            
            if options.get('scan_delay'):
                args.append(f"--scan-delay {options['scan_delay']}")
        
        return ' '.join(args)
    
    def _estimate_total_hosts(self, target):
        """Estimate total number of hosts to scan for progress tracking"""
        import ipaddress
        try:
            # Handle CIDR notation
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return min(network.num_addresses, 256)  # Cap at 256 for progress display
            # Handle range notation (e.g., 192.168.1.1-10)
            elif '-' in target and not target.count('-') > 1:
                parts = target.split('-')
                if len(parts) == 2:
                    try:
                        start = int(parts[0].split('.')[-1])
                        end = int(parts[1])
                        return end - start + 1
                    except:
                        return 1
            # Handle comma-separated targets
            elif ',' in target:
                return len(target.split(','))
            else:
                # Single host
                return 1
        except:
            return 1
    
    def _process_scan_result(self, result, target):
        """Process and format scan results"""
        processed = {
            'hosts': {},
            'summary': {
                'total_hosts': 0,
                'hosts_up': 0,
                'hosts_down': 0,
                'total_ports': 0,
                'open_ports': 0,
                'closed_ports': 0,
                'filtered_ports': 0
            }
        }
        
        for host in result['scan']:
            host_info = result['scan'][host]
            processed['hosts'][host] = {
                'hostname': host_info.get('hostnames', []),
                'status': host_info.get('status', {}),
                'addresses': host_info.get('addresses', {}),
                'ports': {},
                'os': host_info.get('osmatch', []),
                'scripts': host_info.get('hostscript', [])
            }
            
            # Process ports
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    processed['hosts'][host]['ports'][f'tcp/{port}'] = port_info
                    processed['summary']['total_ports'] += 1
                    if port_info['state'] == 'open':
                        processed['summary']['open_ports'] += 1
                    elif port_info['state'] == 'closed':
                        processed['summary']['closed_ports'] += 1
                    elif port_info['state'] == 'filtered':
                        processed['summary']['filtered_ports'] += 1
            
            if 'udp' in host_info:
                for port, port_info in host_info['udp'].items():
                    processed['hosts'][host]['ports'][f'udp/{port}'] = port_info
                    processed['summary']['total_ports'] += 1
                    if port_info['state'] == 'open':
                        processed['summary']['open_ports'] += 1
                    elif port_info['state'] == 'closed':
                        processed['summary']['closed_ports'] += 1
                    elif port_info['state'] == 'filtered':
                        processed['summary']['filtered_ports'] += 1
            
            processed['summary']['total_hosts'] += 1
            if host_info.get('status', {}).get('state') == 'up':
                processed['summary']['hosts_up'] += 1
            else:
                processed['summary']['hosts_down'] += 1
        
        return processed

class IPDomainLookup:
    def __init__(self):
        pass
    
    def perform_lookup(self, target, options):
        """Perform comprehensive IP/Domain lookup"""
        start_time = time.time()
        result = {
            'timestamp': datetime.datetime.now().isoformat(),
            'target': target,
            'target_type': self._determine_target_type(target),
            'response_time_ms': 0,
            'ip_addresses': [],
            'geolocation': None,
            'dns_info': {},
            'whois_info': None
        }
        
        try:
            # Determine if target is IP or domain
            if result['target_type'] == 'ip':
                result['ip_addresses'] = [target]
                if options.get('reverse_dns', False):
                    result['dns_info'] = self._get_reverse_dns(target)
            else:
                if options.get('ip_resolution', False):
                    result['ip_addresses'] = self._resolve_domain_to_ips(target)
                    result['dns_info']['hostname'] = target
            
            # Get geolocation for IP addresses
            if options.get('geolocation', False) and result['ip_addresses']:
                # Use the first IP for geolocation
                result['geolocation'] = self._get_geolocation(result['ip_addresses'][0])
            
            # Get WHOIS information
            if options.get('whois_info', False):
                result['whois_info'] = self._get_whois_info(target)
                
        except Exception as e:
            result['error'] = str(e)
        
        result['response_time_ms'] = int((time.time() - start_time) * 1000)
        return result
    
    def _determine_target_type(self, target):
        """Determine if target is IP address or domain"""
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            return 'domain'
    
    def _resolve_domain_to_ips(self, domain):
        """Resolve domain to IP addresses"""
        ips = []
        try:
            # Get IPv4 addresses
            ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
            for addr in ipv4_addresses:
                ip = addr[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        
        try:
            # Get IPv6 addresses
            ipv6_addresses = socket.getaddrinfo(domain, None, socket.AF_INET6)
            for addr in ipv6_addresses:
                ip = addr[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        
        return ips
    
    def _get_reverse_dns(self, ip):
        """Get reverse DNS lookup for IP"""
        dns_info = {'reverse_dns': []}
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            dns_info['reverse_dns'].append(hostname)
            dns_info['reverse_dns'].extend(aliaslist)
        except socket.herror:
            pass
        
        return dns_info
    
    def _get_geolocation(self, ip):
        """Get geolocation information for IP using free API"""
        try:
            # Using ip-api.com free service (no API key required)
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    }
        except Exception as e:
            print(f"Geolocation lookup failed: {e}")
        
        return None
    
    def _get_whois_info(self, target):
        """Get WHOIS information (basic implementation)"""
        try:
            # Simple WHOIS implementation using system whois command
            result = subprocess.run(['whois', target], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=30)
            if result.returncode == 0:
                return result.stdout
        except Exception as e:
            print(f"WHOIS lookup failed: {e}")
        
        return "WHOIS information not available"

class SSLTLSScanner:
    def __init__(self):
        self.supported_protocols = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'SSLv3', 'SSLv23']
    
    def scan_ssl_tls(self, target, options):
        """Perform comprehensive SSL/TLS analysis"""
        start_time = time.time()
        
        # Parse target
        parsed_target = self._parse_target(target)
        if not parsed_target:
            return {'error': 'Invalid target format'}
        
        host, port = parsed_target
        
        result = {
            'timestamp': datetime.datetime.now().isoformat(),
            'target': target,
            'host': host,
            'port': port,
            'response_time_ms': 0,
            'certificate_info': {},
            'protocol_support': {},
            'cipher_suites': [],
            'vulnerabilities': [],
            'security_rating': 'Unknown'
        }
        
        try:
            # Get certificate information
            result['certificate_info'] = self._get_certificate_info(host, port)
            
            # Test protocol support
            if options.get('test_protocols', True):
                result['protocol_support'] = self._test_protocol_support(host, port)
            
            # Get cipher suites
            if options.get('test_ciphers', True):
                result['cipher_suites'] = self._get_cipher_suites(host, port)
            
            # Check for vulnerabilities
            if options.get('check_vulnerabilities', True):
                result['vulnerabilities'] = self._check_vulnerabilities(host, port, result)
            
            # Calculate security rating
            result['security_rating'] = self._calculate_security_rating(result)
            
        except Exception as e:
            result['error'] = str(e)
        
        result['response_time_ms'] = int((time.time() - start_time) * 1000)
        return result
    
    def _parse_target(self, target):
        """Parse target to extract host and port"""
        try:
            # Handle URLs
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                return host, port
            
            # Handle host:port format
            if ':' in target:
                parts = target.split(':')
                if len(parts) == 2:
                    host = parts[0]
                    port = int(parts[1])
                    return host, port
            
            # Default to HTTPS port
            return target, 443
            
        except Exception:
            return None
    
    def _get_certificate_info(self, host, port):
        """Get SSL certificate information"""
        cert_info = {}
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        cert_info = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'signature_algorithm': cert.get('signatureAlgorithm'),
                            'san': cert.get('subjectAltName', []),
                            'key_size': self._get_key_size(cert_der) if cert_der else 'Unknown'
                        }
                        
                        # Check if certificate is expired
                        import datetime
                        try:
                            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            cert_info['is_expired'] = not_after < datetime.datetime.now()
                            cert_info['expires_in_days'] = (not_after - datetime.datetime.now()).days
                        except:
                            cert_info['is_expired'] = False
                            cert_info['expires_in_days'] = 'Unknown'
        
        except Exception as e:
            cert_info['error'] = str(e)
        
        return cert_info
    
    def _get_key_size(self, cert_der):
        """Extract key size from certificate"""
        try:
            # This is a simplified key size extraction
            # In practice, you'd use a proper ASN.1 parser
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            
            cert = x509.load_der_x509_certificate(cert_der)
            public_key = cert.public_key()
            
            if hasattr(public_key, 'key_size'):
                return public_key.key_size
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def _test_protocol_support(self, host, port):
        """Test SSL/TLS protocol support"""
        protocols = {}
        
        # Test different protocol versions
        test_protocols = {
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None
        }
        
        for protocol_name, protocol in test_protocols.items():
            if protocol is None:
                protocols[protocol_name] = {'supported': False, 'reason': 'Not available in Python version'}
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock) as ssock:
                        protocols[protocol_name] = {
                            'supported': True,
                            'cipher': ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                        }
            except Exception as e:
                protocols[protocol_name] = {'supported': False, 'reason': str(e)}
        
        return protocols
    
    def _get_cipher_suites(self, host, port):
        """Get supported cipher suites"""
        cipher_suites = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_suites.append({
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        })
                        
                        # Get shared ciphers if available
                        if hasattr(ssock, 'shared_ciphers'):
                            shared = ssock.shared_ciphers()
                            if shared:
                                for c in shared[:10]:  # Limit to first 10
                                    cipher_suites.append({
                                        'name': c[0],
                                        'protocol': c[1],
                                        'bits': c[2]
                                    })
        
        except Exception as e:
            cipher_suites.append({'error': str(e)})
        
        return cipher_suites
    
    def _check_vulnerabilities(self, host, port, scan_result):
        """Check for common SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Check for expired certificate
        cert_info = scan_result.get('certificate_info', {})
        if cert_info.get('is_expired'):
            vulnerabilities.append({
                'name': 'Expired Certificate',
                'severity': 'HIGH',
                'description': 'The SSL certificate has expired'
            })
        
        # Check for certificate expiring soon
        expires_in = cert_info.get('expires_in_days')
        if isinstance(expires_in, int) and expires_in < 30:
            vulnerabilities.append({
                'name': 'Certificate Expiring Soon',
                'severity': 'MEDIUM',
                'description': f'Certificate expires in {expires_in} days'
            })
        
        # Check for weak protocols
        protocols = scan_result.get('protocol_support', {})
        weak_protocols = ['SSLv3', 'TLSv1', 'TLSv1.1']
        
        for protocol in weak_protocols:
            if protocols.get(protocol, {}).get('supported'):
                vulnerabilities.append({
                    'name': f'Weak Protocol: {protocol}',
                    'severity': 'HIGH' if protocol == 'SSLv3' else 'MEDIUM',
                    'description': f'Server supports deprecated protocol {protocol}'
                })
        
        # Check for weak key size
        key_size = cert_info.get('key_size')
        if isinstance(key_size, int) and key_size < 2048:
            vulnerabilities.append({
                'name': 'Weak Key Size',
                'severity': 'HIGH',
                'description': f'Certificate uses weak key size: {key_size} bits'
            })
        
        # Check cipher suites for weak ciphers
        cipher_suites = scan_result.get('cipher_suites', [])
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1']
        
        for cipher in cipher_suites:
            if isinstance(cipher, dict) and 'name' in cipher:
                cipher_name = cipher['name'].upper()
                for weak in weak_ciphers:
                    if weak in cipher_name:
                        vulnerabilities.append({
                            'name': f'Weak Cipher: {cipher["name"]}',
                            'severity': 'MEDIUM',
                            'description': f'Server supports weak cipher suite'
                        })
                        break
        
        return vulnerabilities
    
    def _calculate_security_rating(self, scan_result):
        """Calculate overall security rating"""
        score = 100
        
        vulnerabilities = scan_result.get('vulnerabilities', [])
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity == 'HIGH':
                score -= 20
            elif severity == 'MEDIUM':
                score -= 10
            elif severity == 'LOW':
                score -= 5
        
        # Check protocol support
        protocols = scan_result.get('protocol_support', {})
        if not protocols.get('TLSv1.3', {}).get('supported'):
            score -= 5
        if not protocols.get('TLSv1.2', {}).get('supported'):
            score -= 10
        
        # Rating scale
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'

scanner = NmapScanner()
lookup_tool = IPDomainLookup()
ssl_scanner = SSLTLSScanner()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/nmap')
def nmap_scanner():
    return render_template('nmap.html')

@app.route('/lookup')
def lookup_page():
    return render_template('lookup.html')

@app.route('/ssl')
def ssl_page():
    return render_template('ssl.html')

@app.route('/lookup', methods=['POST'])
def perform_lookup():
    data = request.get_json()
    
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Generate unique lookup ID
    lookup_id = str(uuid.uuid4())
    
    # Perform lookup
    result = lookup_tool.perform_lookup(target, options)
    result['lookup_id'] = lookup_id
    
    # Store result
    lookup_results[lookup_id] = result
    
    return jsonify(result)

@app.route('/ssl', methods=['POST'])
def perform_ssl_scan():
    data = request.get_json()
    
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Generate scan ID
    ssl_scan_id = str(uuid.uuid4())
    
    # Perform SSL scan
    result = ssl_scanner.scan_ssl_tls(target, options)
    result['scan_id'] = ssl_scan_id
    
    # Store result
    ssl_scan_results[ssl_scan_id] = result
    
    return jsonify(result)

@app.route('/ssl/<ssl_scan_id>/download')
def download_ssl_result(ssl_scan_id):
    if ssl_scan_id not in ssl_scan_results:
        return jsonify({'error': 'SSL scan not found'}), 404
    
    # Create filename
    result = ssl_scan_results[ssl_scan_id]
    filename = f"ssl_scan_{result['target'].replace('/', '_').replace(':', '_')}_{ssl_scan_id[:8]}.json"
    filepath = os.path.join('scan_results', filename)
    
    # Ensure directory exists
    os.makedirs('scan_results', exist_ok=True)
    
    # Save result to file
    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/lookup/<lookup_id>/download')
def download_lookup_result(lookup_id):
    if lookup_id not in lookup_results:
        return jsonify({'error': 'Lookup not found'}), 404
    
    # Create filename
    result = lookup_results[lookup_id]
    filename = f"lookup_{result['target'].replace('/', '_')}_{lookup_id[:8]}.json"
    filepath = os.path.join('scan_results', filename)
    
    # Ensure directory exists
    os.makedirs('scan_results', exist_ok=True)
    
    # Save result to file
    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    
    target = data.get('target')
    scan_type = data.get('scan_type', 'tcp_syn')
    ports = data.get('ports', '')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Start scan in background thread
    thread = threading.Thread(
        target=scanner.run_scan,
        args=(scan_id, target, scan_type, ports, options)
    )
    thread.daemon = True
    scan_threads[scan_id] = thread
    thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/scan/<scan_id>/cancel', methods=['POST'])
def cancel_scan(scan_id):
    if scan_id in scan_status:
        scan_status[scan_id]['status'] = 'cancelled'
        scan_status[scan_id]['progress'] = scan_status[scan_id].get('progress', 0)
        
        # Clean up thread reference
        if scan_id in scan_threads:
            del scan_threads[scan_id]
        
        return jsonify({'message': 'Scan cancelled successfully'})
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/scan/<scan_id>/status')
def get_scan_status(scan_id):
    status = scan_status.get(scan_id, {'status': 'not_found'})
    return jsonify(status)

@app.route('/scan/<scan_id>/result')
def get_scan_result(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/scans')
def list_scans():
    scans = []
    for scan_id, result in scan_results.items():
        scans.append({
            'id': scan_id,
            'timestamp': result['timestamp'],
            'target': result['target'],
            'scan_type': result['scan_type'],
            'status': scan_status.get(scan_id, {}).get('status', 'unknown')
        })
    
    return jsonify(scans)

@app.route('/scan/<scan_id>/download')
def download_scan_result(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Create filename
    result = scan_results[scan_id]
    filename = f"nmap_scan_{result['target'].replace('/', '_')}_{scan_id[:8]}.json"
    
    # Ensure directory exists
    os.makedirs('scan_results', exist_ok=True)
    filepath = os.path.join('scan_results', filename)
    
    # Save result to file
    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
