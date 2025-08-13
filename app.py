# --- Web Vulnerability Scanner ---
import html

class WebVulnScanner:
    def __init__(self):
        pass

    def scan(self, url, scan_xss=True, scan_sqli=True, scan_misconfig=True):
        vulnerabilities = []
        try:
            resp = requests.get(url, timeout=10)
            content = resp.text
        except Exception as e:
            return [{'type': 'Error', 'severity': 'High', 'description': f'Could not fetch URL: {e}'}]

        # XSS check: look for reflected input in forms
        if scan_xss:
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    if inp.get('type') in [None, 'text', 'search', 'email']:
                        # Simulate reflected XSS by submitting a payload
                        action = form.get('action') or url
                        test_url = urljoin(url, action)
                        payload = '<script>alert(1)</script>'
                        data = {inp.get('name','test'): payload}
                        try:
                            r = requests.post(test_url, data=data, timeout=5)
                            if html.escape(payload) in r.text or payload in r.text:
                                vulnerabilities.append({'type': 'XSS', 'severity': 'High', 'description': f'Reflected XSS possible in form at {test_url}.'})
                        except Exception:
                            continue

        # SQLi check: look for SQL error messages
        if scan_sqli:
            sqli_payloads = ["'", '"', ' OR 1=1--', ' OR "1"="1"--']
            for payload in sqli_payloads:
                try:
                    r = requests.get(url, params={'id': payload}, timeout=5)
                    if any(err in r.text.lower() for err in ['sql syntax', 'mysql', 'syntax error', 'unclosed quotation mark', 'sqlite', 'pg_query']):
                        vulnerabilities.append({'type': 'SQL Injection', 'severity': 'High', 'description': f'SQL error detected with payload {payload}.'})
                        break
                except Exception:
                    continue

        # Misconfiguration check: look for .git, .env, admin, backup files
        if scan_misconfig:
            paths = ['/.git/', '/.env', '/admin', '/backup', '/phpinfo.php']
            for path in paths:
                try:
                    r = requests.get(urljoin(url, path), timeout=5)
                    if r.status_code == 200 and len(r.text) > 20:
                        vulnerabilities.append({'type': 'Misconfiguration', 'severity': 'Medium', 'description': f'Accessible sensitive path: {path}'})
                except Exception:
                    continue

        return vulnerabilities

# Flask routes for vuln scanner
@app.route('/vulnscan', methods=['GET'])
def vulnscan_ui():
    return render_template('vulnscan.html')

@app.route('/vulnscan', methods=['POST'])
def vulnscan_api():
    data = request.get_json()
    url = data.get('targetUrl')
    scan_xss = data.get('scan_xss', True)
    scan_sqli = data.get('scan_sqli', True)
    scan_misconfig = data.get('scan_misconfig', True)
    scanner = WebVulnScanner()
    vulns = scanner.scan(url, scan_xss, scan_sqli, scan_misconfig)
    return jsonify({'vulnerabilities': vulns})
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
from urllib.parse import urlparse, urljoin, quote
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from collections import deque, defaultdict
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype

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

# Store web crawler results
crawler_results = {}

# Store DNS toolkit results
dns_results = {}

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

class WebCrawler:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ShadowScan WebCrawler/1.0 (Security Scanner)'
        })
        self.common_directories = [
            'admin', 'administrator', 'wp-admin', 'login', 'dashboard', 'control',
            'manager', 'api', 'config', 'backup', 'uploads', 'files', 'download',
            'images', 'css', 'js', 'scripts', 'assets', 'static', 'public',
            'private', 'secure', 'hidden', 'test', 'dev', 'staging', 'beta',
            'old', 'new', 'tmp', 'temp', 'cache', 'logs', 'log', 'data',
            'db', 'database', 'sql', 'phpmyadmin', 'mysql', 'postgres',
            'ftp', 'mail', 'email', 'webmail', 'www', 'web', 'site'
        ]
        self.common_files = [
            'robots.txt', 'sitemap.xml', 'sitemap.txt', '.htaccess', 'web.config',
            'crossdomain.xml', 'clientaccesspolicy.xml', 'humans.txt',
            'readme.txt', 'readme.html', 'changelog.txt', 'license.txt',
            'config.php', 'config.xml', 'settings.php', 'wp-config.php',
            'database.php', 'db.php', 'connect.php', 'connection.php',
            'install.php', 'setup.php', 'phpinfo.php', 'info.php',
            'test.php', 'debug.php', 'admin.php', 'login.php',
            'index.bak', 'backup.sql', 'dump.sql', 'database.sql'
        ]
    
    def crawl_website(self, target_url, options):
        """Perform comprehensive web crawling and directory discovery"""
        start_time = time.time()
        
        # Validate and normalize URL
        parsed_url = self._normalize_url(target_url)
        if not parsed_url:
            return {'error': 'Invalid URL format'}
        
        result = {
            'timestamp': datetime.datetime.now().isoformat(),
            'target_url': target_url,
            'base_url': f"{parsed_url.scheme}://{parsed_url.netloc}",
            'response_time_ms': 0,
            'discovered_urls': [],
            'directory_bruteforce': [],
            'file_discovery': [],
            'robots_txt': {},
            'sitemap': [],
            'forms': [],
            'technologies': [],
            'security_headers': {},
            'cookies': [],
            'status_summary': defaultdict(int),
            'crawl_statistics': {}
        }
        
        try:
            base_url = result['base_url']
            
            # Check robots.txt
            if options.get('check_robots', True):
                result['robots_txt'] = self._check_robots_txt(base_url)
            
            # Check sitemap
            if options.get('check_sitemap', True):
                result['sitemap'] = self._check_sitemap(base_url)
            
            # Directory bruteforce
            if options.get('directory_bruteforce', True):
                max_dirs = options.get('max_directories', 20)
                result['directory_bruteforce'] = self._directory_bruteforce(base_url, max_dirs)
            
            # File discovery
            if options.get('file_discovery', True):
                max_files = options.get('max_files', 15)
                result['file_discovery'] = self._file_discovery(base_url, max_files)
            
            # Web crawling (follow links)
            if options.get('crawl_links', True):
                max_depth = options.get('max_depth', 2)
                max_urls = options.get('max_urls', 50)
                crawl_result = self._crawl_links(target_url, max_depth, max_urls)
                result.update(crawl_result)
            
            # Analyze security headers for main page
            result['security_headers'] = self._analyze_security_headers(target_url)
            
            # Generate statistics
            result['crawl_statistics'] = {
                'total_urls_found': len(result['discovered_urls']),
                'total_directories_found': len([d for d in result['directory_bruteforce'] if d.get('status') == 200]),
                'total_files_found': len([f for f in result['file_discovery'] if f.get('status') == 200]),
                'forms_found': len(result['forms']),
                'technologies_detected': len(result['technologies'])
            }
            
        except Exception as e:
            result['error'] = str(e)
        
        result['response_time_ms'] = int((time.time() - start_time) * 1000)
        return result
    
    def _normalize_url(self, url):
        """Normalize and validate URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            
            return parsed
        except Exception:
            return None
    
    def _check_robots_txt(self, base_url):
        """Check robots.txt file"""
        robots_info = {'exists': False, 'disallowed_paths': [], 'allowed_paths': [], 'sitemaps': []}
        
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                robots_info['exists'] = True
                robots_info['content'] = response.text[:1000]  # Limit content size
                
                # Parse robots.txt
                rp = RobotFileParser()
                rp.set_url(robots_url)
                rp.read()
                
                # Extract disallowed paths
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            robots_info['disallowed_paths'].append(path)
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            robots_info['allowed_paths'].append(path)
                    elif line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        if sitemap_url:
                            robots_info['sitemaps'].append(sitemap_url)
        
        except Exception as e:
            robots_info['error'] = str(e)
        
        return robots_info
    
    def _check_sitemap(self, base_url):
        """Check for sitemap files"""
        sitemaps = []
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap.txt',
            '/sitemap/sitemap.xml',
            '/sitemaps.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(base_url, sitemap_path)
                response = self.session.get(sitemap_url, timeout=10)
                
                if response.status_code == 200:
                    sitemap_info = {
                        'url': sitemap_url,
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'size': len(response.content),
                        'urls': []
                    }
                    
                    # Extract URLs from XML sitemap
                    if 'xml' in sitemap_path.lower():
                        try:
                            from xml.etree import ElementTree as ET
                            root = ET.fromstring(response.content)
                            for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                                loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                                if loc_elem is not None and loc_elem.text:
                                    sitemap_info['urls'].append(loc_elem.text)
                        except:
                            pass
                    
                    sitemaps.append(sitemap_info)
            
            except Exception:
                continue
        
        return sitemaps
    
    def _directory_bruteforce(self, base_url, max_directories):
        """Bruteforce common directories"""
        results = []
        
        def check_directory(directory):
            try:
                dir_url = urljoin(base_url, f'/{directory}/')
                response = self.session.get(dir_url, timeout=5, allow_redirects=False)
                
                return {
                    'directory': directory,
                    'url': dir_url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'server': response.headers.get('server', '')
                }
            except Exception as e:
                return {
                    'directory': directory,
                    'url': urljoin(base_url, f'/{directory}/'),
                    'status': 0,
                    'error': str(e)
                }
        
        # Use threading for faster directory bruteforce
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            directories_to_check = self.common_directories[:max_directories]
            future_to_dir = {executor.submit(check_directory, directory): directory 
                           for directory in directories_to_check}
            
            for future in concurrent.futures.as_completed(future_to_dir):
                result = future.result()
                results.append(result)
        
        # Sort by status code (interesting responses first)
        results.sort(key=lambda x: (x.get('status', 999) not in [200, 301, 302, 403], x.get('status', 999)))
        return results
    
    def _file_discovery(self, base_url, max_files):
        """Discover common files"""
        results = []
        
        def check_file(filename):
            try:
                file_url = urljoin(base_url, f'/{filename}')
                response = self.session.get(file_url, timeout=5)
                
                return {
                    'filename': filename,
                    'url': file_url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', ''),
                    'last_modified': response.headers.get('last-modified', '')
                }
            except Exception as e:
                return {
                    'filename': filename,
                    'url': urljoin(base_url, f'/{filename}'),
                    'status': 0,
                    'error': str(e)
                }
        
        # Use threading for faster file discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            files_to_check = self.common_files[:max_files]
            future_to_file = {executor.submit(check_file, filename): filename 
                            for filename in files_to_check}
            
            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                results.append(result)
        
        # Sort by status code (successful responses first)
        results.sort(key=lambda x: x.get('status', 999) != 200)
        return results
    
    def _crawl_links(self, start_url, max_depth, max_urls):
        """Crawl website following links"""
        visited = set()
        to_visit = deque([(start_url, 0)])
        discovered_urls = []
        forms = []
        technologies = set()
        
        while to_visit and len(discovered_urls) < max_urls:
            url, depth = to_visit.popleft()
            
            if url in visited or depth > max_depth:
                continue
            
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    discovered_urls.append({
                        'url': url,
                        'status': response.status_code,
                        'title': '',
                        'depth': depth,
                        'size': len(response.content),
                        'content_type': response.headers.get('content-type', '')
                    })
                    
                    # Parse HTML content
                    if 'text/html' in response.headers.get('content-type', ''):
                        soup = BeautifulSoup(response.content, 'html.parser')
                        
                        # Extract title
                        title_tag = soup.find('title')
                        if title_tag:
                            discovered_urls[-1]['title'] = title_tag.get_text().strip()[:100]
                        
                        # Find forms
                        for form in soup.find_all('form'):
                            form_info = {
                                'url': url,
                                'action': form.get('action', ''),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': []
                            }
                            
                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                input_info = {
                                    'type': input_tag.get('type', 'text'),
                                    'name': input_tag.get('name', ''),
                                    'id': input_tag.get('id', '')
                                }
                                form_info['inputs'].append(input_info)
                            
                            forms.append(form_info)
                        
                        # Detect technologies
                        self._detect_technologies(response, soup, technologies)
                        
                        # Find more links to follow
                        if depth < max_depth:
                            base_domain = urlparse(start_url).netloc
                            for link in soup.find_all('a', href=True):
                                next_url = urljoin(url, link['href'])
                                parsed_next = urlparse(next_url)
                                
                                # Only follow links within the same domain
                                if parsed_next.netloc == base_domain and next_url not in visited:
                                    to_visit.append((next_url, depth + 1))
            
            except Exception:
                continue
        
        return {
            'discovered_urls': discovered_urls,
            'forms': forms,
            'technologies': list(technologies)
        }
    
    def _detect_technologies(self, response, soup, technologies):
        """Detect web technologies"""
        headers = response.headers
        
        # Server detection
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.add('Apache')
        elif 'nginx' in server:
            technologies.add('Nginx')
        elif 'iis' in server:
            technologies.add('IIS')
        
        # Framework detection
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            technologies.add(f"Powered by: {powered_by}")
        
        # Content analysis
        html_content = str(soup).lower()
        
        # Popular frameworks/CMS
        if 'wordpress' in html_content or 'wp-content' in html_content:
            technologies.add('WordPress')
        if 'drupal' in html_content:
            technologies.add('Drupal')
        if 'joomla' in html_content:
            technologies.add('Joomla')
        if 'react' in html_content:
            technologies.add('React')
        if 'angular' in html_content:
            technologies.add('Angular')
        if 'vue' in html_content:
            technologies.add('Vue.js')
        if 'bootstrap' in html_content:
            technologies.add('Bootstrap')
        if 'jquery' in html_content:
            technologies.add('jQuery')
    
    def _analyze_security_headers(self, url):
        """Analyze security headers"""
        headers_info = {}
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'X-Frame-Options',
                'X-XSS-Protection': 'XSS Protection',
                'X-Content-Type-Options': 'Content Type Options',
                'Strict-Transport-Security': 'HSTS',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }
            
            for header, friendly_name in security_headers.items():
                if header in headers:
                    headers_info[friendly_name] = {
                        'present': True,
                        'value': headers[header]
                    }
                else:
                    headers_info[friendly_name] = {
                        'present': False,
                        'recommendation': f'{header} header missing'
                    }
            
            # Check cookies
            cookies = []
            for cookie in response.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': hasattr(cookie, 'httponly') and cookie.httponly,
                    'samesite': getattr(cookie, 'samesite', None)
                }
                cookies.append(cookie_info)
            
            headers_info['cookies'] = cookies
        
        except Exception as e:
            headers_info['error'] = str(e)
        
        return headers_info

class DNSToolkit:
    def __init__(self):
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 
            'cdn', 'blog', 'shop', 'store', 'secure', 'portal', 'webmail',
            'mx', 'ns', 'ns1', 'ns2', 'dns', 'pop', 'imap', 'smtp', 'vpn',
            'remote', 'support', 'help', 'app', 'mobile', 'old', 'new',
            'beta', 'alpha', 'demo', 'sandbox', 'forum', 'chat', 'wiki',
            'm', 'mobile', 'wap', 'video', 'images', 'img', 'static', 'assets'
        ]
        self.dns_servers = [
            '8.8.8.8',        # Google
            '8.8.4.4',        # Google
            '1.1.1.1',        # Cloudflare
            '1.0.0.1',        # Cloudflare
            '208.67.222.222', # OpenDNS
            '208.67.220.220'  # OpenDNS
        ]
    
    def comprehensive_dns_analysis(self, domain, options):
        """Perform comprehensive DNS analysis"""
        start_time = time.time()
        
        # Validate domain
        if not self._is_valid_domain(domain):
            return {'error': 'Invalid domain format'}
        
        result = {
            'timestamp': datetime.datetime.now().isoformat(),
            'domain': domain,
            'response_time_ms': 0,
            'dns_records': {},
            'zone_transfer': {},
            'subdomain_enumeration': [],
            'dns_security': {},
            'nameservers': [],
            'dns_propagation': {},
            'reverse_dns': {},
            'dns_history': {}
        }
        
        try:
            # Basic DNS records lookup
            if options.get('lookup_records', True):
                result['dns_records'] = self._lookup_dns_records(domain)
            
            # Nameserver analysis
            if options.get('analyze_nameservers', True):
                result['nameservers'] = self._analyze_nameservers(domain)
            
            # Zone transfer attempt
            if options.get('attempt_zone_transfer', True):
                result['zone_transfer'] = self._attempt_zone_transfer(domain, result['nameservers'])
            
            # Subdomain enumeration
            if options.get('enumerate_subdomains', True):
                max_subdomains = options.get('max_subdomains', 20)
                result['subdomain_enumeration'] = self._enumerate_subdomains(domain, max_subdomains)
            
            # DNS security analysis
            if options.get('security_analysis', True):
                result['dns_security'] = self._analyze_dns_security(domain)
            
            # DNS propagation check
            if options.get('check_propagation', True):
                result['dns_propagation'] = self._check_dns_propagation(domain)
            
            # Reverse DNS lookup
            if options.get('reverse_dns', True):
                result['reverse_dns'] = self._reverse_dns_lookup(domain)
            
        except Exception as e:
            result['error'] = str(e)
        
        result['response_time_ms'] = int((time.time() - start_time) * 1000)
        return result
    
    def _is_valid_domain(self, domain):
        """Validate domain format"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
    
    def _lookup_dns_records(self, domain):
        """Lookup various DNS record types"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                
                answers = resolver.resolve(domain, record_type)
                records[record_type] = []
                
                for answer in answers:
                    record_data = {
                        'value': str(answer),
                        'ttl': answers.ttl if hasattr(answers, 'ttl') else 'Unknown'
                    }
                    
                    # Add specific data for MX records
                    if record_type == 'MX':
                        record_data['priority'] = answer.preference
                        record_data['exchange'] = str(answer.exchange)
                    
                    # Add specific data for SOA records
                    elif record_type == 'SOA':
                        record_data['mname'] = str(answer.mname)
                        record_data['rname'] = str(answer.rname)
                        record_data['serial'] = answer.serial
                        record_data['refresh'] = answer.refresh
                        record_data['retry'] = answer.retry
                        record_data['expire'] = answer.expire
                        record_data['minimum'] = answer.minimum
                    
                    records[record_type].append(record_data)
                    
            except dns.resolver.NXDOMAIN:
                records[record_type] = {'error': 'Domain not found'}
            except dns.resolver.NoAnswer:
                records[record_type] = {'error': 'No records found'}
            except Exception as e:
                records[record_type] = {'error': str(e)}
        
        return records
    
    def _analyze_nameservers(self, domain):
        """Analyze domain nameservers"""
        nameservers = []
        
        try:
            resolver = dns.resolver.Resolver()
            ns_records = resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_name = str(ns).rstrip('.')
                ns_info = {
                    'nameserver': ns_name,
                    'ip_addresses': [],
                    'response_time': 0
                }
                
                # Get IP addresses for nameserver
                try:
                    ns_start = time.time()
                    ns_resolver = dns.resolver.Resolver()
                    ns_resolver.nameservers = [socket.gethostbyname(ns_name)]
                    
                    # Test response time
                    test_query = ns_resolver.resolve(domain, 'A')
                    ns_info['response_time'] = int((time.time() - ns_start) * 1000)
                    
                    # Get IP addresses
                    a_records = dns.resolver.resolve(ns_name, 'A')
                    for a in a_records:
                        ns_info['ip_addresses'].append(str(a))
                        
                except Exception as e:
                    ns_info['error'] = str(e)
                
                nameservers.append(ns_info)
                
        except Exception as e:
            return {'error': str(e)}
        
        return nameservers
    
    def _attempt_zone_transfer(self, domain, nameservers):
        """Attempt DNS zone transfer"""
        zone_transfer = {'attempted': [], 'successful': [], 'failed': []}
        
        if isinstance(nameservers, dict) and 'error' in nameservers:
            return {'error': 'No nameservers available'}
        
        for ns_info in nameservers[:3]:  # Try first 3 nameservers
            ns_name = ns_info['nameserver']
            zone_transfer['attempted'].append(ns_name)
            
            try:
                # Get IP address of nameserver
                ns_ip = socket.gethostbyname(ns_name)
                
                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                
                # Zone transfer successful
                transfer_result = {
                    'nameserver': ns_name,
                    'ip': ns_ip,
                    'records_count': len(zone.nodes),
                    'records': []
                }
                
                # Extract some records (limit to prevent huge responses)
                for name, node in list(zone.nodes.items())[:50]:
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            transfer_result['records'].append({
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'value': str(rdata)
                            })
                
                zone_transfer['successful'].append(transfer_result)
                
            except Exception as e:
                zone_transfer['failed'].append({
                    'nameserver': ns_name,
                    'error': str(e)
                })
        
        return zone_transfer
    
    def _enumerate_subdomains(self, domain, max_subdomains):
        """Enumerate subdomains using common names"""
        subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                
                answers = resolver.resolve(full_domain, 'A')
                ips = [str(answer) for answer in answers]
                
                return {
                    'subdomain': full_domain,
                    'ip_addresses': ips,
                    'found': True
                }
            except Exception:
                return {
                    'subdomain': f"{subdomain}.{domain}",
                    'found': False
                }
        
        # Use threading for faster subdomain enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            subdomains_to_check = self.common_subdomains[:max_subdomains]
            future_to_subdomain = {executor.submit(check_subdomain, sub): sub 
                                 for sub in subdomains_to_check}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result['found']:
                    subdomains.append(result)
        
        return subdomains
    
    def _analyze_dns_security(self, domain):
        """Analyze DNS security features"""
        security = {
            'dnssec': {'enabled': False, 'details': {}},
            'caa_records': [],
            'spf_record': {},
            'dmarc_record': {},
            'dkim_records': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            
            # Check DNSSEC
            try:
                # Try to get DNSKEY record
                dnskey_answers = resolver.resolve(domain, 'DNSKEY')
                security['dnssec']['enabled'] = True
                security['dnssec']['details']['dnskey_count'] = len(dnskey_answers)
                
                # Try to get DS record from parent zone
                try:
                    ds_answers = resolver.resolve(domain, 'DS')
                    security['dnssec']['details']['ds_records'] = len(ds_answers)
                except:
                    pass
                    
            except:
                security['dnssec']['enabled'] = False
            
            # Check CAA records
            try:
                caa_answers = resolver.resolve(domain, 'CAA')
                for caa in caa_answers:
                    security['caa_records'].append({
                        'flags': caa.flags,
                        'tag': caa.tag,
                        'value': caa.value.decode('utf-8') if isinstance(caa.value, bytes) else str(caa.value)
                    })
            except:
                pass
            
            # Check SPF record
            try:
                txt_answers = resolver.resolve(domain, 'TXT')
                for txt in txt_answers:
                    txt_value = str(txt).strip('"')
                    if txt_value.startswith('v=spf1'):
                        security['spf_record'] = {
                            'found': True,
                            'record': txt_value,
                            'mechanisms': txt_value.split()[1:] if len(txt_value.split()) > 1 else []
                        }
                        break
                else:
                    security['spf_record'] = {'found': False}
            except:
                security['spf_record'] = {'found': False, 'error': 'Query failed'}
            
            # Check DMARC record
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
                for txt in dmarc_answers:
                    txt_value = str(txt).strip('"')
                    if txt_value.startswith('v=DMARC1'):
                        security['dmarc_record'] = {
                            'found': True,
                            'record': txt_value
                        }
                        break
                else:
                    security['dmarc_record'] = {'found': False}
            except:
                security['dmarc_record'] = {'found': False, 'error': 'Query failed'}
                
        except Exception as e:
            security['error'] = str(e)
        
        return security
    
    def _check_dns_propagation(self, domain):
        """Check DNS propagation across different servers"""
        propagation = {}
        
        for dns_server in self.dns_servers[:4]:  # Check first 4 DNS servers
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 5
                
                start_time = time.time()
                answers = resolver.resolve(domain, 'A')
                response_time = int((time.time() - start_time) * 1000)
                
                propagation[dns_server] = {
                    'server_name': self._get_dns_server_name(dns_server),
                    'response_time': response_time,
                    'ip_addresses': [str(answer) for answer in answers],
                    'status': 'success'
                }
                
            except Exception as e:
                propagation[dns_server] = {
                    'server_name': self._get_dns_server_name(dns_server),
                    'status': 'failed',
                    'error': str(e)
                }
        
        return propagation
    
    def _get_dns_server_name(self, ip):
        """Get friendly name for DNS server"""
        dns_names = {
            '8.8.8.8': 'Google DNS',
            '8.8.4.4': 'Google DNS',
            '1.1.1.1': 'Cloudflare DNS',
            '1.0.0.1': 'Cloudflare DNS',
            '208.67.222.222': 'OpenDNS',
            '208.67.220.220': 'OpenDNS'
        }
        return dns_names.get(ip, f'DNS Server ({ip})')
    
    def _reverse_dns_lookup(self, domain):
        """Perform reverse DNS lookup"""
        reverse_dns = {}
        
        try:
            # First get IP addresses
            resolver = dns.resolver.Resolver()
            a_records = resolver.resolve(domain, 'A')
            
            for a_record in a_records:
                ip = str(a_record)
                try:
                    # Perform reverse DNS lookup
                    reverse_name = socket.gethostbyaddr(ip)[0]
                    reverse_dns[ip] = {
                        'reverse_name': reverse_name,
                        'matches_original': reverse_name.lower() == domain.lower()
                    }
                except Exception as e:
                    reverse_dns[ip] = {
                        'error': str(e),
                        'reverse_name': None
                    }
                    
        except Exception as e:
            reverse_dns['error'] = str(e)
        
        return reverse_dns

scanner = NmapScanner()
lookup_tool = IPDomainLookup()
ssl_scanner = SSLTLSScanner()
web_crawler = WebCrawler()
dns_toolkit = DNSToolkit()

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

@app.route('/crawler')
def crawler_page():
    return render_template('crawler.html')

@app.route('/crawler', methods=['POST'])
def perform_crawl():
    data = request.get_json()
    
    target_url = data.get('target_url')
    options = data.get('options', {})
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    # Generate crawl ID
    crawl_id = str(uuid.uuid4())
    
    # Perform web crawl
    result = web_crawler.crawl_website(target_url, options)
    result['crawl_id'] = crawl_id
    
    # Store result
    crawler_results[crawl_id] = result
    
    return jsonify(result)

@app.route('/crawler/<crawl_id>/download')
def download_crawler_result(crawl_id):
    if crawl_id not in crawler_results:
        return jsonify({'error': 'Crawl result not found'}), 404
    
    # Create filename
    result = crawler_results[crawl_id]
    target_clean = result['target_url'].replace('://', '_').replace('/', '_').replace(':', '_')
    filename = f"crawler_{target_clean}_{crawl_id[:8]}.json"
    filepath = os.path.join('scan_results', filename)
    
    # Ensure directory exists
    os.makedirs('scan_results', exist_ok=True)
    
    # Save result to file
    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2)
    
    return send_file(filepath, as_attachment=True, download_name=filename)

@app.route('/dns')
def dns_page():
    return render_template('dns.html')

@app.route('/dns', methods=['POST'])
def perform_dns_analysis():
    data = request.get_json()
    
    domain = data.get('domain')
    options = data.get('options', {})
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Generate DNS analysis ID
    dns_id = str(uuid.uuid4())
    
    # Perform DNS analysis
    result = dns_toolkit.comprehensive_dns_analysis(domain, options)
    result['dns_id'] = dns_id
    
    # Store result
    dns_results[dns_id] = result
    
    return jsonify(result)

@app.route('/dns/<dns_id>/download')
def download_dns_result(dns_id):
    if dns_id not in dns_results:
        return jsonify({'error': 'DNS analysis not found'}), 404
    
    # Create filename
    result = dns_results[dns_id]
    domain_clean = result['domain'].replace('.', '_')
    filename = f"dns_analysis_{domain_clean}_{dns_id[:8]}.json"
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
