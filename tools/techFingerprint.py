import os
import socket as st
import ssl
import asyncio
import aiohttp
import aiodns
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from collections import defaultdict
import re
import json
from tqdm import tqdm
from scapy.all import sr1, IP, TCP, conf
import argparse
from threading import Lock
import random
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import multiprocessing

# Thread-safe list for open ports
open_ports = []
ports_lock = Lock()


def output_to_file(text):
    """Log text to a file."""
    with open('port_scanner_debug_log.txt', 'a', encoding='utf-8') as f:
        f.write(text + '\n')


def parse_banner(banner: str) -> Dict[str, str]:
    """Parse HTTP headers from banner."""
    headers = defaultdict(str)
    if banner:
        lines = banner.split('\r\n')
        in_headers = True
        for line in lines:
            if not line.strip() and in_headers:  # End of headers
                in_headers = False
                continue
            if in_headers and ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
    return dict(headers)


def check_privileges() -> bool:
    """Check if running with root privileges."""
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: OS fingerprinting requires root privileges. Using fallback.")
        return False
    return True

async def analyze_ssl_tls(domain: str, port: int) -> Dict[str, any]:
    """Enhanced SSL/TLS analysis with cipher suites, chain validation, and HSTS."""
    result = {
        'supported_protocols': [],
        'cipher_suites': [],
        'weak_ciphers': [],
        'certificate_info': {},
        'certificate_chain_valid': False,
        'hsts': False,
        'errors': []
    }
    weak_ciphers = {'EXP', 'NULL', 'DES', 'RC4', 'MD5', '3DES'}
    protocols = {
        "TLSv1": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        "TLSv1.3": ssl.PROTOCOL_TLS
    }

    for proto_name, proto in protocols.items():
        try:
            context = ssl.SSLContext(proto)
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(st.create_connection((domain, port)), server_hostname=domain) as sock:
                result['supported_protocols'].append(proto_name)
                cipher = sock.cipher()
                if cipher:
                    result['cipher_suites'].append(cipher[0])
                    if any(w in cipher[0] for w in weak_ciphers):
                        result['weak_ciphers'].append(cipher[0])
        except Exception as e:
            result['errors'].append(f"{proto_name} not supported: {e}")

    if port in [443]:
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(st.create_connection((domain, port)), server_hostname=domain) as sock:
                cert = sock.getpeercert(binary_form=True)
                if cert:
                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                    result['certificate_info'] = {
                        "issuer": cert_obj.issuer.rfc4514_string(),
                        "subject": cert_obj.subject.rfc4514_string(),
                        "valid_from": cert_obj.not_valid_before.isoformat(),
                        "valid_to": cert_obj.not_valid_after.isoformat()
                    }
                    # Certificate chain validation
                    pem_cert = ssl.get_server_certificate((domain, port))
                    result['certificate_chain_valid'] = True  # Simplified; use OpenSSL for full chain check
            # HSTS check via HTTP request
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}") as resp:
                    if 'strict-transport-security' in resp.headers:
                        result['hsts'] = True
        except Exception as e:
            result['errors'].append(f"SSL analysis failed: {e}")

    return result


def detect_os_fingerprint(ip: str, port: int) -> Dict[str, float]:
    """Perform OS fingerprinting using Scapy with fallback."""
    os_info = {'os': 'Unknown', 'confidence': 0.0}
    if not check_privileges():
        return os_info

    try:
        conf.verb = 0  # Suppress Scapy output
        pkt = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=2, retry=2)
        if pkt and pkt.haslayer(TCP) and pkt[TCP].flags == 0x12:  # SYN-ACK
            tcp_options = pkt[TCP].options
            window_size = pkt[TCP].window
            ttl = pkt[IP].ttl

            if ttl <= 64 and window_size in [5840, 65535]:
                os_info['os'] = "Linux/Unix"
                os_info['confidence'] = 0.8
            elif ttl <= 128 and window_size in [8192, 64240]:
                os_info['os'] = "Windows"
                os_info['confidence'] = 0.7
            elif ttl <= 32 and window_size == 16384:
                os_info['os'] = "Cisco IOS"
                os_info['confidence'] = 0.6

            for opt in tcp_options:
                opt_name = str(opt[0])
                if opt_name == "WScale" and ttl <= 64:
                    os_info['os'] = "Linux/Unix"
                    os_info['confidence'] = max(os_info['confidence'], 0.9)
                elif opt_name == "MSS" and ttl <= 128:
                    os_info['os'] = "Windows"
                    os_info['confidence'] = max(os_info['confidence'], 0.8)
    except Exception as e:
        os_info['error'] = f"OS fingerprinting error: {e}"
    return os_info


def detect_cdn(headers: Dict[str, str], domain: str) -> Dict[str, str]:
    """Detect CDN using headers, NS, and CNAME records."""
    result = {'cdn': 'Not detected', 'behind_cdn': False}
    headers = {k.lower(): v.lower() for k, v in headers.items()}
    
    # CDN detection
    if "cf-ray" in headers: result['cdn'], result['behind_cdn'] = "Cloudflare", True
    elif "x-amzn-cdn-id" in headers: result['cdn'], result['behind_cdn'] = "Amazon CloudFront", True
    elif "x-akamai-transformed" in headers: result['cdn'], result['behind_cdn'] = "Akamai", True
    elif "x-cache" in headers and "fastly" in headers.get('x-served-by', ''): result['cdn'], result['behind_cdn'] = "Fastly", True

    # WAF detection
    if "x-sucuri-id" in headers: result['waf'] = "Sucuri"
    elif "x-waf" in headers or "protected by" in headers.get('server', ''): result['waf'] = "Generic WAF"
    elif "cloudflare" in headers.get('server', '') and "cf-ray" in headers: result['waf'] = "Cloudflare WAF"

    # DNS-based detection
    try:
        ns_records = [str(r).lower() for r in dns.resolver.resolve(domain, 'NS')]
        if any("cloudflare" in ns for ns in ns_records): result['cdn'], result['behind_cdn'] = "Cloudflare (DNS)", True
    except Exception:
        pass
    return result


def detect_web_tech(banner: str, headers: Dict[str, str], domain: str, port: int) -> Dict[str, str]:
    """Detect web technologies based on banner, headers, and optional HTML content."""
    tech_info = {'web_tech': 'Unknown', 'version': 'N/A'}

    # Normalize headers for case-insensitive matching
    headers = {k.lower(): v.lower() for k, v in headers.items()}
    banner_lower = banner.lower()

    # Web server detection (expanded from existing logic)
    server = headers.get('server', '')
    if "apache" in server:
        tech_info['web_tech'] = "Apache"
        version_match = re.search(r'apache/([\d.]+)', server)
        tech_info['version'] = version_match.group(1) if version_match else "N/A"
    elif "nginx" in server:
        tech_info['web_tech'] = "Nginx"
        version_match = re.search(r'nginx/([\d.]+)', server)
        tech_info['version'] = version_match.group(1) if version_match else "N/A"
    elif "iis" in server or "microsoft-iis" in server:
        tech_info['web_tech'] = "Microsoft IIS"
        version_match = re.search(r'microsoft-iis/([\d.]+)', server)
        tech_info['version'] = version_match.group(1) if version_match else "N/A"
    elif "litespeed" in server:
        tech_info['web_tech'] = "LiteSpeed"
        version_match = re.search(r'litespeed/([\d.]+)', server)
        tech_info['version'] = version_match.group(1) if version_match else "N/A"

    # Framework/CMS detection via headers
    if "x-powered-by" in headers:
        powered_by = headers['x-powered-by']
        if "php" in powered_by:
            tech_info['web_tech'] = "PHP"
            version_match = re.search(r'php/([\d.]+)', powered_by)
            tech_info['version'] = version_match.group(1) if version_match else "N/A"
        elif "asp.net" in powered_by:
            tech_info['web_tech'] = "ASP.NET"
            version_match = re.search(r'asp.net/([\d.]+)', powered_by)
            tech_info['version'] = version_match.group(1) if version_match else "N/A"

    # CMS detection via banner or additional request
    if "wordpress" in banner_lower or "wp-content" in banner_lower:
        tech_info['web_tech'] = "WordPress"
    elif "drupal" in banner_lower:
        tech_info['web_tech'] = "Drupal"
    elif "joomla" in banner_lower:
        tech_info['web_tech'] = "Joomla"

    # Optional: Fetch HTML for deeper inspection (e.g., CMS detection)
    if tech_info['web_tech'] == 'Unknown' and port in [80, 443]:
        try:
            soc = st.socket(st.AF_INET, st.SOCK_STREAM)
            if port == 443:
                context = ssl.create_default_context()
                soc = context.wrap_socket(soc, server_hostname=domain)
            soc.connect((domain, port))
            soc.send(f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
            response = soc.recv(4096).decode('utf-8', errors='ignore')
            soc.close()
            if "wp-content" in response.lower():
                tech_info['web_tech'] = "WordPress"
            elif "drupal" in response.lower():
                tech_info['web_tech'] = "Drupal"
            elif "joomla" in response.lower():
                tech_info['web_tech'] = "Joomla"
            elif "django" in response.lower():
                tech_info['web_tech'] = "Django"
            elif "ruby on rails" in response.lower():
                tech_info['web_tech'] = "Ruby on Rails"
        except Exception:
            pass  # Silently skip if additional request fails

    return tech_info

def detect_service_and_os(ip: str, port: int, domain: str, timeout: float = 1.0) -> Dict[str, Optional[str]]:
    """Detect service, version, OS, CDN, and web technologies."""
    service_info = {
        'port': port,
        'service': 'Unknown',
        'version': 'N/A',
        'os': 'Unknown',
        'confidence': 0.0,
        'banner': '',
        'headers': {},
        'ttl': None,
        'cdn': 'Not detected',
        'web_tech': 'Unknown',
        'web_tech_version': 'N/A',
        'error': None
    }

    try:
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        st.setdefaulttimeout(timeout)
        soc = st.socket(st.AF_INET, st.SOCK_STREAM)

        if port == 443:
            context = ssl.create_default_context()
            soc = context.wrap_socket(soc, server_hostname=domain)
            pkt = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=2, verbose=0)
            if pkt and pkt.haslayer(IP):
                service_info['ttl'] = pkt[IP].ttl
        else:
            soc.setsockopt(st.IPPROTO_IP, st.IP_TTL, 255)

        soc.connect((ip, port))
        if port != 443:
            service_info['ttl'] = soc.getsockopt(st.IPPROTO_IP, st.IP_TTL)

        # Protocol-specific probes
        probes = {
            80: f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n",
            443: f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n",
            21: "USER anonymous\r\n",
            22: "SSH-2.0-OpenSSH_7.4\r\n",
            25: "HELO test\r\n",
            3306: "SELECT @@version\r\n"  # MySQL
        }
        soc.send(probes.get(port, "HELLO\r\n").encode())
        banner = soc.recv(2048).decode('utf-8', errors='ignore')
        soc.close()

        service_info['banner'] = banner.strip()
        service_info['headers'] = parse_banner(banner)
        cdn_info = detect_cdn(service_info['headers'], domain)
        service_info['cdn'] = cdn_info['cdn']

        # Service detection (unchanged)
        if "SSH" in banner:
            service_info['service'] = "SSH"
            version_match = re.search(r'OpenSSH_([\d.]+)', banner)
            service_info['version'] = version_match.group(1) if version_match else "Unknown"
        elif "HTTP" in banner:
            service_info['service'] = "HTTP" if port == 80 else "HTTPS"
            server = service_info['headers'].get('server', '').lower()
            if "apache" in server:
                version_match = re.search(r'apache/([\d.]+)', server)
                service_info['version'] = version_match.group(1) if version_match else "Unknown"
            elif "nginx" in server:
                version_match = re.search(r'nginx/([\d.]+)', server)
                service_info['version'] = version_match.group(1) if version_match else "Unknown"
        elif "FTP" in banner or "220" in banner:
            service_info['service'] = "FTP"
        elif "SMTP" in banner or "250" in banner:
            service_info['service'] = "SMTP"
        elif "mysql" in banner.lower():
            service_info['service'] = "MySQL"
            version_match = re.search(r'([\d.]+)', banner)
            service_info['version'] = version_match.group(1) if version_match else "Unknown"
        else:
            service_info['service'] = st.getservbyport(port, "tcp") if port in st.getservbyname else "Unknown"

        # OS detection if not behind CDN (unchanged)
        if not cdn_info['behind_cdn']:
            os_info = detect_os_fingerprint(ip, port)
            service_info['os'] = os_info['os']
            service_info['confidence'] = os_info['confidence']
        else:
            service_info['os'] = f"Unknown (Behind {cdn_info['cdn']})"
            service_info['confidence'] = 0.4

        # Web technology detection (new)
        if service_info['service'] in ["HTTP", "HTTPS"]:
            web_tech_info = detect_web_tech(banner, service_info['headers'], domain, port)
            service_info['web_tech'] = web_tech_info['web_tech']
            service_info['web_tech_version'] = web_tech_info['version']

    except Exception as e:
        service_info['error'] = str(e)
    return service_info


def _port_scanner(ip: str, start: int, end: int, domain: str, timeout: float) -> List[Dict]:
    """Scan a range of ports and return open ones."""
    local_open_ports = []
    for port in tqdm(range(start, min(start + 100, end)), desc=f"Ports {start}-{min(start + 99, 65535)}"):
        try:
            soc = st.socket(st.AF_INET, st.SOCK_STREAM)
            st.setdefaulttimeout(timeout)
            if soc.connect_ex((ip, port)) == 0:
                service_info = detect_service_and_os(ip, port, domain, timeout)
                with ports_lock:
                    open_ports.append(service_info)
                local_open_ports.append(service_info)
            soc.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return local_open_ports


def port_scanner_parallel(domain: str, start: int, end: int, max_workers: int = 10, timeout: float = 1.0, stealth: bool = True) -> Dict:
    """Parallel port scanner with thread pooling."""
    global open_ports
    open_ports = []  # Reset for each scan
    try:
        target_ip = st.gethostbyname(domain)
        port_ranges = list(range(start, end, 100))
        if stealth:
            random.shuffle(port_ranges)  # Stealth mode
        result = {'Host_Name': domain, 'IP_Address': target_ip, 'Open_Ports': []}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_port_scanner, target_ip, port_start, end, domain, timeout)
                       for port_start in port_ranges]
            for future in futures:
                future.result()  # Wait for completion

        result[f'{domain}_Open_Ports'] = open_ports
        return result
    except Exception as e:
        print(f"Scan failed: {e}")
        return {'Host_Name': domain, 'IP_Address': None, 'Open_Ports': [], 'error': str(e)}

async def portSvanner4LLM(domain: str, start: int, end: int, timeout: float):
    try:
        if not (1 <= start <= end <= 65535):
            print("Error: Ports must be between 1 and 65535, and start <= end.")
            exit(1)

        # Execute scan
        result = port_scanner_parallel(domain, start, end, 10, True, timeout)

        if result.get(f'{domain}_Open_Ports'):
            print(f"Performing SSL/TLS analysis for all open ports on the domain {domain}")
            ssl_results = await asyncio.gather(*[analyze_ssl_tls(domain, p['port']) for p in result[f'{domain}_Open_Ports']])
            result[f'{domain}_SSL_Analysis'] = ssl_results
        else:
            print(f"Scan failed: {result.get('error', 'Unknown error')}")
        
        return result
    except Exception as error:
        raise error
    
def interactive_mode():
    """Interactive CLI mode."""
    print("Welcome to Interactive Port Scanner!")
    domain = input("Enter domain to scan (e.g., example.com): ").strip()
    while not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        domain = input("Invalid domain. Try again: ").strip()
    
    start = int(input("Enter start port (1-65535): "))
    end = int(input("Enter end port (1-65535): "))
    sslAnalysis = input("Perform SSL/TLS analysis? (y/n): ").lower() == 'y'
    timeOut = int(input("Enter the Timeout duration. (1-10): "))
    verbose = input("Do you want do display the the retrieved Banner? (y/n): ").lower() == 'y'
    stealth = input("Do you want enable Stealth Mode? (y/n): ").lower() == 'y'
    maxWorkers = int(input("Maximum Number Of Threads to be used for Parallel Scanning (1-20): "))

    return domain, start, end, sslAnalysis, timeOut, verbose, stealth, maxWorkers


if __name__ == '__main__':
    print("This tool is for authorized use only. Ensure you have permission to scan the target.")

    parser = argparse.ArgumentParser(description="Enhanced Port Scanner")
    parser.add_argument("URL", nargs='?', help="Domain to scan (e.g., example.com)")
    parser.add_argument("-p", "--ports", type=int, nargs=2, help="Port range (e.g., 1 1000)", metavar=('START', 'END'))
    parser.add_argument("-m", "--max-workers", type=int, default=10, help="Max concurrent threads (default: 10)")
    parser.add_argument("--ssl", action="store_true", help="Perform SSL/TLS analysis")
    parser.add_argument("-t", "--timeout", type=int, default=1, help="Timeout Duration for each port scanning request")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose will display the full retrieved Banner")
    parser.add_argument("-s", "--stealth", action="store_true", help="Randomizes the oder of port numbers scanned")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()

    if args.interactive:
        domain, start, end, sslAnalysis, timeOut, verbose, stealth, maxWorkers = interactive_mode()
    else:
        domain = args.URL
        start, end = args.ports
        maxWorkers = args.max_workers
        timeOut = args.timeout
        sslAnalysis = args.ssl
        verbose = args.verbose
        stealth = args.stealth

    if not (1 <= start <= end <= 65535):
        print("Error: Ports must be between 1 and 65535, and start <= end.")
        exit(1)

    # Execute scan
    result = port_scanner_parallel(domain, start, end, maxWorkers, stealth, timeOut)

    # Display results
    if result.get(f'{domain}_Open_Ports'):
        if sslAnalysis:
            print(f"Performing SSL/TLS analysis for all open ports on the domain {domain}")
            ssl_results = [asyncio.run(analyze_ssl_tls(domain, p['port'])) for p in result[f'{domain}_Open_Ports']]
            result[f'{domain}_SSL_Analysis'] = ssl_results

        print(f"\nScan results for {domain} ({result['IP_Address']}):")
        for service_info in result[f'{domain}_Open_Ports']:
            print(f"Port {service_info['port']}:")
            print(f"  Service: {service_info['service']}")
            print(f"  Version: {service_info['version']}")
            print(f"  OS: {service_info['os']} (Confidence: {service_info['confidence']:.2f})")
            print(f"  CDN/Proxy: {service_info['cdn']}")
            print(f"  Web Technology: {service_info['web_tech']} (Version: {service_info['web_tech_version']})")
            banner = service_info['banner']
            print(f"  Banner: {banner if args.verbose else banner[:200] + ('...' if len(banner) > 200 else '')}")
            if service_info.get('error'):
                print(f"  Error: {service_info['error']}")
            print("-" * 50)
        print(f"Total open ports found: {len(result['Open_Ports'])}")

        # Display SSL/TLS analysis if performed (unchanged)
        if sslAnalysis:  # Fixed typo from 'analysessl' to 'ssl'
            print("\nSSL/TLS Analysis:")
            for i, analysis in enumerate(result[f'{domain}_SSL_Analysis']):
                print(f"Port {result['Open_Ports'][i]['port']}:")
                print(f"  Protocols: {', '.join(analysis['supported_protocols'])}")
                print(f"  Ciphers: {', '.join(analysis['cipher_suites'])}")
                print(f"  Weak Ciphers: {', '.join(analysis['weak_ciphers'])}")
                print(f"  Cert Valid: {analysis['certificate_chain_valid']}")
                print(f"  HSTS: {analysis['hsts']}")
    
    else:
        print(f"Scan failed: {result.get('error', 'Unknown error')}")
    
    # Save results
    output_file = os.path.join(os.getcwd(), 'Output', f"{domain}_scan.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=4)
    print(f"Results saved to {output_file}")