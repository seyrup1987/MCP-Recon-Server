import os
import socket as st
import ssl
import asyncio
import aiohttp
import dns.resolver
from typing import Dict, List, Optional
from collections import defaultdict
import re
import json
from tqdm import tqdm
from scapy.all import sr, IP, TCP, conf
import argparse
import random
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Global file handle and lock for thread-safe logging
log_file = None
log_lock = threading.Lock()

def init_logging():
    """Initialize the log file handle."""
    global log_file
    log_file = open('port_scanner_debug_log.txt', 'a', encoding='utf-8')

def close_logging():
    """Close the log file handle."""
    global log_file
    if log_file:
        log_file.close()
        log_file = None

def output_to_file(text: str) -> None:
    """Log text to a file using a single file handle with thread-safe writes."""
    global log_file
    with log_lock:
        if log_file:
            log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {text}\n")
            log_file.flush()  # Ensure immediate write to disk

def parse_banner(banner: str) -> Dict[str, str]:
    """Parse HTTP headers from banner."""
    headers = defaultdict(str)
    if banner:
        lines = banner.split('\r\n')
        in_headers = True
        for line in lines:
            if not line.strip() and in_headers:
                in_headers = False
                continue
            if in_headers and ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
    return dict(headers)

def check_privileges() -> bool:
    """Check if running with root privileges."""
    if os.name == 'posix' and os.geteuid() != 0:
        output_to_file("Warning: SYN scanning and OS fingerprinting require root privileges. Using fallback.")
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
                pem_cert = ssl.get_server_certificate((domain, port))
                result['certificate_chain_valid'] = True
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
        conf.verb = 0
        pkt = sr(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=2, retry=2)
        answers, _ = pkt
        for sent, received in answers:
            if received.haslayer(TCP) and received[TCP].flags & 0x12 == 0x12:
                tcp_options = received[TCP].options
                window_size = received[TCP].window
                ttl = received[IP].ttl

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
    
    if "cf-ray" in headers: result['cdn'], result['behind_cdn'] = "Cloudflare", True
    elif "x-amzn-cdn-id" in headers: result['cdn'], result['behind_cdn'] = "Amazon CloudFront", True
    elif "x-akamai-transformed" in headers: result['cdn'], result['behind_cdn'] = "Akamai", True
    elif "x-cache" in headers and "fastly" in headers.get('x-served-by', ''): result['cdn'], result['behind_cdn'] = "Fastly", True

    if "x-sucuri-id" in headers: result['waf'] = "Sucuri"
    elif "x-waf" in headers or "protected by" in headers.get('server', ''): result['waf'] = "Generic WAF"
    elif "cloudflare" in headers.get('server', '') and "cf-ray" in headers: result['waf'] = "Cloudflare WAF"

    try:
        ns_records = [str(r).lower() for r in dns.resolver.resolve(domain, 'NS')]
        if any("cloudflare" in ns for ns in ns_records): result['cdn'], result['behind_cdn'] = "Cloudflare (DNS)", True
    except Exception:
        pass
    return result

def detect_web_tech(banner: str, headers: Dict[str, str], domain: str, port: int) -> Dict[str, str]:
    """Detect web technologies based on banner, headers, and optional HTML content."""
    tech_info = {'web_tech': 'Unknown', 'version': 'N/A'}
    headers = {k.lower(): v.lower() for k, v in headers.items()}
    banner_lower = banner.lower()

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

    if "wordpress" in banner_lower or "wp-content" in banner_lower:
        tech_info['web_tech'] = "WordPress"
    elif "drupal" in banner_lower:
        tech_info['web_tech'] = "Drupal"
    elif "joomla" in banner_lower:
        tech_info['web_tech'] = "Joomla"

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
            pass

    return tech_info

async def fingerprint_service_and_os(ip: str, port: int, domain: str, timeout: float = 1.0) -> Dict[str, Optional[str]]:
    """Perform service detection, OS fingerprinting, and web tech detection for an open port."""
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
        probes = {
            80: f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n",
            443: f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n",
            21: "USER anonymous\r\n",
            22: "SSH-2.0-OpenSSH_7.4\r\n",
            25: "HELO test\r\n",
            3306: "SELECT @@version\r\n"
        }
        probe = probes.get(port, "HELLO\r\n").encode()

        if port == 443:
            context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=domain),
                timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )

        writer.write(probe)
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        banner = banner.decode('utf-8', errors='ignore')
        writer.close()
        await writer.wait_closed()

        service_info['banner'] = banner.strip()
        service_info['headers'] = parse_banner(banner)
        cdn_info = detect_cdn(service_info['headers'], domain)
        service_info['cdn'] = cdn_info['cdn']

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

        if not cdn_info['behind_cdn']:
            os_info = detect_os_fingerprint(ip, port)
            service_info['os'] = os_info['os']
            service_info['confidence'] = os_info['confidence']
        else:
            service_info['os'] = f"Unknown (Behind {cdn_info['cdn']})"
            service_info['confidence'] = 0.4

        if service_info['service'] in ["HTTP", "HTTPS"]:
            web_tech_info = detect_web_tech(banner, service_info['headers'], domain, port)
            service_info['web_tech'] = web_tech_info['web_tech']
            service_info['web_tech_version'] = web_tech_info['version']

    except Exception as e:
        service_info['error'] = str(e)
    return service_info

def scan_port_scapy(ip: str, port: int, timeout: float = 0.5) -> Optional[int]:
    """Scan a single port using Scapy SYN scan with adaptive timeout."""
    conf.verb = 0
    max_timeout = 2.0
    current_timeout = timeout
    attempt = 0
    max_attempts = 3

    while attempt < max_attempts:
        try:
            start_time = time.time()
            pkt = sr(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=current_timeout, retry=1)
            answers, _ = pkt
            for sent, received in answers:
                if received.haslayer(TCP) and received[TCP].flags & 0x12 == 0x12:
                    elapsed = time.time() - start_time
                    output_to_file(f"Port {port} open, responded in {elapsed:.2f}s")
                    return port
            break
        except Exception as e:
            output_to_file(f"Scapy scan error on port {port}, attempt {attempt + 1}: {e}")
            attempt += 1
            current_timeout = min(current_timeout * 2, max_timeout)
    return None

def scan_port_batch(ip: str, start: int, end: int, domain: str, max_workers: int, timeout: float, stealth: bool) -> List[int]:
    """Scan a batch of ports using Scapy SYN scan with threading."""
    ports = list(range(start, end + 1))
    if stealth:
        random.shuffle(ports)
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port_scapy, ip, port, timeout) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    
    return open_ports

async def port_scanner_async(domain: str, max_workers: int, timeout: float, stealth: bool) -> Dict:
    """Asynchronous port scanner for all ports 1-10000 in batches of 500."""
    output_to_file(f"Starting port scan for {domain}")
    try:
        target_ip = st.gethostbyname(domain)
        result = {'Host_Name': domain, '{domain}_IP_Address': target_ip, '{domain}_Open_Ports': []}
        
        batch_size = 500
        batches = [(i, min(i + batch_size - 1, 10000)) for i in range(1, 10001, batch_size)]
        open_ports = []
        
        if not check_privileges():
            output_to_file("SYN scanning requires root privileges. Exiting.")
            return {'Host_Name': domain, '{domain}_IP_Address': target_ip, '{domain}_Open_Ports': [], 'error': 'Root privileges required for SYN scanning'}

        with tqdm(total=10000, desc=f"Scanning {domain} ports 1-10000") as pbar:
            for start, end in batches:
                batch_open_ports = scan_port_batch(target_ip, start, end, domain, max_workers, timeout, stealth)
                open_ports.extend(batch_open_ports)
                pbar.update(batch_size)
        
        if open_ports:
            output_to_file(f"Found open ports: {open_ports}")
            fingerprint_tasks = [
                asyncio.create_task(fingerprint_service_and_os(target_ip, port, domain, timeout))
                for port in open_ports
            ]
            service_infos = await asyncio.gather(*fingerprint_tasks)
            result['{domain}_Open_Ports'] = [info for info in service_infos if info.get('error') is None]
        
        output_to_file(f"Port scan completed for {domain}")
        return result
    except Exception as e:
        output_to_file(f"Scan failed for {domain}: {e}")
        return {'Host_Name': domain, 'IP_Address': None, 'Open_Ports': [], 'error': str(e)}

def run_scanner(domain: str, max_workers: int, timeout: float, ssl_analysis: bool, verbose: bool, stealth: bool):
    """Run the scanner in a separate process with proper asyncio event loop management."""
    init_logging()  # Initialize log file handle
    output_to_file(f"Starting scan for {domain} with max_workers={max_workers}, timeout={timeout}, stealth={stealth}")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(port_scanner_async(domain, max_workers, timeout, stealth))
        
        if ssl_analysis and result.get('Open_Ports'):
            print(f"Performing SSL/TLS analysis for all open ports on {domain}")
            ssl_tasks = [analyze_ssl_tls(domain, p['port']) for p in result['Open_Ports']]
            ssl_results = loop.run_until_complete(asyncio.gather(*ssl_tasks))
            result[f'{domain}_SSL_Analysis'] = ssl_results

        if result.get('{domain}_Open_Ports'):
            print(f"\nScan results for {domain} ({result['{domain}_IP_Address']}):")
            for service_info in result['{domain}_Open_Ports']:
                print(f"Port {service_info['port']}:")
                print(f"  Service: {service_info['service']}")
                print(f"  Version: {service_info['version']}")
                print(f"  OS: {service_info['os']} (Confidence: {service_info['confidence']:.2f})")
                print(f"  CDN/Proxy: {service_info['cdn']}")
                print(f"  Web Technology: {service_info['web_tech']} (Version: {service_info['web_tech_version']})")
                banner = service_info['banner']
                print(f"  Banner: {banner if verbose else banner[:200] + ('...' if len(banner) > 200 else '')}")
                if service_info.get('error'):
                    print(f"  Error: {service_info['error']}")
                print("-" * 50)
            print(f"Total open ports found: {len(result['{domain}_Open_Ports'])}")

            if ssl_analysis and f'{domain}_SSL_Analysis' in result:
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

        
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(result, f, indent=4)
        output_to_file(f"Scan completed for {domain}. Results saved to {OUTPUT_FILE}")
        print(f"Results saved to {OUTPUT_FILE}")

    finally:
        close_logging()  # Ensure log file is closed

def interactive_mode():
    """Interactive CLI mode."""
    print("Welcome to Interactive Port Scanner!")
    domain = input("Enter domain to scan (e.g., example.com): ").strip()
    while not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        domain = input("Invalid domain. Try again: ").strip()
    
    ssl_analysis = input("Perform SSL/TLS analysis? (y/n): ").lower() == 'y'
    timeout = float(input("Enter the initial Timeout duration (0.5-10): "))
    verbose = input("Display the retrieved Banner? (y/n): ").lower() == 'y'
    stealth = input("Enable Stealth Mode? (y/n): ").lower() == 'y'
    max_workers = 100  # Fixed to 50 as per optimization

    return domain, max_workers, timeout, ssl_analysis, verbose, stealth

async def portScanner4LLM(domain: str, timeOut: float):
    try:
        global OUTPUT_FILE
        OUTPUT_FILE = os.path.join(os.getcwd(), 'Output', f"{domain}_scan.json")
        max_workers = 100
        ssl_analysis = True
        verbose = True
        stealth = True

        process = multiprocessing.Process(
            target=run_scanner,
            args=(domain, max_workers, timeOut, ssl_analysis, verbose, stealth)
        )
        process.start()
        process.join()

        with open(OUTPUT_FILE, 'r') as f:
            result = json.load(f)

        return result
            
    except Exception as error:
        print(error)
        return error

if __name__ == "__main__":
    print("This tool is for authorized use only. Ensure you have permission to scan the target.")

    parser = argparse.ArgumentParser(description="Enhanced Port Scanner")
    parser.add_argument("URL", nargs='?', help="Domain to scan (e.g., example.com)")
    parser.add_argument("-m", "--max-workers", type=int, default=50, help="Max concurrent workers (default: 50)")
    parser.add_argument("--ssl", action="store_true", help="Perform SSL/TLS analysis")
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Initial timeout duration for each port scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display full retrieved Banner")
    parser.add_argument("-s", "--stealth", action="store_true", help="Randomize port scan order")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()

    if args.interactive:
        domain, max_workers, timeout, ssl_analysis, verbose, stealth = interactive_mode()
    else:
        domain = args.URL
        max_workers = args.max_workers
        timeout = args.timeout
        ssl_analysis = args.ssl
        verbose = args.verbose
        stealth = args.stealth

    if not domain:
        print("Error: Domain must be provided.")
        exit(1)

    global OUTPUT_FILE
    OUTPUT_FILE = os.path.join(os.getcwd(), 'Output', f"{domain}_scan.json")
    process = multiprocessing.Process(
        target=run_scanner,
        args=(domain, max_workers, timeout, ssl_analysis, verbose, stealth)
    )
    process.start()
    process.join()