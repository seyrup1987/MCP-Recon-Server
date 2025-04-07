import whois
import dns.resolver
import argparse
from concurrent.futures import ThreadPoolExecutor
import sys
from datetime import datetime
import colorama
from colorama import Fore, Style
import os
import time

# Output file path
OUTPUT_FILE = os.path.join('Output', 'whoISAndDNSEnum.txt')

# Initialize colorama for colored output
colorama.init()

def get_whois_info(domain):
    """
    Retrieve WHOIS information for a given domain.
    """
    try:
        w = whois.whois(domain)
        if w.status is None:
            return f"No WHOIS data available for {domain}"
        
        result = f"{Fore.CYAN}WHOIS Information for {domain}:{Style.RESET_ALL}\n"
        result += "-" * 50 + "\n"
        
        fields = {
            'Domain Name': w.domain_name,
            'Registrar': w.registrar,
            'Creation Date': w.creation_date,
            'Expiration Date': w.expiration_date,
            'Last Updated': w.updated_date,
            'Name Servers': ', '.join(w.name_servers) if w.name_servers else None,
            'Registrant': w.registrant,
            'Registrant Country': w.registrant_country
        }
        
        for field, value in fields.items():
            if value:
                result += f"{field}: {value}\n"
        
        return result
    except Exception as e:
        return f"Error performing WHOIS lookup for {domain}: {str(e)}"

def query_dns_record(args):
    """
    Query a specific DNS record type for a domain using configured public DNS servers.
    """
    domain, record_type, timeout = args
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Use Google and Cloudflare DNS
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, record_type)
        return (record_type, [rdata.to_text() for rdata in answers])
    except dns.resolver.NXDOMAIN:
        return (record_type, [f"Error: Domain {domain} does not exist"])
    except dns.resolver.NoAnswer:
        return (record_type, [f"No {record_type} records found for {domain}"])
    except dns.resolver.Timeout:
        return (record_type, [f"Timeout after {timeout}s for {record_type} query on {domain}"])
    except Exception as e:
        return (record_type, [f"Error: {str(e)}"])

def get_dns_records(domain, timeout=2.0, verbose=False):
    """
    Retrieve various DNS records for a domain with controlled parallelism and delays.
    """
    # Expanded list of DNS record types
    record_types = [
        'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR',
        'SRV', 'CAA', 'DS', 'DNSKEY', 'SPF'
    ]
    
    result = f"\n{Fore.GREEN}DNS Records for {domain}:{Style.RESET_ALL}\n"
    result += "-" * 50 + "\n"
    
    # Parallel DNS queries with reduced workers and delay
    with ThreadPoolExecutor(max_workers=2) as executor:
        dns_results = []
        for result_item in executor.map(query_dns_record, [(domain, rt, timeout) for rt in record_types]):
            dns_results.append(result_item)
            time.sleep(0.5)  # Add delay to avoid rate limiting
    
    for record_type, records in dns_results:
        if records:
            result += f"\n{Fore.YELLOW}{record_type} Records:{Style.RESET_ALL}\n"
            for record in records:
                if record_type == 'MX':
                    # Special formatting for MX records
                    parts = record.split()
                    if len(parts) > 1:
                        result += f"  {parts[1]} (Priority: {parts[0]})\n"
                    else:
                        result += f"  {record}\n"
                else:
                    result += f"  {record}\n"
            if verbose:
                result += f"  [Queried with {timeout}s timeout]\n"
    
    return result

def main():
    """
    Main function to parse arguments and execute WHOIS and DNS enumeration.
    """
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Perform WHOIS lookup and DNS enumeration')
    parser.add_argument('domain', help='Domain name to lookup (e.g., google.com)')
    parser.add_argument('-t', '--timeout', type=float, default=2.0,
                       help='DNS query timeout in seconds (default: 2.0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show verbose output including timeout info')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    args = parser.parse_args()
    
    domain = args.domain.strip()
    if not domain:
        print("Please provide a domain name")
        return
    
    # Prepare output
    output = []
    output.append(get_whois_info(domain))
    output.append(get_dns_records(domain, args.timeout, args.verbose))
    final_output = "\n".join(output)
    
    # Handle color output
    if args.no_color:
        final_output = colorama.decolorize(final_output)
    
    # Print to console
    print(final_output)

    try:
        os.makedirs('Output', exist_ok=True)  # Ensure Output directory exists
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"# Lookup for {domain} performed on {timestamp}\n\n")
            f.write(final_output)
        print(f"\nResults saved to {OUTPUT_FILE}")
    except Exception as e:
        print(f"Error saving to file: {str(e)}")

if __name__ == "__main__":
    main()