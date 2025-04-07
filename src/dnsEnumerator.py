import dns.resolver
import dns.zone
import dns.query
import argparse
import json
from tqdm import tqdm

def get_dns_records(domain, resolver_ip=None, verbose=True):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    results = {}
    resolver = dns.resolver.Resolver()
    if resolver_ip:
        resolver.nameservers = [resolver_ip]
    
    for rtype in tqdm(record_types, colour='RED', desc=f"Scanning {domain}"):
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(answer) for answer in answers]
            results[rtype] = records
            if verbose:
                print(f"  {rtype} resolved successfully: {records}")
            # Handle CNAME resolution
            if rtype == 'CNAME':
                for cname in answers:
                    cname_target = str(cname)
                    if verbose:
                        print(f"  Resolving CNAME target: {cname_target}")
                    cname_records = get_dns_records(cname_target, resolver_ip, verbose)
                    results[f"CNAME_{cname_target}"] = cname_records
        except Exception as e:
            if verbose:
                print(f"  {rtype} failed: {e}")
            continue
    return results

def test_zone_transfer(domain, verbose=True):
    resolver = dns.resolver.Resolver()
    results = []
    try:
        ns_records = resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_server = str(ns)
            if verbose:
                print(f"Attempting zone transfer from {ns_server}...")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                if verbose:
                    print(f"Zone transfer succeeded from {ns_server}!")
                zone_data = {str(name): node.to_text() for name, node in zone.nodes.items()}
                results.append({ns_server: zone_data})
            except Exception as e:
                if verbose:
                    print(f"Zone transfer failed from {ns_server}: {e}")
    except Exception as e:
        if verbose:
            print(f"No NS records found or error occurred: {e}")
    return results

def analyze_spf_dmarc(dns_records):
    analysis = {}
    if 'TXT' in dns_records:
        for txt in dns_records['TXT']:
            if txt.startswith('v=spf1'):
                analysis['SPF'] = txt
                if 'all' not in txt:
                    analysis['SPF_warning'] = "No 'all' mechanism found - SPF may be incomplete."
                elif '-all' not in txt:
                    analysis['SPF_warning'] = "Soft fail or no fail policy - potential spoofing risk."
            elif txt.startswith('v=DMARC1'):
                analysis['DMARC'] = txt
                if 'p=none' in txt:
                    analysis['DMARC_warning'] = "DMARC policy set to 'none' - no enforcement."
    return analysis

async def dnsEnumerator(domain: str) -> dict:
    dns_records = get_dns_records(domain)
    for rtype, records in dns_records.items():
        if not rtype.startswith("CNAME_"):
            print(f"{rtype}: {records}")

    for key, records in dns_records.items():
        if key.startswith("CNAME_"):
            print(f"\nCNAME target {key.replace('CNAME_', '')}:")
            for rtype, recs in records.items():
                print(f"  {rtype}: {recs}")

    zone_transfers = test_zone_transfer(domain)
    if zone_transfers:
        for transfer in zone_transfers:
            for ns, data in transfer.items():
                print(f"Zone transfer from {ns}:")
                for name, record in data.items():
                    print(f"  {name}: {record}")
    else:
        print("No successful zone transfers.")

    spf_dmarc = analyze_spf_dmarc(dns_records)
    if spf_dmarc.get('SPF'):
        print(f"SPF Record: {spf_dmarc['SPF']}")
        if 'SPF_warning' in spf_dmarc:
            print(f"  Warning: {spf_dmarc['SPF_warning']}")
    if spf_dmarc.get('DMARC'):
        print(f"DMARC Record: {spf_dmarc['DMARC']}")
        if 'DMARC_warning' in spf_dmarc:
            print(f"  Warning: {spf_dmarc['DMARC_warning']}")
    if not spf_dmarc:
        print("No SPF or DMARC records found.")

    results = {
            "domain": domain,
            "dns_records": dns_records,
            "zone_transfers": zone_transfers,
            "spf_dmarc_analysis": spf_dmarc
        }
    return results

if __name__ == "__main__":
    print("This tool is for authorized use only. Ensure you have permission to scan the target.")

    parser = argparse.ArgumentParser(description="DNS enumeration and analysis tool")
    parser.add_argument("domain", help="Domain to enumerate (e.g., example.com)")
    parser.add_argument("-r", "--resolver", default=None, help="Custom DNS resolver (e.g., 8.8.8.8)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    domain = args.domain.strip()
    OUTPUT_FILE_PATH = f'Output/{domain}_dnsENumeration.txt'

    # Get DNS records
    print(f"\nScanning DNS records for {domain}:")
    dns_records = get_dns_records(domain, resolver_ip=args.resolver, verbose=args.verbose)
    for rtype, records in dns_records.items():
        if not rtype.startswith("CNAME_"):
            print(f"{rtype}: {records}")

    # Display CNAME resolutions
    for key, records in dns_records.items():
        if key.startswith("CNAME_"):
            print(f"\nCNAME target {key.replace('CNAME_', '')}:")
            for rtype, recs in records.items():
                print(f"  {rtype}: {recs}")

    # Test zone transfer
    print(f"\nTesting zone transfer for {domain}:")
    zone_transfers = test_zone_transfer(domain, verbose=args.verbose)
    if zone_transfers:
        for transfer in zone_transfers:
            for ns, data in transfer.items():
                print(f"Zone transfer from {ns}:")
                for name, record in data.items():
                    print(f"  {name}: {record}")
    else:
        print("No successful zone transfers.")

    # Analyze SPF and DMARC
    print(f"\nSPF/DMARC Analysis for {domain}:")
    spf_dmarc = analyze_spf_dmarc(dns_records)
    if spf_dmarc.get('SPF'):
        print(f"SPF Record: {spf_dmarc['SPF']}")
        if 'SPF_warning' in spf_dmarc:
            print(f"  Warning: {spf_dmarc['SPF_warning']}")
    if spf_dmarc.get('DMARC'):
        print(f"DMARC Record: {spf_dmarc['DMARC']}")
        if 'DMARC_warning' in spf_dmarc:
            print(f"  Warning: {spf_dmarc['DMARC_warning']}")
    if not spf_dmarc:
        print("No SPF or DMARC records found.")

    # Save to file
    results = {
            "domain": domain,
            "dns_records": dns_records,
            "zone_transfers": zone_transfers,
            "spf_dmarc_analysis": spf_dmarc
        }
    
    with open(OUTPUT_FILE_PATH, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {OUTPUT_FILE_PATH}")