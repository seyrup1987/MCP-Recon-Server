import requests
import argparse
import logging
from tqdm import tqdm
import signal
import os
import random
from requests.exceptions import ProxyError, ConnectTimeout, SSLError
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDLIST_PATH = "../../../config/n0kovo_subdomains/n0kovo_subdomains_tiny.txt"
PROXY_LIST_FILE = os.path.join('..', 'Output', 'proxy_list.txt')
OUTPUT_FILE = f"Output/found_directories.txt"  # Default output file name

def signal_handler(sig, frame):
    global interrupted
    logger.warning("Interrupt received! Shutting down gracefully...")
    interrupted = True

signal.signal(signal.SIGINT, signal_handler)

# Global interrupt flag
interrupted = False

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def load_proxies(proxy_file):
    """Load proxies from file and return a list."""
    try:
        with open(proxy_file, 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
        if not proxies:
            logger.warning("Proxy list is empty or file not found.")
            return None
        logger.info(f"Loaded {len(proxies)} proxies from {proxy_file}")
        return proxies
    except FileNotFoundError:
        logger.error(f"Proxy file {proxy_file} not found.")
        return None

def get_random_proxy(proxies):
    """Return a random proxy in the format required by requests."""
    if not proxies:
        return None
    proxy = random.choice(proxies)
    return {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}"
    }

def check_directory(subdomain, dir, proxies=None, max_retries=3):
    """Check a single directory with proxy retry logic and return result if found."""
    if interrupted:
        return None, None, []

    url = f"http://{subdomain}/{dir}"
    session = requests.Session()
    attempts = 0
    current_proxies = proxies.copy() if proxies else None
    log_messages = []

    while attempts < max_retries:
        if not current_proxies:
            log_messages.append(("WARNING", f"No more proxies available for {url} after {attempts} attempts."))
            break

        proxy_dict = get_random_proxy(current_proxies) if current_proxies else None
        proxy_str = proxy_dict['http'] if proxy_dict else 'None'

        try:
            r = session.get(
                url,
                timeout=5,
                proxies=proxy_dict,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            if r.status_code == 200:
                log_messages.append(("INFO", f"Found: {url} (Proxy: {proxy_str})"))
                session.close()
                return url, r.status_code, log_messages
            elif r.status_code in [403, 401]:
                log_messages.append(("DEBUG", f"Access denied at {url} (Status: {r.status_code})"))
                break
            else:
                log_messages.append(("DEBUG", f"No directory at {url} (Status: {r.status_code})"))
                break

        except (ProxyError, ConnectTimeout) as e:
            attempts += 1
            proxy_key = proxy_dict['http'].replace('http://', '') if proxy_dict else None
            log_messages.append(("WARNING", f"Proxy error for {url} with {proxy_str}: {str(e)}. Attempt {attempts}/{max_retries}"))
            if proxy_key in current_proxies:
                current_proxies.remove(proxy_key)
                log_messages.append(("INFO", f"Discarded proxy: {proxy_str}. {len(current_proxies)} proxies remaining."))
            if current_proxies:
                log_messages.append(("DEBUG", f"Retrying with a new proxy..."))
            else:
                log_messages.append(("WARNING", f"No proxies left to retry for {url}."))
                break
        except SSLError as e:
            log_messages.append(("ERROR", f"SSL error for {url}: {str(e)}"))
            break
        except requests.RequestException as e:
            log_messages.append(("DEBUG", f"Request failed for {url}: {str(e)}"))
            break
        finally:
            if attempts >= max_retries or not current_proxies:
                session.close()

    session.close()
    return None, None, log_messages

def dir_enum(subdomain, proxies=None, max_workers=10, output_file=OUTPUT_FILE):
    """Enumerate directories using threading and write results to a file."""
    found = []
    log_messages = []

    with open(WORDLIST_PATH, 'r') as f:
        dirs = [line.strip() for line in f]

    # Use ThreadPoolExecutor for parallel execution
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_dir = {executor.submit(check_directory, subdomain, dir, proxies): dir for dir in dirs}
        
        # Process results with tqdm
        for future in tqdm(as_completed(future_to_dir), total=len(dirs), colour='CYAN', desc="Scanning directories"):
            if interrupted:
                log_messages.append(("WARNING", "Stopping enumeration due to interrupt."))
                executor.shutdown(wait=False)
                break
            try:
                result, status_code, thread_logs = future.result()
                if result:
                    found.append((result, status_code))  # Store URL and status code
                log_messages.extend(thread_logs)
            except Exception as e:
                log_messages.append(("ERROR", f"Error processing future: {str(e)}"))

    # Log all messages after the loop
    for level, message in log_messages:
        getattr(logger, level.lower())(message)

    # Write found directories to output file
    if found:
        try:
            with open(output_file, 'w') as f:
                for url, status_code in found:
                    f.write(f"{url} - HTTP {status_code}\n")
            print(f"\nResults written to {output_file}")
        except IOError as e:
            print(f"\nError writing to {output_file}: {str(e)}")

    return found

if __name__ == '__main__':
    print("This tool is for authorized use only. Ensure you have permission to scan the target.")

    parser = argparse.ArgumentParser(description="Directory enumeration tool with proxy support")
    parser.add_argument("domain", help="Domain to enumerate (e.g., www.example.com)")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy usage")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--output", default=OUTPUT_FILE, help=f"Output file for results (default: {OUTPUT_FILE})")

    args = parser.parse_args()
    
    # Normalize domain input
    if not args.domain.startswith(('http://', 'https://')):
        args.domain = f"http://{args.domain}"

    # Load proxies unless explicitly disabled
    proxies = None if args.no_proxy else load_proxies(PROXY_LIST_FILE)
    
    # Run enumeration with specified number of threads and output file
    results = dir_enum(args.domain, proxies, max_workers=args.threads, output_file=args.output)
    
    # Print summary
    if results:
        print("\nFound directories:")
        for url, status_code in results:
            print(f"{url} - HTTP {status_code}")
        print(f"\nTotal directories found: {len(results)}")
    else:
        print("\nNo directories found.")