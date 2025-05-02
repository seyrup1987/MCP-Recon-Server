import asyncio
import dns.resolver
from datetime import datetime
from duckduckgo_search import DDGS
from urllib.parse import urlparse
import logging
import os
from concurrent.futures import ThreadPoolExecutor
import requests
import json
import multiprocessing
from typing import List, Set, Dict, Any
import argparse
from icecream import ic

# Logging configuration
LOG_DIRECTORY = "/home/seyrup/Projects_Private/ReCon_Artist/logs"
if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)
LOG_FILE = os.path.join(LOG_DIRECTORY, f"subdomain_enumerator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for detailed logging
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.debug(f"Logging initialized. Writing to {LOG_FILE} and console.")

# Configuration
CONFIG = {
    "dns_timeout": 5,
    "http_timeout": 10,
    "task_timeout": 300,
    "brute_force_concurrency": 50,
    "resolution_concurrency": 20,  # Reduced for stability
    "max_retries": 3,
    "backoff_factor": 2,
    "batch_size": 1000,  # Reduced batch size for smaller wordlist
}
PROGRESS_INTERVAL = 5  # Seconds between progress updates

WORDLIST_FOLDER = '/home/seyrup/Projects_Private/ReCon_Artist/config/SubdomainWordlists'
# Smaller default wordlist for testing
DEFAULT_WORDLIST = ["www", "mail", "ftp", "dev", "test", "admin", "api", "blog", "shop", "staging"]

def load_wordlist() -> List[str]:
    """
    Load a smaller wordlist for testing. Falls back to DEFAULT_WORDLIST if folder is inaccessible.
    """
    logger.debug(f"Attempting to load wordlist from {WORDLIST_FOLDER}")
    wordlist_set = set(DEFAULT_WORDLIST)  # Start with default small wordlist
    try:
        if os.path.isdir(WORDLIST_FOLDER):
            for filename in os.listdir(WORDLIST_FOLDER):
                if filename.endswith('.txt'):
                    file_path = os.path.join(WORDLIST_FOLDER, filename)
                    logger.debug(f"Reading wordlist file: {file_path}")
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                            words = [line.strip() for line in file if line.strip() and not line.startswith('#')]
                            wordlist_set.update(words[:5000])  # Limit to 1000 entries per file
                            logger.debug(f"Loaded {len(words)} words from {file_path}")
                    except Exception as e:
                        logger.warning(f"Error reading {file_path}: {e}")
        else:
            logger.warning(f"Wordlist folder {WORDLIST_FOLDER} does not exist. Using default wordlist.")
    except Exception as e:
        logger.error(f"Error accessing wordlist folder {WORDLIST_FOLDER}: {e}")
    
    if not wordlist_set:
        logger.warning("No valid words loaded. Using default wordlist.")
        wordlist_set = set(DEFAULT_WORDLIST)
    
    wordlist = list(wordlist_set)
    logger.info(f"Loaded {len(wordlist)} unique subdomains for enumeration")
    return wordlist

def resolve_subdomain(subdomain: str) -> List[str]:
    """Resolve a subdomain to its IP addresses using DNS A records."""
    logger.debug(f"Resolving subdomain: {subdomain}")
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Use Google DNS for reliability
        resolver.timeout = CONFIG["dns_timeout"]
        resolver.lifetime = CONFIG["dns_timeout"]
        answers = resolver.resolve(subdomain, 'A')
        ips = [str(rdata) for rdata in answers]
        logger.debug(f"Resolved {subdomain} to {ips}")
        return ips
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        logger.debug(f"No resolution for {subdomain}")
        return []
    except Exception as e:
        logger.error(f"Error resolving {subdomain}: {e}")
        return []

def get_subdomains_from_search(domain: str, progress_tracker: Dict[str, Any]) -> List[str]:
    """Find subdomains by searching the domain using DuckDuckGo."""
    logger.info(f"Starting web search for subdomains of {domain}")
    try:
        ddgs = DDGS()
        results = ddgs.text(domain, max_results=100)
        progress_tracker['search']['results_fetched'] = len(results)
        logger.info(f"Retrieved {len(results)} search results")
        potential_subdomains = set()
        
        for result in results:
            url = result.get('href', '')
            if not url:
                continue
            parsed = urlparse(url)
            netloc = parsed.netloc
            if netloc and (netloc.endswith("." + domain) or netloc == domain):
                potential_subdomains.add(netloc)
        
        progress_tracker['search']['potential'] = len(potential_subdomains)
        logger.info(f"Found {len(potential_subdomains)} potential subdomains from search")
        confirmed_subdomains = set()
        for sub in potential_subdomains:
            ips = resolve_subdomain(sub)
            if ips:
                confirmed_subdomains.add(sub)
                progress_tracker['search']['confirmed'] += 1
                logger.info(f"Confirmed subdomain from search: {sub} -> {ips}")
        
        progress_tracker['search']['status'] = 'completed'
        logger.info(f"Web search completed. Confirmed {len(confirmed_subdomains)} subdomains")
        return list(confirmed_subdomains)
    except Exception as e:
        progress_tracker['search']['errors'].append(str(e))
        progress_tracker['search']['status'] = 'failed'
        logger.error(f"Error in web search for {domain}: {e}")
        return []

def get_subdomains_from_dns(domain: str, progress_tracker: Dict[str, Any]) -> List[str]:
    """Find subdomains by querying DNS records (NS, MX, SRV)."""
    logger.info(f"Starting DNS record query for subdomains of {domain}")
    record_types = ['NS', 'MX', 'SRV']
    subdomains = set()
    
    for rec_type in record_types:
        logger.info(f"Querying {rec_type} records for {domain}")
        try:
            answers = dns.resolver.resolve(domain, rec_type)
            for rdata in answers:
                target = None
                if rec_type == 'NS':
                    target = str(rdata.target).rstrip('.')
                elif rec_type == 'MX':
                    target = str(rdata.exchange).rstrip('.')
                elif rec_type == 'SRV':
                    target = str(rdata.target).rstrip('.')
                
                if target and (target.endswith("." + domain) or target == domain):
                    subdomains.add(target)
                    progress_tracker['dns']['potential'] += 1
                    logger.info(f"Found subdomain from {rec_type}: {target}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            logger.debug(f"No {rec_type} records found for {domain}")
            continue
        except Exception as e:
            progress_tracker['dns']['errors'].append(str(e))
            logger.error(f"Error querying {rec_type} for {domain}: {e}")
    
    progress_tracker['dns']['potential'] = len(subdomains)
    logger.info(f"Found {len(subdomains)} potential subdomains from DNS records")
    confirmed_subdomains = set()
    for sub in subdomains:
        ips = resolve_subdomain(sub)
        if ips:
            confirmed_subdomains.add(sub)
            progress_tracker['dns']['confirmed'] += 1
    
    progress_tracker['dns']['status'] = 'completed'
    logger.info(f"DNS query completed. Confirmed {len(confirmed_subdomains)} subdomains")
    return list(confirmed_subdomains)

async def brute_force_subdomains(domain: str, progress_tracker: Dict[str, Any]) -> List[str]:
    """Perform brute-force subdomain enumeration with batch processing."""
    logger.info(f"Starting brute-force enumeration for {domain}")
    wordlist = load_wordlist()
    subdomains = set()
    
    # Split wordlist into batches
    batch_size = CONFIG["batch_size"]
    batches = [wordlist[i:i + batch_size] for i in range(0, len(wordlist), batch_size)]
    progress_tracker['brute']['total_batches'] = len(batches)
    
    async def process_batch(batch: List[str], batch_idx: int, executor: ThreadPoolExecutor):
        logger.info(f"Processing batch {batch_idx + 1}/{len(batches)} with {len(batch)} subdomains")
        tasks = []
        for word in batch:
            subdomain = f"{word}.{domain}".lower()
            tasks.append(resolve_task(subdomain, executor))
        await asyncio.gather(*tasks, return_exceptions=True)
        progress_tracker['brute']['batches_completed'] += 1
    
    async def resolve_task(subdomain: str, executor: ThreadPoolExecutor):
        loop = asyncio.get_event_loop()
        try:
            ips = await loop.run_in_executor(executor, resolve_subdomain, subdomain)
            if ips:
                subdomains.add(subdomain)
                progress_tracker['brute']['confirmed'] += 1
                logger.info(f"Found subdomain: {subdomain} -> {ips}")
        except Exception as e:
            progress_tracker['brute']['errors'].append(str(e))
            logger.debug(f"Failed to resolve {subdomain}: {e}")
    
    with ThreadPoolExecutor(max_workers=CONFIG["resolution_concurrency"]) as executor:
        batch_tasks = [
            process_batch(batch, idx, executor)
            for idx, batch in enumerate(batches)
        ]
        logger.info(f"Submitting {len(batch_tasks)} brute-force batches")
        await asyncio.gather(*batch_tasks, return_exceptions=True)
    
    progress_tracker['brute']['status'] = 'completed'
    logger.info(f"Brute-force completed. Found {len(subdomains)} subdomains")
    return list(subdomains)

async def fetch_crtsh_subdomains(domain: str, progress_tracker: Dict[str, Any]) -> List[str]:
    """Fetch subdomains from crt.sh."""
    logger.info(f"Starting crt.sh subdomain fetching for {domain}")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    
    for attempt in range(CONFIG["max_retries"]):
        try:
            logger.info(f"Attempt {attempt + 1} to fetch crt.sh data")
            response = requests.get(url, timeout=CONFIG["http_timeout"])
            response.raise_for_status()
            data = response.json()
            progress_tracker['crtsh']['results_fetched'] = len(data)
            
            for entry in data:
                name = entry.get('name_value', '').lower().strip()
                if name.endswith("." + domain) or name == domain:
                    if '\n' in name:
                        for n in name.split('\n'):
                            if n.endswith("." + domain) or n == domain:
                                subdomains.add(n)
                    else:
                        subdomains.add(name)
            
            progress_tracker['crtsh']['potential'] = len(subdomains)
            logger.info(f"Retrieved {len(subdomains)} potential subdomains from crt.sh")
            confirmed_subdomains = set()
            with ThreadPoolExecutor(max_workers=CONFIG["resolution_concurrency"]) as executor:
                loop = asyncio.get_event_loop()
                tasks = [
                    loop.run_in_executor(executor, resolve_subdomain, sub)
                    for sub in subdomains
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for sub, result in zip(subdomains, results):
                    if isinstance(result, List) and result:
                        confirmed_subdomains.add(sub)
                        progress_tracker['crtsh']['confirmed'] += 1
                        logger.info(f"Confirmed crt.sh subdomain: {sub} -> {result}")
            
            progress_tracker['crtsh']['status'] = 'completed'
            logger.info(f"crt.sh fetching completed. Confirmed {len(confirmed_subdomains)} subdomains")
            return list(confirmed_subdomains)
        
        except requests.RequestException as e:
            progress_tracker['crtsh']['errors'].append(str(e))
            logger.warning(f"Attempt {attempt + 1} failed for crt.sh: {e}")
            if attempt < CONFIG["max_retries"] - 1:
                await asyncio.sleep(CONFIG["backoff_factor"] ** attempt)
            else:
                progress_tracker['crtsh']['status'] = 'failed'
                logger.error(f"Failed to fetch crt.sh subdomains after {CONFIG['max_retries']} attempts")
                return []
    
    return []

async def log_progress(progress_tracker: Dict[str, Any]):
    """Periodically log progress of all discovery methods to the console."""
    while True:
        logger.info("--- Progress Update ---")
        for method, stats in progress_tracker.items():
            status = stats.get('status', 'running')
            confirmed = stats.get('confirmed', 0)
            errors = len(stats.get('errors', []))
            details = []
            if method == 'brute':
                total_batches = stats.get('total_batches', 0)
                completed = stats.get('batches_completed', 0)
                details.append(f"Batches: {completed}/{total_batches}")
            elif method in ['search', 'crtsh']:
                fetched = stats.get('results_fetched', 0)
                potential = stats.get('potential', 0)
                details.append(f"Fetched: {fetched}, Potential: {potential}")
            elif method == 'dns':
                potential = stats.get('potential', 0)
                details.append(f"Potential: {potential}")
            logger.info(f"{method.capitalize()}: Status={status}, Confirmed={confirmed}, Errors={errors}, {', '.join(details)}")
        logger.info("----------------------")
        await asyncio.sleep(PROGRESS_INTERVAL)

async def enumerate_subdomains(domain: str) -> Dict[str, Any]:
    """Enumerate subdomains using multiple methods in parallel."""
    logger.info(f"Starting subdomain enumeration for {domain}")
    all_subdomains = set()
    errors = []
    
    # Initialize progress tracker
    progress_tracker = {
        'brute': {'status': 'running', 'confirmed': 0, 'batches_completed': 0, 'total_batches': 0, 'errors': []},
        'search': {'status': 'running', 'confirmed': 0, 'results_fetched': 0, 'potential': 0, 'errors': []},
        'crtsh': {'status': 'running', 'confirmed': 0, 'results_fetched': 0, 'potential': 0, 'errors': []},
        'dns': {'status': 'running', 'confirmed': 0, 'potential': 0, 'errors': []}
    }
    
    # Run progress logger in parallel
    progress_task = asyncio.create_task(log_progress(progress_tracker))
    
    # Run all discovery methods in parallel with timeout
    try:
        loop = asyncio.get_event_loop()
        results = await asyncio.wait_for(
            asyncio.gather(
                brute_force_subdomains(domain, progress_tracker),
                loop.run_in_executor(None, get_subdomains_from_search, domain, progress_tracker),
                fetch_crtsh_subdomains(domain, progress_tracker),
                loop.run_in_executor(None, get_subdomains_from_dns, domain, progress_tracker),
                return_exceptions=True
            ),
            timeout=CONFIG["task_timeout"]
        )
        
        # Process results
        for method, result in zip(['brute', 'search', 'crtsh', 'dns'], results):
            if isinstance(result, Exception):
                errors.append(f"{method} error: {str(result)}")
                progress_tracker[method]['status'] = 'failed'
                progress_tracker[method]['errors'].append(str(result))
                logger.error(f"{method} error: {result}")
            else:
                all_subdomains.update(result)
                logger.info(f"Completed {method}. Found {len(result)} subdomains")
        
    except asyncio.TimeoutError:
        logger.error(f"Subdomain enumeration timed out after {CONFIG['task_timeout']} seconds")
        errors.append("Enumeration timed out")
    finally:
        # Cancel progress logger
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            logger.info("Progress logger cancelled")
    
    logger.info("Merging all subdomains...")
    result = {
        "domain": domain,
        f"{domain}_subdomains": sorted(list(all_subdomains)),
        "count": len(all_subdomains),
        "timestamp": datetime.now().isoformat(),
        "errors": errors
    }
    return result

def run_enumeration_in_process(domain: str, result_queue: multiprocessing.Queue):
    """Run enumerate_subdomains in a separate process and send results via queue."""
    logger.debug("Starting enumeration process")
    try:
        result = asyncio.run(enumerate_subdomains(domain))
        result_queue.put(('success', result))
        logger.debug("Enumeration process completed successfully")
    except Exception as e:
        result_queue.put(('error', str(e)))
        logger.error(f"Error in enumeration process: {e}")

def subDomainMapper4LLM(domain: str) -> Dict[str, Any]:
    """Wrapper for enumerate_subdomains for LLM integration, running in a new process."""
    logger.info("Initiating subdomain enumeration via subDomainMapper4LLM")
    
    # Create a multiprocessing queue for results
    result_queue = multiprocessing.Queue()
    
    # Start enumeration in a new process
    process = multiprocessing.Process(
        target=run_enumeration_in_process,
        args=(domain, result_queue)
    )
    process.start()
    
    # Wait for the process to complete with timeout
    try:
        process.join(timeout=CONFIG["task_timeout"])
        if process.is_alive():
            process.terminate()
            logger.error("Enumeration process timed out")
            return {"error": "Enumeration process timed out"}
    except Exception as e:
        logger.error(f"Error in enumeration process: {e}")
        process.terminate()
        return {"error": f"Enumeration process failed: {str(e)}"}
    
    # Retrieve results from queue
    if not result_queue.empty():
        status, result = result_queue.get()
        if status == 'success':
            logger.info("Subdomain enumeration completed via subDomainMapper4LLM")
            return result
        else:
            logger.error(f"Subdomain enumeration failed: {result}")
            return {"error": result}
    else:
        logger.error("No results received from enumeration process")
        return {"error": "Enumeration process failed to return results"}

def main():
    """
    Main function to run the script from the terminal.
    """
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument("domain", help="Domain to enumerate subdomains for (e.g., example.com)")
    args = parser.parse_args()

    # Run the subdomain enumeration
    result = subDomainMapper4LLM(args.domain)

    # Print the results
    if result[f'{args.domain}_subdomains']:
        print("\nValid Subdomains:")
        print(f"\nSubdomain Enumeration Results for {result['domain']}:")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Total Subdomains Found: {result['count']}")
        for subdomain in result[f'{args.domain}_subdomains']:
            print(f"  - {subdomain}")
    else:
        print("\nNo valid subdomains found.")
    if result['errors']:
        print("\nErrors Encountered:")
        for error in result['errors']:
            print(f"  - {error}")

if __name__ == "__main__":
    main()