# Ensure 'requests' is installed: pip install requests
import requests
import re
import socket
import logging
import sys
import os
import time
import threading
import asyncio # Import asyncio
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Determine script and log directory ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../logs"))
LOG_FILE = os.path.join(LOG_DIR, "subdomain_mapper.log")

# --- Ensure log directory exists ---
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except OSError as e:
    # Use stderr for this initial critical error as logging might not be set up
    sys.stderr.write(f"CRITICAL: Failed to create log directory {LOG_DIR}: {e}\n")
    # Depending on requirements, you might want to exit or raise here
    # raise

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(threadName)s:%(funcName)s:%(lineno)d] - %(message)s') # Added lineno

# Get the root logger for this module
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set level (INFO or DEBUG for more verbose)

# --- Remove existing handlers (like the default StreamHandler if any were added elsewhere) ---
# This prevents duplicate messages if the module is reloaded or logger configured elsewhere
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
    handler.close() # Close the handler properly

# --- Create and add File Handler ---
try:
    file_handler = logging.FileHandler(LOG_FILE, mode='a') # Append mode
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)
except Exception as e:
    # Fallback to stderr if file logging fails
    sys.stderr.write(f"CRITICAL: Failed to set up file logging to {LOG_FILE}: {e}\n")
    # Optionally add a StreamHandler as a fallback
    # log_handler = logging.StreamHandler(sys.stderr)
    # log_handler.setFormatter(log_formatter)
    # logger.addHandler(log_handler)

logger.propagate = False # Prevent messages from propagating to the root logger if configured

logger.info("--- subDomainMapper logging initialized ---")
logger.info(f"Logging to file: {LOG_FILE}")

# --- Custom Exception ---
class FetchError(Exception):
    """Custom exception for errors during fetching from external sources."""
    pass

# --- Core Functions ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST_PATH = os.path.join(SCRIPT_DIR, "../config/subdomains-uk-1000.txt")

def load_wordlist(wordlist_path: str = DEFAULT_WORDLIST_PATH) -> list:
    """Load subdomains from a wordlist file using an absolute path."""
    resolved_path = os.path.abspath(wordlist_path)
    logger.info(f"Attempting to load wordlist from: {resolved_path}")
    if not os.path.exists(resolved_path):
        logger.error(f"Wordlist file not found at resolved path: {resolved_path}")
        raise FileNotFoundError(f"Wordlist file not found: {resolved_path}")
    try:
        with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as file:
            words = [line.strip() for line in file if line.strip()]
            logger.info(f"Successfully loaded {len(words)} words from {resolved_path}")
            return words
    except Exception as e:
        logger.error(f"Error reading wordlist file {resolved_path}: {e}", exc_info=True) # Log exception info
        raise


def brute_force_subdomains(
    domain: str,
    wordlist: list,
    concurrency: int = 100
) -> list:
    """
    Brute-force subdomain resolution using threads and concurrency limiting.
    For each word from the wordlist, the candidate subdomain is generated as "<word>.domain".
    A DNS resolution is attempted for each candidate using socket.gethostbyname.
    Returns a list of resolved subdomains.
    """
    resolved_subdomains = []
    candidates = [f"{word.strip()}.{domain}" for word in wordlist if word.strip()]
    total_candidates = len(candidates)
    logger.info(f"Starting brute-force for {domain} with {total_candidates} candidates using {concurrency} workers.")

    resolved_count = 0
    failed_count = 0

    def resolve_candidate(candidate: str):
        try:
            # Attempt to resolve the candidate subdomain
            logger.debug(f"Attempting to resolve: {candidate}")
            ip = socket.gethostbyname(candidate) # This is the blocking call
            logger.info(f"Resolved {candidate} -> {ip}")
            return candidate
        except socket.gaierror:
            logger.debug(f"Failed to resolve (NXDOMAIN or other): {candidate}")
            return None
        except Exception as e: # Catch other potential socket errors
             logger.warning(f"Unexpected error resolving {candidate}: {e}")
             return None

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix='SubdomainResolver') as executor:
        future_to_candidate = {executor.submit(resolve_candidate, candidate): candidate for candidate in candidates}
        
        processed_count = 0
        for future in as_completed(future_to_candidate):
            candidate = future_to_candidate[future]
            processed_count += 1
            try:
                result = future.result()
                if result:
                    resolved_subdomains.append(result)
                    resolved_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                # This catches exceptions raised *within* resolve_candidate if not caught there,
                # or exceptions during future retrieval itself.
                logger.error(f"Error processing result for {candidate}: {e}", exc_info=True)
                failed_count += 1

            if processed_count % 100 == 0 or processed_count == total_candidates: # Log progress periodically
                 logger.debug(f"Progress: {processed_count}/{total_candidates} candidates processed.")

    elapsed = time.time() - start_time
    logger.info(f"Brute-force for {domain} completed in {elapsed:.2f} seconds. Found: {resolved_count}, Failed/Not Found: {failed_count}.")

    # Remove duplicates just in case (though resolve_candidate results should be unique if successful)
    unique_resolved = list(set(resolved_subdomains))
    if len(unique_resolved) != len(resolved_subdomains):
         logger.warning(f"Duplicate resolutions detected for {domain}, returning unique set.")
         
    return unique_resolved


def clean_subdomains(subdomains: list, domain: str) -> list:
    """
    Cleans and deduplicates a list of subdomains.
    """
    logger.info(f"Starting cleaning process for {len(subdomains)} potential subdomains of {domain}.")
    if not isinstance(subdomains, (list, set)):
        logger.warning(f"clean_subdomains received non-list/set input: {type(subdomains)}. Returning empty list.")
        return []

    clean_set = set()
    rejected_count = 0
    # Compile regex patterns outside the loop for efficiency
    escaped_domain = re.escape(domain)
    sub_part = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    # Allow FQDN or *.domain patterns. Adjusted to be more robust.
    pattern_str = rf"^(?:(?:{sub_part}|\*)\.)*{escaped_domain}$"
    try:
        pattern = re.compile(pattern_str, re.IGNORECASE)
        part_pattern = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    except re.error as e:
         logger.error(f"Regex compilation error for domain '{domain}': {e}. Skipping cleaning.")
         # Decide how to handle this - return original? empty? raise?
         # Returning original list might be safer but could contain junk.
         return sorted(list(set(subdomains))) # Return unique original items


    for sub in subdomains:
        original_sub = sub # Keep original for logging
        if not isinstance(sub, str):
            logger.debug(f"Rejected: Non-string item: {type(sub)}")
            rejected_count += 1
            continue
            
        sub = sub.strip().lower()
        
        # Basic syntax checks
        if not sub or '..' in sub or sub.startswith('.') or sub.endswith('.') or ' ' in sub:
            logger.debug(f"Rejected (basic format): {original_sub}")
            rejected_count += 1
            continue
            
        # Domain suffix check (allow exact domain match)
        if not sub.endswith(f'.{domain}') and sub != domain:
            if sub == f"*.{domain}": # Allow wildcard directly under domain
                 pass
            else:
                 logger.debug(f"Rejected (wrong domain suffix): {original_sub}")
                 rejected_count += 1
                 continue
                 
        # Overall structure check
        if not pattern.match(sub):
             logger.debug(f"Rejected (regex pattern mismatch): {original_sub}")
             rejected_count += 1
             continue
             
        # Check individual parts (labels) for validity
        parts = sub.split('.')
        # Adjust part slicing based on whether the base domain itself has dots
        domain_parts_count = domain.count('.') + 1
        labels_to_check = parts[:-domain_parts_count]

        valid_parts = True
        for part in labels_to_check:
            if part == '*': continue # Allow wildcard parts
            if not part_pattern.match(part):
                 logger.debug(f"Rejected (invalid part '{part}'): {original_sub}")
                 valid_parts = False
                 rejected_count += 1
                 break
        if not valid_parts:
             continue # Already logged and counted

        # If all checks pass, add to the clean set
        if sub not in clean_set:
             logger.debug(f"Accepted: {sub}")
             clean_set.add(sub)
        else:
             logger.debug(f"Duplicate accepted: {sub}") # Log duplicates being added to set

    # Ensure the base domain is included if it's valid (simple check)
    if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
        if domain not in clean_set:
             logger.debug(f"Adding base domain to results: {domain}")
             clean_set.add(domain)
             
    final_list = sorted(list(clean_set))
    logger.info(f"Cleaning complete for {domain}. Accepted: {len(final_list)}, Rejected/Duplicates: {rejected_count + (len(subdomains) - rejected_count - len(final_list))}. Final count: {len(final_list)}")
    return final_list


def subDomainEnumSync(
    domain: str,
    future: asyncio.Future
) -> None:
    """
    Synchronous wrapper for subdomain enumeration, designed to be run in a thread executor.

    This function orchestrates the subdomain discovery process:
    1. Loads a subdomain wordlist.
    2. Performs brute-force DNS resolution using the wordlist (internally threaded).
    3. Cleans and validates the discovered subdomains.
    4. Sets the final list of subdomains as the result on the provided asyncio.Future
       or sets an exception if an error occurs.

    Args:
        domain: The target domain (e.g., "example.com").
        future: An asyncio.Future object provided by the caller (typically via loop.run_in_executor).
                This function will call future.set_result() or future.set_exception() upon completion or error.
    """
    func_start_time = time.time()
    # Use the module-level logger configured at the top of the file
    # Note: Using logger directly assumes it's configured in the global scope of subDomainMapper.py
    global logger 
    
    logger.info(f"Starting subdomain enumeration task for: {domain}")

    # Check if the future was cancelled *before* starting work
    if future.cancelled():
        logger.warning(f"Subdomain enumeration for {domain} cancelled before starting.")
        return # Don't proceed if already cancelled

    try:
        # --- Step 1: Load Wordlist ---
        logger.debug(f"[{domain}] Loading wordlist...")
        step_start_time = time.time()
        try:
            wordList = load_wordlist() # Can raise FileNotFoundError or other reading errors
            logger.debug(f"[{domain}] Wordlist loaded in {time.time() - step_start_time:.2f}s. Found {len(wordList)} words.")
        except FileNotFoundError as e:
            logger.error(f"[{domain}] Wordlist not found. Cannot proceed with brute-force. {e}", exc_info=True)
            # Set exception on the future if it's not already done
            if not future.done(): future.set_exception(e)
            else: logger.warning(f"Future for [{domain}] was already done when trying to set FileNotFoundError.")
            return # Stop execution for this task
        except Exception as e: # Catch other potential errors during wordlist loading
            logger.error(f"[{domain}] Failed to load wordlist due to unexpected error: {e}", exc_info=True)
            if not future.done(): future.set_exception(e)
            else: logger.warning(f"Future for [{domain}] was already done when trying to set wordlist load exception.")
            return

        # --- Step 2: Brute-Force Subdomains ---
        logger.debug(f"[{domain}] Starting brute-force resolution...")
        step_start_time = time.time()
        # This function uses ThreadPoolExecutor internally for concurrency
        brute_forced_results = brute_force_subdomains(domain, wordList)
        logger.debug(f"[{domain}] Brute-force resolution finished in {time.time() - step_start_time:.2f}s. Found {len(brute_forced_results)} potential subdomains.")

        # --- Step 3: Clean Subdomains ---
        logger.debug(f"[{domain}] Starting subdomain cleaning...")
        step_start_time = time.time()
        cleaned_subdomains = clean_subdomains(brute_forced_results, domain)
        logger.debug(f"[{domain}] Subdomain cleaning finished in {time.time() - step_start_time:.2f}s. Final count: {len(cleaned_subdomains)}.")

        # --- Task Completion ---
        total_elapsed = time.time() - func_start_time
        # Set the result on the future *only if* it hasn't been cancelled or timed out by the caller
        if not future.done():
            logger.info(f"Subdomain enumeration for {domain} completed successfully in {total_elapsed:.2f} seconds. Found {len(cleaned_subdomains)} unique subdomains.")
            future.set_result(cleaned_subdomains)
        else:
            # Log if the future was already completed (e.g., cancelled or timed out in the caller)
             logger.warning(f"Future for {domain} was already done (cancelled/timed out?) when trying to set result. Task took {total_elapsed:.2f}s internally.")

    except Exception as e:
        # Catch any unexpected errors during brute-forcing or cleaning
        total_elapsed = time.time() - func_start_time
        logger.critical(f"Unhandled exception during subdomain enumeration task for {domain} after {total_elapsed:.2f} seconds: {e}", exc_info=True)
        # Set the exception on the future if it's not already done
        if not future.done():
            future.set_exception(e)
        else:
            logger.warning(f"Future for {domain} was already done when trying to set unhandled exception: {e}", exc_info=True)
