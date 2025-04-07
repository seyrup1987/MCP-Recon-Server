from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI
from webCrawler_proxyHunter import webCrawler_proxyHunter
from techFingerprint import portScanner4LLM
from dnsEnumerator import dnsEnumerator
from dirEnumerator import dirEnum4LLM
from subDomainMapper import subDomainEnumSync
from ingest2DB import ingest2DB, chunk_and_ingest
from sse_starlette.sse import EventSourceResponse
from starlette.responses import Response
import uvicorn
from duckduckgo_search import DDGS
from bs4 import BeautifulSoup
from bs4.element import Comment
import urllib.request
import traceback
import asyncio
import functools
import sys
import json
import signal
import logging
import anyio
import os # Added for path operations
from datetime import datetime # Added for timestamped log file

# --- Logging Configuration ---
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs') # Define log directory relative to main.py
os.makedirs(LOG_DIR, exist_ok=True) # Ensure log directory exists
os.environ['PYTHONASYNCIODEBUG'] = '1'

# Generate a timestamped log filename
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"mcp_pentest_{timestamp}.log")

# Configure root logger
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.FileHandler(os.path.join(LOG_DIR, "mcp_pentest_AsyncIOlog")) # Use os.path.join for path
log_handler.setFormatter(log_formatter)

# Get the main logger for your app
logger = logging.getLogger("mcp-pentest") # Or your main logger name
logger.setLevel(logging.DEBUG) # Set your main logger to DEBUG to see asyncio logs

# --- Remove existing handlers if any (e.g., from previous runs in interactive sessions) ---
# This is good practice when reconfiguring logging.
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

logger.addHandler(log_handler)

# File Handler - writes DEBUG level logs and above to a file
file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG) # Ensure file handler captures DEBUG level
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)


# --- Enhanced AsyncIO Logging Configuration ---
def handle_asyncio_exception(loop, context):
    """
    Custom exception handler for the asyncio loop.
    Logs all exceptions/callback issues registered inside the loop.
    """
    msg = context.get("exception", context.get("message"))
    logger.error(f"Asyncio exception caught: {msg}", exc_info=True)
    # We don't stop the loop here to allow the application to continue

def task_factory(loop, coro):
    """
    Custom task factory that logs every task creation and completion.
    """
    task = asyncio.Task(coro, loop=loop)
    task_name = task.get_name() if hasattr(task, "get_name") else f"Task-{id(task)}"
    logger.debug(f"Task created: {task_name} for coroutine: {coro}")
    
    def log_task_done(t):
        try:
            if t.exception():
                logger.debug(f"Task finished: {task_name} with exception: {t.exception()}")
            else:
                logger.debug(f"Task finished: {task_name} successfully")
        except asyncio.CancelledError:
            logger.debug(f"Task cancelled: {task_name}")
        except Exception as e:
            logger.error(f"Error logging task completion: {e}", exc_info=True)
    
    task.add_done_callback(log_task_done)
    return task

# Configure asyncio loop with enhanced logging when available
try:
    loop = asyncio.get_running_loop()
    loop.set_debug(True)
    loop.set_exception_handler(handle_asyncio_exception)
    loop.set_task_factory(task_factory)

    # --- Instrument subDomainEnumSync ---
    # Wrap the imported subDomainEnumSync to add detailed logging of its execution.
    _original_subDomainEnumSync = subDomainEnumSync  # Save original reference

    def instrumented_subDomainEnumSync(domain, future):
        logger.info(f"subDomainEnumSync: START enumeration for domain: {domain}")
        try:
            logger.debug(f"subDomainEnumSync: Loading wordlist for domain: {domain}")
            result = _original_subDomainEnumSync(domain, future)
            logger.info(f"subDomainEnumSync: COMPLETED enumeration for domain: {domain}")
            return result
        except Exception as e:
            logger.error(f"subDomainEnumSync: ERROR during enumeration for domain: {domain}", exc_info=True)
            raise

    # Override the imported function with the instrumented version
    subDomainEnumSync = instrumented_subDomainEnumSync
    logger.info("Enhanced asyncio logging configured for existing loop")
except RuntimeError:
    logger.info("No running event loop found, will configure when loop starts")
# --- End Enhanced AsyncIO Logging Configuration ---


mcpServer = FastMCP("PENTEST-MCP-SERVER")
app = FastAPI()

USER_AGENT = "pentest-app/1.0"

@mcpServer.resource(uri = "file://home/seyrup/Projects_Private/config/subdomains-uk-1000.txt")
def common_subdomain_list():
    """List of common subdomains used for enumeration, loaded from a file"""
    filename = "/home/seyrup/Projects_Private/config/subdomains-uk-1000.txt"  # Change this to your preferred path
    filename = "/home/seyrup/Projects_Private/config/n0kovo_subdomains/n0kovo_subdomains_huge.txt"
    logger.debug(f"Attempting to load common subdomains from {filename}")
    try:
        with open(filename, "r") as file:
            subdomains = [line.strip() for line in file if line.strip()]
        logger.info(f"Loaded {len(subdomains)} subdomains from {filename}")
        return subdomains
    except FileNotFoundError:
        logger.warning(f"Subdomain file {filename} not found, using default list")
        return ["www", "mail", "ftp", "localhost", "webmail", "smtp", "admin", "blog",
            "dev", "test", "portal", "ns1", "ns2", "server", "vpn", "api", "cdn",
            "cloud", "auth", "secure", "shop", "store", "m", "mobile", "app"]
    except Exception as e:
        logger.error(f"Error loading subdomains from {filename}: {e}", exc_info=True)
        return [] # Return empty list on other errors


@mcpServer.resource(uri = "file:///home/seyrup/Projects_Private/config/WordLists-20111129/Directories_All.txt")
def common_directories():
    """List of common directory names used for enumeration, loaded from a file"""
    filename = "/home/seyrup/Projects_Private/config/WordLists-20111129/Directories_All.txt"  # Change this to your preferred path
    logger.debug(f"Attempting to load common directories from {filename}")
    try:
        with open(filename, "r") as file:
            directoriesList = [line.strip() for line in file if line.strip()]
        logger.info(f"Loaded {len(directoriesList)} directories from {filename}")
        return directoriesList
    except FileNotFoundError:
        logger.warning(f"Directory list file {filename} not found, using default list")
        # Log to stderr as well for immediate visibility - REMOVED as per request
        # print(f"Warning: {filename} not found, using default list", file=sys.stderr)
        return ["admin", "backup", "config", "dashboard", "db", "debug", "images",
            "inc", "include", "js", "log", "login", "old", "private", "robots.txt",
            "scripts", "secret", "temp", "test", "upload", "uploads", "wp-admin", "wp-content"]
    except Exception as e:
        logger.error(f"Error loading directories from {filename}: {e}", exc_info=True)
        return []


@mcpServer.resource(uri = "file:///home/seyrup/Projects_Private/config/vulnerability_list.json")
def known_vulnerability_patterns():
    """Common patterns to look for in web applications"""
    filename = "/home/seyrup/Projects_Private/config/vulnerability_list.json"  # Change this to your preferred path
    logger.debug(f"Attempting to load vulnerability patterns from {filename}")
    try:
        with open(filename, "r") as file:
            vulnerabilityList = json.load(file)
        logger.info(f"Loaded vulnerability patterns from {filename}")
        return vulnerabilityList
    except FileNotFoundError:
        logger.warning(f"Vulnerability patterns file {filename} not found, using default list")
        # Log to stderr as well - REMOVED
        # print(f"Warning: {filename} not found, using default list", file=sys.stderr)
        return {
            "file_inclusion": ["include=", "file=", "path=", "page="],
            "sql_injection": ["id=", "category=", "view=", "item="],
            "xss": ["search=", "q=", "query=", "s="],
            "open_redirect": ["url=", "redirect=", "next=", "target="]
        }
    except json.JSONDecodeError as e:
         logger.error(f"Error decoding JSON from {filename}: {e}", exc_info=True)
         return {}
    except Exception as e:
        logger.error(f"Error loading vulnerability patterns from {filename}: {e}", exc_info=True)
        return {}

# Fix the webSearch function - there was a typo in "reults"
@mcpServer.tool()
async def port_scanner(ip: str, startPort: int, endPort: int, domain: str, timeout: float):
    """
    Scan a range of ports on a given domain to see which of those ports are open. The services and OS running on those ports and the if a CDN is present.

    Args:
        ip: IP address of the domain to be scanned.
        startPort: starting number of the range of ports to be scanned.
        endPort: ending number of the range of ports to be scanned.
        domain: domain name to be scanned.
        timeout: timeout, in seconds, between successive scans.

    Returns:
        List of open ports for a given IP address/domain along with the possible service and Operating System running on that port.
    """
    tool_name = "port_scanner"
    target_info = f"{domain} ({ip}), ports {startPort}-{endPort}, scan_timeout={timeout}"
    logger.info(f"Starting {tool_name} for {target_info}")
    operation_timeout = 300.0 # Timeout for the entire operation
    try:
        logger.debug(f"[{tool_name}] Calling portScanner4LLM for {target_info} with operation timeout {operation_timeout}s")

        # Directly await the portScanner4LLM coroutine, assuming it's async
        # Remove the unnecessary future and run_in_executor call
        result = await asyncio.wait_for(
            portScanner4LLM(ip=ip, startPort=startPort, endPort=endPort, domain=domain, timeout=timeout), # Pass arguments correctly
            timeout=operation_timeout
        )

        logger.info(f"Successfully completed {tool_name} for {target_info}")
        return result
    except asyncio.TimeoutError:
        logger.error(f"[{tool_name}] Operation timed out after {operation_timeout}s for {target_info}")
        return {"error": f"{tool_name} operation timed out"}
    except Exception as e:
        # Log the full traceback for better debugging
        logger.error(f"Error during {tool_name} for {target_info}: {e}", exc_info=True)
        return {"error": str(e)}

@mcpServer.tool()
async def dns_enumerator(domain: str):
    """
    Retrieve all DNS records of a given domain and resolves all CNAME record chains as well as analyses the SPF and DMARC records. Also tests for zone transfer vulnerability.

    Args:
        domain: domain name whoose DNS recirds will be retrieved and analysed.

    Returns:
        Dictionary containing the domain name, DNS records and results of zone transfer and SPF DMARC analysis.
    """
    tool_name = "dns_enumerator"
    target_info = f"domain: {domain}"
    logger.info(f"Starting {tool_name} for {target_info}")
    try:
        # Set a timeout for the operation - increased timeout
        operation_timeout = 180.0
        logger.debug(f"[{tool_name}] Calling dnsEnumerator for {target_info} with operation timeout {operation_timeout}s")
        result = await asyncio.wait_for(dnsEnumerator(domain), timeout=operation_timeout)
        logger.info(f"Successfully completed {tool_name} for {target_info}")
        return result
    except asyncio.TimeoutError:
        logger.error(f"[{tool_name}] Operation timed out after {operation_timeout}s for {target_info}")
        return {"error": f"{tool_name} operation timed out"}
    except Exception as e:
        logger.error(f"Error during {tool_name} for {target_info}: {e}", exc_info=True)
        return {"error": str(e)}

@mcpServer.tool()
async def dir_enumerator(domain: str):
    """
    Retrieve all unsecured directories' list for a given domain by brute force.

    Args:
        domain: domain name for which enumeration will be performed

    Returns:
        List of directories on the domain that have not been secured and are accessible.
    """
    tool_name = "dir_enumerator"
    target_info = f"domain: {domain}"
    logger.info(f"Starting {tool_name} for {target_info}")
    try:
        # Set a timeout for the operation
        operation_timeout = 300.0
        logger.debug(f"[{tool_name}] Calling dirEnum4LLM for {target_info} with operation timeout {operation_timeout}s")
        result = await asyncio.wait_for(dirEnum4LLM(domain), timeout=operation_timeout) # Added timeout
        logger.info(f"Successfully completed {tool_name} for {target_info}")
        return result
    except asyncio.TimeoutError:
        logger.error(f"[{tool_name}] Operation timed out after {operation_timeout}s for {target_info}")
        return {"error": f"{tool_name} operation timed out"}
    except Exception as e:
        logger.error(f"Error during {tool_name} for {target_info}: {e}", exc_info=True)
        return {"error": str(e)}

@mcpServer.tool()
async def subdomain_enumerator(domain: str):
    """
    Using a list of possible sub-domains, finds the sub-domains for a given domain by brute force and analyses their headers.
    This function wraps the synchronous subDomainEnumSync function using run_in_executor.

    Args:
        domain: domain name for which enumeration will be performed

    Returns:
        List of sub-domains for the domain and their headers, or an error dictionary.
    """
    tool_name = "subdomain_enumerator"
    target_info = f"domain: {domain}"
    logger.info(f"Starting {tool_name} for {target_info}")
    operation_timeout = 300.0 # Timeout for the entire operation

    try:
        loop = asyncio.get_running_loop()
        loop.set_debug(True)
        logging.getLogger("asyncio").setLevel(logging.DEBUG) # Make asyncio logger output DEBUG messages
        logging.getLogger("asyncio").addHandler(log_handler)
        logger.info("Asyncio debug logging enabled.")
        future = loop.create_future()

        # functools.partial is used to pass arguments to the function
        # when it's called by the executor.
        # Ensure subDomainEnumSync is imported or defined above
        sync_call_with_args = functools.partial(subDomainEnumSync, domain, future)

        # Schedule the synchronous function to run in the default thread pool executor.
        logger.debug(f"[{tool_name}] Scheduling subDomainEnumSync for {target_info} in executor thread with timeout {operation_timeout}s")

        # Run the executor task with a timeout
        await asyncio.wait_for(
            loop.run_in_executor(None, sync_call_with_args),
            timeout=operation_timeout
        )

        logger.debug(f"[{tool_name}] subDomainEnumSync for {target_info} has finished executing in the thread.")

        # Now wait for the future that subDomainEnumSync should have populated.
        # Add a small extra timeout for the future itself, though it should be set
        # almost immediately after run_in_executor completes.
        logger.debug(f"[{tool_name}] Awaiting future result for {target_info}")
        result = await asyncio.wait_for(future, timeout=5.0) # Short timeout for future result

        logger.info(f"Successfully completed {tool_name} for {target_info}")
        return result

    except RuntimeError:
        logger.warning("Could not get event loop to enable debug logging yet. Ensure this runs before the loop starts.")
    except asyncio.TimeoutError:
        # This catches timeout from either wait_for call
        logger.error(f"[{tool_name}] Operation timed out after {operation_timeout}s (or during future wait) for {target_info}")
        # Attempt to set an error on the future if it wasn't done, although it might be too late
        if not future.done():
            try:
                future.set_exception(asyncio.TimeoutError(f"{tool_name} timed out"))
            except asyncio.InvalidStateError:
                pass # Future might have been set just before timeout check
        return {"error": f"{tool_name} operation timed out"}
    except Exception as e:
        logger.error(f"Error during {tool_name} for {target_info}: {e}", exc_info=True)
        # Ensure the future is marked done with the exception if it wasn't already.
        if not future.done():
             try:
                 future.set_exception(e)
             except asyncio.InvalidStateError:
                 pass # Future might have been set concurrently
        return {"error": str(e)}

@mcpServer.tool()
async def web_crawler_proxy_hunter(domain: str):
    """
    Crawls external sources (Reddit, GitHub, DuckDuckGo) to find proxies, potentially related to the domain but not crawling the domain itself.
    NOTE: The description was updated to reflect the actual implementation in webCrawler_proxyHunter.py.

    Args:
        domain: The domain name, currently unused by the underlying function but kept for potential future use or context.

    Returns:
        Dictionary containing 'list_of_proxy_servers' or an error message.
    """
    tool_name = "web_crawler_proxy_hunter"
    # Domain isn't actually used by webCrawler_proxyHunter logic, but log it anyway
    target_info = f"domain context: {domain} (Note: domain not directly used by crawler logic)"
    logger.info(f"Starting {tool_name} ({target_info})")
    try:
        # Set a timeout for the operation
        operation_timeout = 6000.0 # Increased timeout
        logger.debug(f"[{tool_name}] Calling webCrawler_proxyHunter with operation timeout {operation_timeout}s")
        # The webCrawler_proxyHunter function itself needs better internal logging
        result = await asyncio.wait_for(webCrawler_proxyHunter(), timeout=operation_timeout) # Pass no args as per function def
        logger.info(f"Successfully completed {tool_name}")
        return result
    except asyncio.TimeoutError:
        logger.error(f"[{tool_name}] Operation timed out after {operation_timeout}s")
        return {"error": f"{tool_name} operation timed out"}
    except Exception as e:
        logger.error(f"Error during {tool_name}: {e}", exc_info=True)
        return {"error": str(e)}

@mcpServer.tool()
async def webSearch(query: str):
    """
    Function uses DuckDuckGo search engine to search the Internet.

    Args:
        query: string containing the query to search for

    Returns:
        List of objects containing results from the DuckDuckGo search engine. Each Object contains the title of the page, the URL of the page and its brief description.
    """
    tool_name = "webSearch"
    target_info = f"query: '{query}'"
    logger.info(f"Starting {tool_name} for {target_info}")
    try:
        # Using asyncio.to_thread for the synchronous DDGS library
        def sync_search():
             logger.debug(f"[{tool_name}] Executing synchronous DDGS search for {target_info}")
             # Add internal try/except within the thread for better error capture
             try:
                 with DDGS() as ddgs:
                     # Limiting results, consider making max_results an argument
                     results = list(ddgs.text(query, max_results=15))
                     logger.debug(f"[{tool_name}] Synchronous DDGS search completed for {target_info}, found {len(results)} results")
                     return results
             except Exception as thread_err:
                 logger.error(f"[{tool_name}] Error inside sync_search thread for {target_info}: {thread_err}", exc_info=True)
                 raise # Re-raise the exception so asyncio.to_thread catches it

        logger.debug(f"[{tool_name}] Calling sync_search via asyncio.to_thread for {target_info}")
        # Add a timeout to the thread execution itself if possible, though asyncio.to_thread doesn't directly support it.
        # A higher-level timeout might be needed if the thread hangs indefinitely. Consider asyncio.wait_for on the thread task if needed.
        results = await asyncio.to_thread(sync_search)
        logger.info(f"Successfully completed {tool_name} for {target_info}, found {len(results)} results.")
        return {'results': results}
    # No specific TimeoutError expected here unless the thread itself hangs for longer than a global timeout
    except Exception as error:
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

@mcpServer.tool()
async def webSearch4CVEs(technology: str):
    """
    Function uses DuckDuckGo search engine to search the cvedetails.com for Common Vulnerabilities and Exploits.

    Args:
        query: string containing the technology whose CVEs we are searching for.

    Returns:
        List of objects containing results from the DuckDuckGo search engine. Each Object contains the title of the page, the URL of the page and its brief description.
    """
    tool_name = "webSearch4CVEs"
    search_query = f"site:cvedetails.com {technology}"
    target_info = f"technology: '{technology}', query: '{search_query}'"
    logger.info(f"Starting {tool_name} for {target_info}")
    try:
        def sync_cve_search():
            logger.debug(f"[{tool_name}] Executing synchronous DDGS CVE search for {target_info}")
            try:
                with DDGS() as ddgs:
                    # Consider limiting results further if needed
                    results = list(ddgs.text(search_query, max_results=30))
                    logger.debug(f"[{tool_name}] Synchronous DDGS CVE search completed for {target_info}, found {len(results)} results")
                    return results
            except Exception as thread_err:
                 logger.error(f"[{tool_name}] Error inside sync_cve_search thread for {target_info}: {thread_err}", exc_info=True)
                 raise

        logger.debug(f"[{tool_name}] Calling sync_cve_search via asyncio.to_thread for {target_info}")
        results = await asyncio.to_thread(sync_cve_search)
        logger.info(f"Successfully completed {tool_name} for {target_info}, found {len(results)} results.")
        return {'results': results}
    except Exception as error:
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

@mcpServer.tool()
async def ingestText2DB(inputText: str, metadata: str):
    """
    The function ingests the information into a Chroma Vector Database in order to be retrieved and used in answering user queries.
    NOTE: This ingests the entire text as one chunk. Use 'process_and_ingest_documentation' for chunking.

    Args:
        inputText: The text information that will be stored in the vector database
        metadata: Text information detailing the origin of the text contained in the argument 'inputText'.

    Returns:
        The results of the operation of storing information in the vector database.
    """
    tool_name = "ingestText2DB"
    target_info = f"metadata: '{metadata}', text length: {len(inputText)}"
    logger.warning(f"Calling deprecated {tool_name} (single chunk) for {target_info}. Consider using process_and_ingest_documentation.")
    try:
        # Assuming ingest2DB from ingest2DB.py is already async
        logger.debug(f"[{tool_name}] Calling ingest2DB for {target_info}")
        results = await ingest2DB(inputText, metadata)
        logger.info(f"Successfully completed {tool_name} for {target_info}")
        return {"results": str(results)} # Ensure results are stringified if needed
    except Exception as error:
        logger.error(f"Error in {tool_name} for {target_info}: {error}", exc_info=True)
        return {'error': str(error)}

@mcpServer.tool()
async def getWebPages(url: str):
    """
    Functions returns the visible text content from the web page URL provided.

    Args:
        url: A URL of a webpage.

    Returns:
        Visible text present on the webpage or an error message.
    """
    tool_name = "getWebPages"
    target_info = f"url: {url}"
    logger.info(f"Starting {tool_name} for {target_info}")

    def tag_visible(element):
        if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
            return False
        if isinstance(element, Comment):
            return False
        return True

    try:
        # Use asyncio compatible HTTP client if possible, or run sync request in thread
        def sync_fetch():
            fetch_timeout = 20 # Timeout for the request itself
            logger.debug(f"[{tool_name}] Executing synchronous fetch for {target_info} with timeout {fetch_timeout}s")
            try:
                request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
                with urllib.request.urlopen(request, timeout=fetch_timeout) as response:
                     content_type = response.headers.get('Content-Type', '').lower()
                     if 'text/html' not in content_type:
                         logger.warning(f"[{tool_name}] Content-Type for {url} is '{content_type}', not text/html. Parsing might be suboptimal.")
                     html = response.read()
                     charset = response.headers.get_content_charset() or 'utf-8'
                     logger.debug(f"[{tool_name}] Fetched {len(html)} bytes from {url}, status: {response.status}, charset: {charset}")
                     try:
                         return html.decode(charset)
                     except UnicodeDecodeError:
                         logger.warning(f"[{tool_name}] Failed to decode {url} with charset {charset}. Falling back to utf-8 with error handling.")
                         return html.decode('utf-8', errors='replace')
            except Exception as thread_err:
                 # Catch errors within urlopen/read/decode
                 logger.error(f"[{tool_name}] Error inside sync_fetch thread for {target_info}: {thread_err}", exc_info=True)
                 raise # Re-raise


        logger.debug(f"[{tool_name}] Calling sync_fetch via asyncio.to_thread for {target_info}")
        # Add a timeout wrapper around the to_thread call if needed (more complex)
        # operation_timeout = 30 # Overall timeout for the thread + parsing
        # html_content = await asyncio.wait_for(asyncio.to_thread(sync_fetch), timeout=operation_timeout)
        html_content = await asyncio.to_thread(sync_fetch)


        if not html_content:
             logger.warning(f"[{tool_name}] No content fetched from {url}")
             return {'visibleText': ''}

        logger.debug(f"[{tool_name}] Parsing HTML content ({len(html_content)} chars) from {url} using BeautifulSoup")
        soup = BeautifulSoup(html_content, 'html.parser')
        texts = soup.find_all(string=True) # Updated from findAll to find_all for newer bs4
        visible_texts = filter(tag_visible, texts)
        visibleText = " ".join(t.strip() for t in visible_texts if t.strip()) # Added check for non-empty stripped text
        logger.info(f"Successfully completed {tool_name} for {target_info}, extracted {len(visibleText)} characters.")
        return {'visibleText': visibleText}

    # except asyncio.TimeoutError: # Only if using wait_for around to_thread
    #     logger.error(f"[{tool_name}] Overall operation timed out for {target_info}")
    #     return {"error": f"Overall operation timed out"}
    except urllib.error.URLError as e:
        # Specifically log URL errors which often indicate network issues or timeouts within urlopen
        # This might be caught inside the thread now, but keep it here as a fallback
        if isinstance(e.reason, TimeoutError) or 'timed out' in str(e.reason).lower():
             logger.error(f"[{tool_name}] URL fetch timed out for {target_info}: {e.reason}")
             return {"error": f"URL fetch timed out: {e.reason}"}
        else:
             logger.error(f"[{tool_name}] URL Error fetching {target_info}: {e.reason}")
             return {"error": f"URL Error: {e.reason}"}
    except Exception as error:
        # Catch other potential errors (like thread errors re-raised, parsing errors)
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

# Define prompts for different penetration testing scenarios
@mcpServer.prompt("domain_reconnaissance")
def domain_recon_prompt():
    return """
    You are a cybersecurity analyst performing domain reconnaissance.

    First, enumerate the DNS records using dns_enumerator.
    Then, identify subdomains using subdomain_enumerator.
    Next, scan open ports and services with port_scanner.
    Finally, check for open directories with dir_enumerator.

    Analyze all findings and identify potential security weaknesses:
    - Exposed sensitive directories
    - Vulnerable services and outdated software
    - Misconfigured DNS records
    - Weak SPF/DMARC configurations

    Provide a comprehensive report with findings organized by severity (Critical, High, Medium, Low), including evidence and remediation suggestions.
    """

@mcpServer.prompt("web_vulnerability_assessment")
def web_vulnerability_prompt():
    return """
    You are a web application security specialist.
    Use the following steps to assess the security of the target web application:

    1. Identify the technology stack using `port_scanner` on relevant web ports (e.g., 80, 443, 8080). Note server banners and technologies.
    2. Perform initial reconnaissance using `webSearch` for publicly known vulnerabilities related to the identified technologies. Use `webSearch4CVEs` for specific technologies found.
    3. Crawl the website using `getWebPages` to understand its structure (Note: `web_crawler_proxy_hunter` searches external sites for proxies, it doesn't crawl the target domain).
    4. Check for common vulnerability patterns in URL parameters using the `known_vulnerability_patterns` resource. Craft potential test URLs based on discovered pages and patterns (DO NOT execute attacks, just identify possibilities).
    5. Evaluate directory security and look for exposed files/listings with `dir_enumerator`.

    Analyze the gathered information and look for potential indicators of:
    - Injection vulnerabilities (SQL, Command, etc.) based on parameter names and technology.
    - Cross-site scripting (XSS) opportunities based on parameter names (e.g., 'search', 'query').
    - Insecure direct object references (IDOR) if URL patterns suggest sequential IDs.
    - Security misconfigurations (e.g., verbose error messages, default credentials suggested by technology).
    - Broken authentication mechanism indicators (e.g., predictable session tokens in URLs - analyze, don't test).
    - Sensitive data exposure (e.g., comments in source code, accessible config files).

    Provide recommendations to remediate each potential vulnerability category identified. Structure the report clearly.
    """ # Updated step 3 description

@mcpServer.prompt("osint_investigation")
def osint_investigation_prompt():
    return """
    You are an OSINT (Open Source Intelligence) specialist investigating a target.
    Use the following tools systematically:
    1. Perform broad searches using `webSearch` for the target name, associated emails, known usernames, etc.
    2. If specific websites are identified as relevant, use `getWebPages` to extract their content for detailed analysis.
    3. If investigating a domain, use `dns_enumerator` to map technical infrastructure (MX, NS records etc.).
    4. If investigating a domain, use `subdomain_enumerator` to discover related subdomains and associated services.
    5. Search for CVEs related to technologies identified using `webSearch4CVEs`.

    Synthesize the information gathered to create a comprehensive profile including:
    - Technical infrastructure details (IP ranges, hosting providers, name servers, mail servers).
    - Digital footprint and online presence (websites, social media profiles, forum posts).
    - Potential security exposures revealed through public information (e.g., data breaches mentioning target emails, exposed credentials on paste sites found via search).
    - Associated entities and relationships (employees, partner companies found via search).
    - Technologies used and associated potential vulnerabilities (from CVE search).

    Organize findings by information source (e.g., DNS records, Web Search Result X, Page Content from URL Y) and assess the confidence level (Low, Medium, High) for each piece of information. Structure the final report clearly.
    """

@mcpServer.prompt("extract_propositions_with_context")
def extractPropositionAndContext():
    return """
    You are an diligent and mindful Assistant helping organize information into a databse efficiently.

    Follow these steps to decompose text into clear and simple propositions that can be easily stored and retrieved from a vector database:
    - Split every compound sentence into separate simple sentences, preserving the original phrasing from the text whenever possible.
    - For any named entity (e.g., person, place, organization) with additional descriptive information, create a separate proposition for that information.
    - Contextualize each proposition by adding necessary text blocks or entire sentences from the input and replacing pronouns (e.g., "it", "he", "she", "they", "this", "that") with the full name of the entities they refer to.
    - Present the results as a list of strings, where each string is a proposition that can be understood independently without relying on other propositions.
    - Add short succinct context that will be situated as part of each proposition for the purpose of improving search retrieval of the chunk.
    - Do not summarize the text; extract propositions that are fully interpretable and contain sufficient and extensive context.
    """

# --- New Tool for Processing and Ingesting Documentation ---
@mcpServer.tool()
async def process_and_ingest_documentation(documentation_text: str, library_name: str, language: str, source_url: str):
    """
    Processes retrieved documentation text by chunking it and ingesting
    it into the vector database.

    Args:
        documentation_text: The full text content retrieved from the documentation source.
        library_name: The name of the library the documentation is for.
        language: The programming language of the library.
        source_url: The URL from which the documentation was retrieved.

    Returns:
        A dictionary containing the list of generated chunk IDs or an error message.
    """
    tool_name = "process_and_ingest_documentation"
    target_info = f"library: {library_name}, lang: {language}, source: {source_url}, text length: {len(documentation_text)}"
    logger.info(f"Starting {tool_name} for {target_info}")

    if not documentation_text:
        logger.warning(f"[{tool_name}] No documentation text provided for {target_info}.")
        return {"error": "No documentation text provided."}

    # Construct metadata string
    metadata = f"Library: {library_name}, Language: {language}, Source: {source_url}"

    try:
        # Call the chunk_and_ingest function from ingest2DB.py
        # Assuming chunk_and_ingest handles potential errors internally and returns a dict
        logger.debug(f"[{tool_name}] Calling chunk_and_ingest for metadata: '{metadata}'")
        result = await chunk_and_ingest(
            full_text=documentation_text,
            source_metadata=metadata
            # Add chunk_size/overlap overrides here if needed, e.g.:
            # chunk_size=800,
            # chunk_overlap=100
        )

        if 'error' in result:
             logger.error(f"[{tool_name}] Chunking/Ingestion failed for {target_info}: {result.get('error')}", exc_info=True) # Added exc_info
             # Return the error structure from chunk_and_ingest
             return result
        else:
             logger.info(f"Successfully completed {tool_name} for {target_info}. Chunks: {len(result.get('chunk_ids', []))}")
             # Return the success structure from chunk_and_ingest
             return result

    except Exception as e:
        logger.error(f"Unexpected error calling {tool_name} for {target_info}: {e}", exc_info=True)
        return {"error": f"Unexpected error during processing/ingestion: {str(e)}"}


# --- New Prompt for Documentation Retrieval ---
@mcpServer.prompt("document_retrieval_and_ingestion")
def document_retrieval_prompt():
    return """
    You are a research assistant tasked with finding, retrieving, and ingesting documentation for a specific software library.

    Follow these steps for the requested library and language:

    1.  **Find Documentation URLs:** Use the `webSearch` tool to find the official documentation website or key documentation pages for the specified library and language. Prioritize official sources, readmes on code repositories (like GitHub, GitLab), or highly reputable community resources. Formulate queries like "[library_name] [language] documentation", "[library_name] official docs", "[library_name] tutorial".
    2.  **Select Key URLs:** From the search results, identify 1-3 promising URLs that seem to contain substantial documentation content (e.g., main documentation page, API reference, getting started guide).
    3.  **Retrieve Page Content:** For each selected URL, use the `getWebPages` tool to extract the visible text content.
    4.  **Process and Ingest:** Consolidate the text retrieved from the relevant pages. If multiple pages were retrieved, concatenate their text with clear separators (e.g., "\\n\\n--- Page: [URL] ---\\n\\n"). Then, call the `process_and_ingest_documentation` tool, providing the combined `documentation_text`, the `library_name`, the `language`, and the primary `source_url` (or a list if appropriate metadata handling is implemented).
    5.  **Report Results:** Confirm the successful ingestion by reporting the chunk IDs returned by the `process_and_ingest_documentation` tool, or report any errors encountered during the process.

    Be methodical and prioritize official sources. Ensure you pass all required arguments to the tools, especially `process_and_ingest_documentation`.
    """

@app.get("/mcp/tools")
async def list_tools_sse():
    async def event_generator():
        logger.info("SSE Request: Starting tools list stream")
        try:
            tools = list(mcpServer._tool_manager._tools.keys())
            logger.debug(f"Sending tools list: {tools}")
            yield {
                "event": "message",
                "data": json.dumps({"available_tools": tools})
            }
        except Exception as e:
            logger.exception(f"SSE Request: Error in tools stream: {e}")
            yield {
                "event": "error",
                "data": json.dumps({"error": f"Failed to list tools: {str(e)}"})
            }

    response = EventSourceResponse(event_generator(), headers={
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
    })
    logger.info(f"Response headers: {response.headers}")
    return response

@app.get("/mcp/tools/{tool_name}")
async def call_tool_sse(tool_name: str, arguments: str = "{}"):
    async def event_generator():
        logger.info(f"SSE Request: Calling tool {tool_name} with {arguments}")
        tool_args_dict = {}
        try:
            # Using json.loads is safer than eval
            tool_args_dict = json.loads(arguments)
        except json.JSONDecodeError:
            yield {"event": "error", "data": json.dumps({"error": "Invalid JSON arguments provided"})}
            return # Stop processing

        try:
            # Await call_tool first to get the async generator or result
            async_generator_or_result = await mcpServer._tool_manager.call_tool(tool_name, tool_args_dict, mcpServer.get_context())

            # Check if the result is an async iterator (like our async generator tool)
            if hasattr(async_generator_or_result, '__aiter__'):
                # Now iterate over the obtained async generator
                async for event in async_generator_or_result:
                    yield event
            else:
                # Handle cases where call_tool might return a direct result (not an iterator)
                # This might need adjustment based on FastMCP's behavior for non-generator tools
                logger.warning(f"Tool {tool_name} did not return an async iterator. Yielding single result.")
                # Assuming the result should be wrapped in the standard SSE format
                yield {"event": "message", "data": json.dumps({"result": async_generator_or_result})}

        except Exception as e:
             logger.exception(f"SSE Request: Error calling or iterating tool {tool_name}: {e}")
             yield {"event": "error", "data": json.dumps({"error": f"Failed to execute tool: {str(e)}"}) }

    return EventSourceResponse(event_generator())

if __name__ == "__main__":
    logger.info("Starting Server on Port 8080 . . .")
    # Basic check if the function is imported
    try:
        if not callable(subDomainEnumSync):
             logger.error("subDomainEnumSync function not found or not callable!")
             exit(1)
    except NameError:
         logger.error("subDomainEnumSync function not imported correctly!")
         exit(1)

    uvicorn.run(app, host="0.0.0.0", port=8080)
