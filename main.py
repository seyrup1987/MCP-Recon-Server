from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI, Request, HTTPException
from sse_starlette.sse import EventSourceResponse
import uvicorn
import json
import sys
import logging
import os
import asyncio
import requests
from duckduckgo_search import DDGS
from urllib.parse import urlparse
from bs4 import BeautifulSoup, Comment
from datetime import datetime
from tools.TechProbe import portScanner4LLM
from tools.SubdomainMapper import subDomainMapper4LLM
from tools.dnsEnumerator import dnsEnumerator4LLM # Assume async
from tools.ingest2DB import ingest2DB, chunk_and_ingest, queryDB# Assume async
from tools.ingestResults2DB import ingest_results_to_db

# --- Logging Configuration (Keep as is) ---
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(LOG_DIR, f"mcp_pentest_{timestamp}.log")
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Use StreamHandler for console output during development with FastAPI/Uvicorn
console_log_handler = logging.StreamHandler(sys.stdout)
console_log_handler.setFormatter(log_formatter)
console_log_handler.setLevel(logging.DEBUG) # Or INFO

# File Handler
file_handler = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_formatter)

# Get the main logger for your app
logger = logging.getLogger("mcp-pentest")
logger.setLevel(logging.DEBUG)

# Remove existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)
    try: handler.close() # Attempt to close handler
    except: pass

logger.addHandler(console_log_handler) # Add console handler first
logger.addHandler(file_handler)
logger.propagate = False # Prevent double logging if root logger is configured

mcpServer = FastMCP("PENTEST-MCP-SERVER")
app = FastAPI()

USER_AGENT = "pentest-app/1.0"

# --- Resources (Keep as is) ---
@mcpServer.resource(uri = "file://home/seyrup/Projects_Private/ReCon_Artist/config/subdomains-uk-1000.txt")
def common_subdomain_list():
    """List of common subdomains used for enumeration, loaded from a file"""
    # filename = "/home/seyrup/Projects_Private/config/subdomains-uk-1000.txt"
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
        logger.exception(f"Error loading subdomains from {filename}: {e}", exc_info=True)
        return []

@mcpServer.resource(uri = "file:///home/seyrup/Projects_Private/ReCon_Artist/config/WordLists-20111129/Directories_All.txt")
def common_directories():
    """List of common directory names used for enumeration, loaded from a file"""
    filename = "/home/seyrup/Projects_Private/config/WordLists-20111129/Directories_All.txt"
    logger.debug(f"Attempting to load common directories from {filename}")
    try:
        with open(filename, "r") as file:
            directoriesList = [line.strip() for line in file if line.strip()]
        logger.info(f"Loaded {len(directoriesList)} directories from {filename}")
        return directoriesList
    except FileNotFoundError:
        logger.warning(f"Directory list file {filename} not found, using default list")
        return ["admin", "backup", "config", "dashboard", "db", "debug", "images",
            "inc", "include", "js", "log", "login", "old", "private", "robots.txt",
            "scripts", "secret", "temp", "test", "upload", "uploads", "wp-admin", "wp-content"]
    except Exception as e:
        logger.exception(f"Error loading directories from {filename}: {e}", exc_info=True)
        return []

@mcpServer.resource(uri = "file:///home/seyrup/Projects_Private/ReCon_Artist/config/vulnerability_list.json")
def known_vulnerability_patterns():
    """Common patterns to look for in web applications"""
    filename = "/home/seyrup/Projects_Private/config/vulnerability_list.json"
    logger.debug(f"Attempting to load vulnerability patterns from {filename}")
    try:
        with open(filename, "r") as file:
            vulnerabilityList = json.load(file)
        logger.info(f"Loaded vulnerability patterns from {filename}")
        return vulnerabilityList
    except FileNotFoundError:
        logger.warning(f"Vulnerability patterns file {filename} not found, using default list")
        return {
            "file_inclusion": ["include=", "file=", "path=", "page="],
            "sql_injection": ["id=", "category=", "view=", "item="],
            "xss": ["search=", "q=", "query=", "s="],
            "open_redirect": ["url=", "redirect=", "next=", "target="]
        }
    except json.JSONDecodeError as e:
         logger.exception(f"Error decoding JSON from {filename}: {e}", exc_info=True)
         return {}
    except Exception as e:
        logger.exception(f"Error loading vulnerability patterns from {filename}: {e}", exc_info=True)
        return {}

mcpServer = FastMCP("PENTEST-MCP-SERVER")
app = FastAPI()

# Helper - Functions -
async def web_vulnerability_prompt():
    return """
            “Problem”: “get a list of all cities  in the country of USA and enumerate their bus stations.”
            "Resources": !!CHAT HISTORY!!
            “Tools”: {functions}
            "Function_Call_Format": [func_name1(params_name1=params_value1, params_name2=params_value2...), func_name2(params)].
            “Solution”: [
                {
                    "prompt": "get a list of cities  in USA using the GetCityList tool",
                }
                {
                    "prompt": "gather the list of cities from the prvious replies",
                }
                {
                    “prompt”: “get a list of bus stations for New York using the tool BusStationEnumerator”.
                }
                {
                    “prompt”: “get a list of bus stations for San Diego using the tool BusStationEnumerator”.
                }
                {
                    “prompt”: “get a list of bus stations for Boston using the tool BusStationEnumerator”.
                }
                {
                    “prompt”: “get a list of bus stations for Chicago using the tool BusStationEnumerator”.
                }
                ...
                ]
    """

async def store_recon_results(results_json: dict[str, any], source_info: str):
    """
    Stores structured reconnaissance results (JSON) in the 'Reconnaissance' DB collection.
    Use this to save structured outputs from tools like port scanners, enumerators, etc.

    Args:
        results_json: The JSON data (as a Python dictionary) to store.
        source_info: Metadata describing the source (e.g., 'port_scanner_scanme.org', 'dns_enum_example.com').

    Returns:
        A dictionary indicating success status and document ID, or an error dictionary.
    """
    tool_name = "store_recon_results"
    target_info = f"source: {source_info}, data type: JSON"
    logger.info(f"Starting {tool_name} for {target_info}")

    if not isinstance(results_json, dict):
        logger.error(f"[{tool_name}] Invalid input: 'results_json' must be a dictionary, got {type(results_json)}")
        return {"status": "error", "error": "Input 'results_json' must be a dictionary."}

    try:
        logger.debug(f"[{tool_name}] Calling ingest_results_to_db for {target_info}")
        ingestion_result = await ingest_results_to_db(
            json_data=results_json,
            source_metadata=source_info
        )

        if 'error' in ingestion_result:
            logger.error(f"[{tool_name}] Failed to store results for {target_info}: {ingestion_result['error']}")
            return {"status": "error", "error": f"Failed to store results: {ingestion_result['error']}"}
        else:
            doc_id = ingestion_result.get('id', 'N/A')  # Ensure id exists
            if doc_id == 'N/A':
                logger.warning(f"[{tool_name}] No 'id' returned in ingestion result for {target_info}")
            logger.info(f"Successfully completed {tool_name} for {target_info}. Result ID: {doc_id}")
            return {"status": "success", "message": f"Successfully stored results from {source_info}.", "id": doc_id}

    except Exception as e:
        logger.exception(f"Unexpected error during {tool_name} for {target_info}: {e}", exc_info=True)
        return {"status": "error", "error": f"An unexpected error occurred in the '{tool_name}' tool: {str(e)}"}

def validate_schema(params_schema):
    if not isinstance(params_schema, dict):
        return False
    required_fields = ['type', 'properties']
    return all(field in params_schema for field in required_fields) and \
           isinstance(params_schema.get('properties'), dict)

# --- Helper Functions for WebSearch ---
def is_valid_url(url: str) -> bool:
    """Check if a URL is valid and uses HTTP/HTTPS."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc != ''
    except Exception:
        return False

def calculate_relevance_score(result: dict, query: str) -> float:
    """Calculate a relevance score for a search result."""
    score = 0.0
    query_words = set(query.lower().split())
    
    # Title relevance (weight: 0.4)
    title = result.get('title', '').lower()
    title_matches = len([word for word in query_words if word in title])
    score += 0.4 * (title_matches / max(len(query_words), 1))
    
    # Description relevance (weight: 0.3)
    body = result.get('body', '').lower()
    body_matches = len([word for word in query_words if word in body])
    score += 0.3 * (body_matches / max(len(query_words), 1))
    
    # Content length (weight: 0.2)
    body_length = len(body)
    score += 0.2 * min(body_length / 200, 1.0)  # Cap at 200 chars
    
    # Source credibility (weight: 0.1)
    domain = urlparse(result.get('href', '')).netloc.lower()
    high_value_domains = {'.edu', '.gov', '.org', 'wikipedia.org', 'microsoft.com', 'apache.org', 'python.org'}
    if any(domain.endswith(d) for d in high_value_domains):
        score += 0.1
    
    return score

# --- Updated WebSearch Function ---
@mcpServer.tool()
async def WebSearch(query: str):
    """
    Use DuckDuckGo search to search the Internet, with filtering and ranking of results.

    Args:
        query: a string containing the text to search for on the Internet.

    Returns:
        List of filtered and ranked URLs that are the most relevant sources for the searched text.
    """
    tool_name = "webSearch"
    target_info = f"query: '{query}'"
    logger.info(f"Starting {tool_name} for {target_info}")
    
    try:
        def sync_search():
            logger.debug(f"[{tool_name}] Executing synchronous DDGS search for {target_info}")
            try:
                with DDGS() as ddgs:
                    results = list(ddgs.text(query, max_results=25))
                logger.debug(f"[{tool_name}] DDGS search found {len(results)} raw results")
                return results
            except Exception as thread_err:
                logger.error(f"[{tool_name}] Error inside sync_search thread: {thread_err}", exc_info=True)
                raise
        
        # Run synchronous search in a thread to avoid blocking
        results = await asyncio.to_thread(sync_search)
        
        # Verify results type
        if not isinstance(results, list):
            logger.error(f"[{tool_name}] Expected list from sync_search, got {type(results)}")
            return {"error": f"Invalid result type from search: {type(results)}"}
        
        logger.debug(f"[{tool_name}] Received {len(results)} raw results: {results[:2]}...")  # Log first 2 for brevity
        
        # Filter results
        blocklist_domains = {'twitter.com', 'facebook.com', 'instagram.com', 'pinterest.com', 'tiktok.com'}
        filtered_results = []
        for result in results:
            url = result.get('href', '')
            domain = urlparse(url).netloc.lower()
            # Apply filters
            if not is_valid_url(url):
                logger.debug(f"[{tool_name}] Skipping invalid URL: {url}")
                continue
            if not result.get('title') or not result.get('body'):
                logger.debug(f"[{tool_name}] Skipping result with missing title/body: {url}")
                continue
            if any(domain.endswith(blocked) for blocked in blocklist_domains):
                logger.debug(f"[{tool_name}] Skipping blocked domain: {domain}")
                continue
            filtered_results.append(result)
        
        logger.debug(f"[{tool_name}] Filtered to {len(filtered_results)} results")
        
        # Rank results
        ranked_results = sorted(
            filtered_results,
            key=lambda r: calculate_relevance_score(r, query),
            reverse=True
        )
        
        # Limit to top 15 results after ranking
        ranked_results = ranked_results[:15]
        logger.info(f"Successfully completed {tool_name} for {target_info}, returning {len(ranked_results)} ranked results")
        return {'results': ranked_results}
    
    except Exception as error:
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

@mcpServer.tool()
async def WebSearch4CVEs(technology: str):
    """
    Use DuckDuckGo search to search the website cvedetails.com for common vulnerabilities and exploits for the given technology.

    Args:
        technology: Technology for which common vulnerabilities and exploits will be searched for.

    Returns:
        List of URLs that are the most relevant sources for the searched text.
    """
    tool_name = "webSearch4CVEs"
    search_query = f"site:cvedetails.com {technology}"
    target_info = f"technology: '{technology}', query: '{search_query}'"
    logger.info(f"Starting {tool_name} for {target_info}")
    try:
        logger.debug(f"[{tool_name}] Executing synchronous DDGS CVE search for {target_info}")
        with DDGS() as ddgs:
            results = list(ddgs.text(search_query, max_results=30))
        logger.debug(f"[{tool_name}] DDGS CVE search found {len(results)} results")
        return {'results': results}
    except Exception as error:
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

@mcpServer.tool()
async def GetWebPages(url: str):
    """
    Gets visible text from a URL using 'requests'.
    
    Args:
        url: The URL whose visible text will be retreived.

    Returns:
        All of teh visible text in the web page of the URL.
    """
    tool_name = "getWebPages"
    target_info = f"url: {url}"
    logger.info(f"Starting {tool_name} for {target_info}")

    def tag_visible(element):
        if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']: return False
        if isinstance(element, Comment): return False
        return True

    try:
        fetch_timeout = 20
        logger.debug(f"[{tool_name}] Executing sync fetch for {target_info} (timeout {fetch_timeout}s)")
        response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=fetch_timeout, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()

        if 'text/html' not in content_type:
            logger.warning(f"[{tool_name}] Content-Type for {url} is '{content_type}', not text/html.")
        html_content = response.text # Use text for automatic decoding
        logger.debug(f"[{tool_name}] Fetched {len(response.content)} bytes from {response.url} (final URL), status: {response.status_code}")

        if not html_content:
             logger.warning(f"[{tool_name}] No content fetched from {url}")
             return {'visibleText': ''}

        logger.debug(f"[{tool_name}] Parsing HTML ({len(html_content)} chars) from {url}")
        soup = BeautifulSoup(html_content, 'html.parser')
        texts = soup.find_all(string=True)
        visible_texts = filter(tag_visible, texts)
        visibleText = " ".join(t.strip() for t in visible_texts if t.strip())
        logger.info(f"Successfully completed {tool_name} for {target_info}, extracted {len(visibleText)} chars.")
        return {'visibleText': visibleText}

    except requests.exceptions.Timeout:
        logger.error(f"[{tool_name}] Request timed out for {target_info}")
        return {"error": f"Request timed out fetching URL"}
    except requests.exceptions.HTTPError as e:
        logger.error(f"[{tool_name}] HTTP error for {target_info}: {e.response.status_code} {e.response.reason}")
        return {"error": f"HTTP Error: {e.response.status_code} {e.response.reason}"}
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[{tool_name}] Connection error for {target_info}: {e}")
        return {"error": f"Connection Error: {e}"}
    except requests.exceptions.RequestException as e:
        logger.error(f"[{tool_name}] Request error for {target_info}: {e}", exc_info=False)
        return {"error": f"Request Error: {e}"}
    except Exception as error:
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

@mcpServer.tool()
async def PortScanner(domain: str, startPort: int, endPort: int, storeResults: bool = False):
    """
    Scan the range of ports 1-10000 for a given domain and return the results containing a list of open ports and the services, OS as well as the web technology running on those ports.
    Stores the results if 'storeResults' is True.

    Args:
        domain: domain name to be scanned (for context/logging).
        storeResults: boolean indicating if the results of the function is to be stored in the vector database.

    Returns:
        List of open ports, between 1-10000, and operating system and the services running on them along with their versions.
    """
    try:
        logger.info(f"Executing portScanner tool for {domain} ports {startPort}-{endPort}")
        result = await portScanner4LLM(domain, 5.0)
        logger.info(f"portScanner for {domain} completed. Result keys: {list(result.keys()) if isinstance(result, dict) else 'Non-dict result'}")

        storeResults = storeResults.lower() == "true" if isinstance(storeResults, str) else bool(storeResults)
        if storeResults:
            storeOptn = await store_recon_results(result, f"PortScanner {domain}_{timestamp}")
            if storeOptn['status'] == 'success':
                return {'result': result, 'doc_id': storeOptn['id']}  # Fix: Use storeOptn['id']

        return result
    except Exception as error:
        logger.exception(f"Error Occurred while enumerating subdomains: {error}")
        raise error

@mcpServer.tool()
async def SubDomainEnumerator(domain: str, storeResults: bool = False):
    """
    Finds sub-domains for a given domain using brute-force and crt.sh,
    then resolves them. Returns a single JSON object with all results.
    Stores the results if 'storeResults' is True.

    Args:
        domain: domain name for which enumeration will be performed
        storeResults: boolean indicating if the results of the function is to be stored in the vector database.

    Returns:
        A dictionary containing the domain, timestamp, count, and a list of
        validated subdomains.
    """
    try:
        logger.info(f"Executing subdomain enumerator tool for {domain}")
        result = subDomainMapper4LLM(domain)
        logger.info(f"subdomain enumerator for {domain} completed. Result keys: {list(result.keys()) if isinstance(result, dict) else 'Non-dict result'}")

        storeResults = storeResults.lower() == "true" if isinstance(storeResults, str) else bool(storeResults)
        if storeResults:
            storeOptn = await store_recon_results(result, f"subDomainEnumerator_{domain}_{timestamp}")
            if storeOptn['status'] == 'success':
                return {'result': result, 'doc_id': storeOptn['id']}  # Fix: Use storeOptn['id']

        return result
    except Exception as error:
        logger.exception(f"Error Occurred while enumerating subdomains: {error}")
        raise error

@mcpServer.tool()
async def DnsEnumerator(domain: str, storeResults: bool = False):
    """
    Retrieve DNS records for a given domain and the results of a zone transfer attack as well as the SPF DMARC analysis. Stores the results if 'storeResults' is True.

    Args:
        domain: domain name for which the subdomain enumeration will be conducted.
        storeResults: boolean indicating if the results of the function is to be stored in the vector database.

    Returns:
        A list of DNS records for the given domain name, results for zone transfer attack and results for SPF DMARC analysis.
    """
    try:
        logger.info(f"Executing DNS enumerator tool for {domain}")
        result = await dnsEnumerator4LLM(domain)
        print("DEBUG LOG | result: ", result)
        logger.info(f"DNS enumerator for {domain} completed. Result keys: {list(result.keys()) if isinstance(result, dict) else 'Non-dict result'}")

        storeResults = storeResults.lower() == "true" if isinstance(storeResults, str) else bool(storeResults)
        if storeResults:
            storeOptn = await store_recon_results(result, f"DnsEnumerator{domain}_{timestamp}")
            if storeOptn['status'] == 'success':
                return {'result': result, 'doc_id': storeOptn['id']}  # Fix: Use storeOptn['id']

        return result
    except Exception as error:
        logger.exception(f"Error Occurred while enumerating subdomains: {error}")
        raise error

@mcpServer.tool()
async def IngestText2DB(inputText: str, metadata: str):
    """
    Ingests text (single chunk) into DB. Assumes ingest2DB is async.

    Args:
        inputText: Chunk of text to be stored into the vector database.
        metadata: Information detailing the origin of the information in 'inputText'.
    Returns:
        A dictionary containing a list of relevant documents/results found or an error message.
    """
    tool_name = "ingestText2DB"
    target_info = f"metadata: '{metadata}', text length: {len(inputText)}"
    logger.warning(f"Calling deprecated {tool_name} (single chunk) for {target_info}.")
    try:
        logger.debug(f"[{tool_name}] Calling ingest2DB for {target_info}")
        results = await ingest2DB(inputText, metadata) # Assuming async
        logger.info(f"Successfully completed {tool_name} for {target_info}")
        return {"results": str(results)}
    except Exception as error:
        logger.error(f"Error in {tool_name} for {target_info}: {error}", exc_info=True)
        return {'error': str(error)}

@mcpServer.tool()
async def QueryVectorDB(query: str, n_results: int = 5, collection: str = "documents"): # <-- Add collection parameter
    """
    Queries a specified Chroma vector database collection to find documents relevant to the input query.

    Args:
        query: The natural language query string to search for.
        n_results: The maximum number of relevant documents to return. Defaults to 5.
        collection: The name of the collection to query (e.g., "documents", "Reconnaissance"). Defaults to "documents".

    Returns:
        A dictionary containing a list of relevant documents/results found or an error message.
    """
    tool_name = "queryVectorDB"
    target_info = f"collection: '{collection}', query: '{query}', n_results: {n_results}" # <-- Update log info
    logger.info(f"Starting {tool_name} for {target_info}")

    try:
        logger.debug(f"[{tool_name}] Calling queryDB for {target_info}")
        # Pass the collection name to queryDB
        results = await queryDB(
            query_texts=[query],
            n_results=n_results,
            collection_name=collection # <-- Pass the collection name
        )

        if results is None:
            # Handle case where queryDB returned None (e.g., collection init failed)
            logger.error(f"[{tool_name}] queryDB returned None for {target_info}.")
            return {"error": f"Failed to query collection '{collection}'."}

        # Log the number of documents found
        found_count = len(results.get('documents', [[]])[0]) if results and results.get('documents') else 0
        logger.info(f"Successfully completed {tool_name} for {target_info}, found {found_count} potential results.")
        return {"results": results} # Return the raw results dictionary from Chroma

    except Exception as error:
        logger.error(f"Error during {tool_name} for {target_info}: {error}", exc_info=True)
        return {"error": str(error)}

@mcpServer.tool()
async def ProcessAndIngestDocumentation(documentation_text: str, library_name: str, language: str, source_url: str):
    """
    Chunks and ingests documentation. Assumes chunk_and_ingest is async.

    Args:
        documentation_text: Text from the documentation source.
        library_name: Name of the library for whom the documentation is for.
        language: Computer language for whom the documentation is for
        source_url: URL for the web page from where the information was retreieved.

    Returns:
        A dictionary indicating success status and document ID, or an error dictionary.
    """
    tool_name = "process_and_ingest_documentation"
    target_info = f"library: {library_name}, lang: {language}, source: {source_url}, text length: {len(documentation_text)}"
    logger.info(f"Starting {tool_name} for {target_info}")

    if not documentation_text:
        logger.warning(f"[{tool_name}] No documentation text provided for {target_info}.")
        return {"error": "No documentation text provided."}

    metadata = f"Library: {library_name}, Language: {language}, Source: {source_url}"
    try:
        logger.debug(f"[{tool_name}] Calling chunk_and_ingest for metadata: '{metadata}'")
        result = await chunk_and_ingest( # Assuming async
            full_text=documentation_text,
            source_metadata=metadata
        )
        if 'error' in result:
             logger.error(f"[{tool_name}] Chunking/Ingestion failed for {target_info}: {result.get('error')}")
             return result
        else:
             logger.info(f"Successfully completed {tool_name} for {target_info}. Chunks: {len(result.get('chunk_ids', []))}")
             return result
    except Exception as e:
        logger.error(f"Unexpected error calling {tool_name} for {target_info}: {e}", exc_info=True)
        return {"error": f"Unexpected error during processing/ingestion: {str(e)}"}

@app.get("/mcp/prompts")
async def listServerPrompts():
    prompt = await web_vulnerability_prompt()
    async def eventGenerator():
        if prompt:
            yield {
                "event": "prompt",
                "data": json.dumps({
                    "prompt": prompt
                })
            }
        else:
            yield {
                "event": "error",
                "data": json.dumps({
                    "error": "No Prompts available on MCP - Pentest -  Server"
                })
            }
    return EventSourceResponse(eventGenerator())

@app.get("/mcp/tools")
async def listServerTools():
    async def eventGenerator():
        request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
        logger.info(f"[SSE-{request_id}] Request received for tools list.")
        try:
            if hasattr(mcpServer, '_tool_manager') and hasattr(mcpServer._tool_manager, '_tools'):
                tools_dict = mcpServer._tool_manager._tools
                tool_schemas = []
                for name, tool_def in tools_dict.items():
                    try:
                        params_schema = getattr(tool_def, 'parameters', None)
                        if not params_schema:
                            params_schema = getattr(tool_def, 'inputSchema', None)
                            if not params_schema:
                                params_schema = getattr(tool_def, 'schema', {})
                        if not validate_schema(params_schema):
                            logger.warning(f"Invalid schema for tool '{name}', skipping.")
                            continue
                        tool_schemas.append({
                            "name": name,
                            "description": getattr(tool_def, 'description', f"Tool named {name}"),
                            "parameters": params_schema
                        })
                    except Exception as e:
                        logger.exception(f"[SSE-{request_id}] Error processing schema for tool '{name}': {e}")
                logger.info(f"[SSE-{request_id}] Prepared {len(tool_schemas)} valid tool schemas.")
                yield {"event": "tools_list", "data": json.dumps({"available_tools": tool_schemas})}
            else:
                logger.error(f"[SSE-{request_id}] Could not find tool dictionary.")
                yield {"event": "error", "data": json.dumps({"error": "Internal server error: Could not access tool definitions."})}
        except Exception as e:
            logger.exception(f"[SSE-{request_id}] Error occurred while listing tools: {e}")
            yield {"event": "error", "data": json.dumps({"error": f"Failed to list tools: {str(e)}"})}
        finally:
            logger.info(f"[SSE-{request_id}] Finished event generator for tools list.")
    return EventSourceResponse(eventGenerator())

@app.get("/mcp/tools/{tool_name}")
async def callMCPTool(request: Request, tool_name: str):
    request_id = datetime.now().strftime("%Y%m%d%H%M%S%f")
    logger.info(f"[SSE-Tool-{request_id}] Request received for tool '{tool_name}'")

    # Get the tool from the mcpServer's tool registry instead of globals()
    if hasattr(mcpServer, '_tool_manager') and hasattr(mcpServer._tool_manager, '_tools'):
        tool_def = mcpServer._tool_manager._tools.get(tool_name)
    else:
        tool_def = None

    if tool_def is None or not callable(tool_def):
        # Try MCP server tool registry attribute if one exists
        tool_func = getattr(tool_def, 'fn')
        # You may have to adapt this to your actual tool registry

    if tool_func is None or not callable(tool_func):
        async def error_gen():
             yield {"event": "error", "data": json.dumps({"error": f"Tool '{tool_name}' not found or invalid."})}
        return EventSourceResponse(error_gen(), status_code=404)

    # Extract query parameters
    params = {}
    if "arguments" in request.query_params:
        raw_args = request.query_params["arguments"]
        try:
            params = json.loads(raw_args)
            logger.info(f"[SSE-Tool-{request_id}] Parsed arguments for '{tool_name}': {params}")
        except json.JSONDecodeError as error:
            logger.error(f"[SSE-Tool-{request_id}] Invalid JSON in arguments for tool '{tool_name}': {error}. Raw args: {raw_args}")
            async def error_gen():
                yield {"event": "error", "data": json.dumps({"error": f"Invalid JSON arguments provided: {error}"})}
            return EventSourceResponse(error_gen(), status_code=400)
    else:
        # Handle case where args might be directly in query params (less common now)
        params = dict(request.query_params)
        logger.warning(f"[SSE-Tool-{request_id}] No 'arguments' query parameter found, using direct query params for '{tool_name}': {params}")


    async def event_generator():
        logger.debug(f"[SSE-Tool-{request_id}] Starting event generator for '{tool_name}'")
        try:
            # Yield initial status event
            yield {
                "event": "status", # Use 'status' as client expects this
                "data": json.dumps({"status": "started", "tool": tool_name, "message": f"Executing tool {tool_name}..."})
            }
            await asyncio.sleep(0.01) # Give client time to process status
            result = await tool_func(**params)
            logger.info(f"[SSE-Tool-{request_id}] Tool '{tool_name}' completed successfully.")
            logger.debug(f"[SSE-Tool-{request_id}] Result preview for '{tool_name}': {str(result)[:200]}...")

            # Serialize the result BEFORE yielding to catch errors
            try:
                json_result = json.dumps(result)
            except TypeError as json_err:
                 logger.error(f"[SSE-Tool-{request_id}] Tool '{tool_name}' result is not JSON serializable: {json_err}", exc_info=True)
                 yield {
                     "event": "error",
                     "data": json.dumps({"error": f"Tool '{tool_name}' produced a non-JSON-serializable result: {str(json_err)}"})
                 }
                 return # Stop the generator

            # Yield the final result
            yield {
                "event": "final_result",
                "data": json_result
            }
            logger.debug(f"[SSE-Tool-{request_id}] Sent final_result for '{tool_name}'.")

        except Exception as error:
            logger.exception(f"[SSE-Tool-{request_id}] Error during execution of tool '{tool_name}': {error}", exc_info=True)
            # Yield an error event in SSE format
            yield {
                "event": "error",
                "data": json.dumps({"error": f"Failed to execute {tool_name}: {str(error)}", "args": params})
            }
        finally:
             logger.info(f"[SSE-Tool-{request_id}] Event generator for tool '{tool_name}' finished.")

    # *** THE CRUCIAL FIX ***
    # Wrap the generator in EventSourceResponse to set the correct headers and stream
    return EventSourceResponse(event_generator())

def main():
    print("Hello from recon-artist!")
    uvicorn.run(app, host="0.0.0.0", port=8080, log_config=None)


if __name__ == "__main__":
    main()
