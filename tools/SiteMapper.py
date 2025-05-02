import json
import glob
import re
import threading
import time
import os
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import requests as rq
from bs4 import BeautifulSoup
from icecream import ic
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Global variables
visited_links = set()
bad_urls = []
page_details = []
lock = threading.Lock()
proxy_server_list = []
wappalyzer_data = {}
vulnerability_list = {}
selenium_driver = None

def load_proxies(proxy_file_path: str = "../config/proxy_list.txt") -> list:
    """Load proxy servers from a file."""
    proxies = []
    try:
        with open(proxy_file_path, "r") as f:
            proxies = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        ic(f"Proxy file {proxy_file_path} not found.")
    return proxies

def get_response(url: str) -> rq.Response | None:
    """Fetch the response for a given URL, handling proxies and errors."""
    proxies = proxy_server_list.copy()
    while True:
        try:
            proxy = proxies[0] if proxies else None
            response = rq.get(url, proxies={"http": proxy, "https": proxy} if proxy else None, timeout=10)
            response.raise_for_status()
            return response
        except rq.RequestException as e:
            ic(f"Error fetching {url}: {e}")
            if proxy and proxies:
                proxies.pop(0)
                if not proxies:
                    ic(f"No more proxies available for {url}. Attempting direct request.")
                    proxies = [None]
            else:
                with lock:
                    bad_urls.append({"url": url, "error": str(e)})
                return None
        time.sleep(2)

def get_selenium_page(url: str, driver: webdriver.Chrome) -> tuple[str, dict, dict]:
    """Fetch rendered page content, headers, and cookies using Selenium."""
    try:
        driver.get(url)
        time.sleep(2)  # Wait for dynamic content
        html = driver.page_source
        
        # Get cookies
        cookies = {cookie['name']: cookie['value'] for cookie in driver.get_cookies()}
        
        # Get headers (using requests for headers, as Selenium doesn't provide them directly)
        headers = {}
        response = get_response(url)
        if response:
            headers = dict(response.headers)
        
        return html, headers, cookies
    except Exception as e:
        ic(f"Selenium error at {url}: {e}")
        return "", {}, {}

def check_vulnerabilities(url: str, html: str, headers: dict, cookies: dict) -> list:
    """Check for vulnerabilities based on VulnerabilityList.json."""
    matches = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # Check URL query parameters
    for category, patterns in vulnerability_list.items():
        if category in ['security_headers', 'cookie_attributes', 'security_products']:
            continue
        if isinstance(patterns, list):
            for pattern in patterns:
                for param in query_params:
                    if param == pattern or pattern in param:
                        matches.append({
                            "category": category,
                            "pattern": pattern,
                            "description": f"Found in URL query parameter: {param}"
                        })
        elif category == 'vulnerable_js_libraries':
            # Check script tags and inline scripts
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script'):
                src = script.get('src', '')
                content = script.string or ''
                for pattern in patterns:
                    try:
                        if re.search(pattern, src, re.IGNORECASE) or re.search(pattern, content, re.IGNORECASE):
                            matches.append({
                                "category": category,
                                "pattern": pattern,
                                "description": f"Found in script: {pattern}"
                            })
                    except re.error:
                        ic(f"Invalid regex pattern {pattern} for {category}")
        else:
            # Check HTML content for regex patterns
            for pattern in patterns:
                try:
                    if re.search(pattern, html, re.IGNORECASE):
                        matches.append({
                            "category": category,
                            "pattern": pattern,
                            "description": f"Found in HTML content: {pattern}"
                        })
                except re.error:
                    ic(f"Invalid regex pattern {pattern} for {category}")

    # Check security headers
    if 'security_headers' in vulnerability_list:
        for header in vulnerability_list['security_headers']['missing']:
            if header not in headers:
                matches.append({
                    "category": "security_headers",
                    "pattern": header,
                    "description": f"Missing security header: {header}"
                })
        for header, values in vulnerability_list['security_headers']['insecure_values'].items():
            if header in headers and headers[header] in values:
                matches.append({
                    "category": "security_headers",
                    "pattern": f"{header}: {headers[header]}",
                    "description": f"Insecure header value: {header}={headers[header]}"
                })

    # Check cookie attributes
    if 'cookie_attributes' in vulnerability_list:
        for cookie_name, cookie_value in cookies.items():
            # Selenium cookies don't provide attributes directly; assume missing for simplicity
            for attr in vulnerability_list['cookie_attributes']['missing']:
                matches.append({
                    "category": "cookie_attributes",
                    "pattern": attr,
                    "description": f"Cookie {cookie_name} missing attribute: {attr}"
                })
            # Insecure values not checked due to lack of attribute data in Selenium cookies

    return matches

def fingerprint_technologies(url: str, html: str, headers: dict, cookies: dict, wappalyzer_data: dict) -> list:
    """Detect technologies using Wappalyzer patterns on rendered content."""
    detected = []
    soup = BeautifulSoup(html, 'html.parser')
    
    for tech, rules in wappalyzer_data.items():
        # URL patterns
        if "url" in rules:
            patterns = rules["url"] if isinstance(rules["url"], list) else [rules["url"]]
            for pattern in patterns:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        detected.append(tech)
                        break
                except re.error:
                    ic(f"Invalid regex pattern {pattern} for {tech}")

        # HTML patterns
        if "html" in rules:
            patterns = rules["html"] if isinstance(rules["html"], list) else [rules["html"]]
            for pattern in patterns:
                try:
                    if re.search(pattern, html, re.IGNORECASE):
                        detected.append(tech)
                        break
                except re.error:
                    ic(f"Invalid regex pattern {pattern} for {tech}")

        # Headers
        if "headers" in rules:
            for header, pattern in rules["headers"].items():
                if header in headers:
                    try:
                        if not pattern or re.search(pattern, headers[header], re.IGNORECASE):
                            detected.append(tech)
                            break
                    except re.error:
                        ic(f"Invalid regex pattern {pattern} for {tech} header {header}")

        # Cookies
        if "cookies" in rules:
            for cookie_name, pattern in rules["cookies"].items():
                if cookie_name in cookies:
                    try:
                        if not pattern or re.search(pattern, cookies[cookie_name], re.IGNORECASE):
                            detected.append(tech)
                            break
                    except re.error:
                        ic(f"Invalid regex pattern {pattern} for {tech} cookie {cookie_name}")

        # JavaScript patterns
        if "js" in rules:
            patterns = rules["js"] if isinstance(rules["js"], list) else [rules["js"]]
            for script in soup.find_all('script'):
                src = script.get('src', '')
                content = script.string or ''
                for pattern in patterns:
                    try:
                        if re.search(pattern, src, re.IGNORECASE) or re.search(pattern, content, re.IGNORECASE):
                            detected.append(tech)
                            break
                    except re.error:
                        ic(f"Invalid regex pattern {pattern} for {tech}")

    return list(set(detected))

def site_mapper(current_url: str, depth: int = 0, driver: webdriver.Chrome = None):
    """Recursively crawl a website and map its pages."""
    if depth > MAXIMUM_DEPTH:
        return

    with lock:
        if current_url in visited_links:
            return
        visited_links.add(current_url)

    try:
        # Use Selenium to render page
        html, headers, cookies = get_selenium_page(current_url, driver)
        if not html:
            with lock:
                bad_urls.append({"url": current_url, "error": "Failed to load with Selenium"})
            return

        page_info = {"url": current_url, "status_code": 200}  # Assume 200 for Selenium-loaded pages

        # Check vulnerabilities
        vuln_matches = check_vulnerabilities(current_url, html, headers, cookies)
        if vuln_matches:
            page_info["vulnerability_matches"] = vuln_matches
            # Fingerprint technologies if vulnerabilities are found
            technologies = fingerprint_technologies(current_url, html, headers, cookies, wappalyzer_data)
            if technologies:
                page_info["technologies"] = technologies

        with lock:
            page_details.append(page_info)

        # Extract links
        soup = BeautifulSoup(html, "html.parser")
        components = urlparse(current_url)
        domain = components.netloc

        hrefs = []
        for link in soup.find_all("a", href=True):
            href = link["href"]
            absolute_url = urljoin(current_url, href)
            parsed_url = urlparse(absolute_url)
            if parsed_url.netloc == domain:
                hrefs.append(absolute_url)

        # Crawl linked pages in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(lambda url: site_mapper(url, depth + 1, driver), hrefs)

    except Exception as e:
        ic(f"Unexpected error at {current_url}: {e}")
        with lock:
            bad_urls.append({"url": current_url, "error": str(e)})

def main():
    """Main function to initiate the site mapping process."""
    import argparse
    parser = argparse.ArgumentParser(description="SiteMapper: A web crawler with vulnerability and technology detection.")
    parser.add_argument("url", help="The starting URL to crawl")
    args = parser.parse_args()

    global proxy_server_list
    proxy_server_list = load_proxies()

    # Initialize Selenium WebDriver
    global selenium_driver
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    try:
        selenium_driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options
        )
    except Exception as e:
        ic(f"Failed to initialize Selenium WebDriver: {e}")
        return

    try:
        # Load Wappalyzer JSON files
        global wappalyzer_data
        for file in glob.glob("./TechFingerprint/*.json"):
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    wappalyzer_data.update(data)
            except Exception as e:
                ic(f"Error loading Wappalyzer file {file}: {e}")

        # Load VulnerabilityList.json
        global vulnerability_list
        try:
            with open("../config/VulnerabilityList.json", "r") as f:
                vulnerability_list = json.load(f)
            # Compile regex patterns where applicable
            for category, patterns in vulnerability_list.items():
                if isinstance(patterns, list) and category not in ['file_inclusion', 'sql_injection', 'xss', 'open_redirect', 'command_injection', 'ssrf', 'csrf_tokens', 'sensitive_form_fields', 'server_info', 'api_exposure', 'authentication_bypass', 'file_upload', 'session_handling']:
                    vulnerability_list[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        except Exception as e:
            ic(f"Error loading VulnerabilityList.json: {e}")
            vulnerability_list = {}

        # Start crawling
        components = urlparse(args.url)
        domain = components.netloc
        output_path = "./output"
        os.makedirs(output_path, exist_ok=True)

        site_mapper(args.url, driver=selenium_driver)

        # Save results
        output_data = {
            "website": domain,
            "pages": page_details,
            "invalid_urls": bad_urls
        }
        output_file = os.path.join(output_path, f"{domain}_sitemap.json")
        try:
            with open(output_file, "w") as f:
                json.dump(output_data, f, indent=4)
            ic(f"Output saved to {output_file}")
        except Exception as e:
            ic(f"Error saving output: {e}")

    finally:
        if selenium_driver:
            selenium_driver.quit()

if __name__ == "__main__":
    MAXIMUM_DEPTH = 100
    ic.configureOutput(
        outputFunction=lambda *a: open("site_mapper_debug_log.txt", "a").write(f"{a[0]}\n"),
        includeContext=True
    )
    main()