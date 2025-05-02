import praw
import json
import os
import re
import requests
from datetime import datetime
import pytz
from github import Github
from duckduckgo_search import DDGS
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import backoff

# Configuration
CONFIG_FILE = "../config/grokCrawler.json"
OUTPUT_DIR = "Output"
OUTPUT_FILE = os.path.join('..', 'config', "proxy_servers.txt")
PROXY_LIST_FILE = os.path.join('..', 'config', "proxy_list.txt")

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Utility Functions ---
def load_config():
    try:
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
            logger.info("Loaded config (keys hidden)")
            return config
    except Exception as e:
        logger.exception("Failed to load config: %s", e, exc_info=True) # Use logger.exception
        raise

def init_reddit():
    config = load_config()
    try:
        reddit = praw.Reddit(
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            user_agent=config["user_agent"],
            username=config["username"],
            password=config["password"]
        )
        logger.info("Reddit authenticated as: %s", reddit.user.me())
        return reddit
    except Exception as e:
        logger.exception("Reddit authentication failed: %s", e, exc_info=True) # Use logger.exception
        raise

def init_github():
    config = load_config()
    github_token = config.get("github_token")
    if not github_token or "your_github_token_here" in github_token:
        raise ValueError("Valid GitHub token required in config.")
    try:
        g = Github(github_token)
        logger.info("GitHub authenticated successfully")
        return g
    except Exception as e:
        logger.exception("GitHub authentication failed: %s", e, exc_info=True) # Use logger.exception
        raise

def is_valid_proxy(proxy):
    try:
        if ':' in proxy:
            ip, port = proxy.split(':')
            port = int(port)
            if not (0 <= port <= 65535):
                return False
        else:
            ip = proxy
        octets = ip.split('.')
        return len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets)
    except (ValueError, IndexError):
        return False

def find_proxies_in_text(text):
    proxy_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})\b'
    candidates = re.findall(proxy_pattern, text)
    valid_proxies = [p for p in candidates if is_valid_proxy(p)]
    if valid_proxies:
        logger.info("Found proxies: %s", valid_proxies)
    return valid_proxies

@backoff.on_exception(backoff.expo, (requests.RequestException, requests.Timeout), max_tries=3)
def scrape_url(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        proxies = find_proxies_in_text(response.text)
        logger.info("Scraped %s: found %d proxies", url, len(proxies))
        return proxies
    except requests.RequestException as e:
        logger.debug("Error scraping %s: %s", url, e)
        return []

# --- Optimized Crawling Functions with Threading and Error Handling ---

def crawl_reddit_submission(submission):
    """Process a single Reddit submission and its URL with retry logic."""
    proxies = []
    text = submission.title + " " + (submission.selftext if submission.is_self else "")
    found_proxies = find_proxies_in_text(text)
    proxies.extend(found_proxies)

    url_proxies = []
    if submission.url and not submission.url.startswith("https://www.reddit.com"):
        try:
            url_proxies = scrape_url(submission.url)
            proxies.extend(url_proxies)
        except Exception as e:
            logger.exception("Failed to scrape URL %s from submission %s: %s", submission.url, submission.id, e, exc_info=True) # Use logger.exception

    data = {
        "timestamp": datetime.now(pytz.UTC).isoformat(),
        "subreddit": submission.subreddit.display_name,
        "title": submission.title,
        "url": submission.url,
        "proxies": found_proxies + url_proxies
    }
    try:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")
    except IOError as e:
        logger.exception("Failed to write submission data for %s: %s", submission.id, e, exc_info=True) # Use logger.exception
    return proxies

def crawl_reddit_for_proxies(reddit, subreddit, term, max_retries=3):
    """Crawl a single subreddit with a search term, with retries."""
    proxies = []
    for attempt in range(max_retries):
        try:
            logger.info("Crawling r/%s for '%s' (attempt %d/%d)", subreddit, term, attempt + 1, max_retries)
            submissions = list(reddit.subreddit(subreddit).search(term, limit=50))
            logger.info("Fetched %d submissions from r/%s", len(submissions), subreddit)
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_submission = {executor.submit(crawl_reddit_submission, sub): sub for sub in submissions}
                for future in as_completed(future_to_submission):
                    try:
                        proxies.extend(future.result())
                    except Exception as e:
                        sub = future_to_submission[future]
                        logger.exception("Failed to process submission %s: %s", sub.id, e, exc_info=True) # Use logger.exception
            time.sleep(random.uniform(2, 5))  # Rate limit delay
            break
        except Exception as e:
            logger.exception("Error in r/%s for '%s' (attempt %d): %s", subreddit, term, attempt + 1, e, exc_info=True) # Use logger.exception
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logger.error("Max retries reached for r/%s '%s'", subreddit, term)
    return proxies

def crawl_reddit_parallel():
    reddit = init_reddit()
    subreddits = ["hacking", "pentest", "proxies", "netsec", "all"]
    search_terms = ["free proxy list", "working proxies 2025", "fresh proxies"]
    proxies = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {
            executor.submit(crawl_reddit_for_proxies, reddit, subreddit, term): (subreddit, term)
            for subreddit in subreddits
            for term in search_terms
        }
        for future in as_completed(future_to_task):
            subreddit, term = future_to_task[future]
            try:
                proxies.extend(future.result())
            except Exception as e:
                logger.exception("Failed task r/%s '%s': %s", subreddit, term, e, exc_info=True) # Use logger.exception
    return proxies

def crawl_github_repo(repo):
    """Process a single GitHub repository with error handling."""
    proxies = []
    logger.debug("Processing repo: %s", repo.full_name)
    try:
        contents = repo.get_contents("")
        for content_file in contents:
            if content_file.type == "file" and content_file.name.endswith((".txt", ".md")):
                try:
                    file_content = content_file.decoded_content.decode("utf-8", errors="ignore")
                    found_proxies = find_proxies_in_text(file_content)
                    proxies.extend(found_proxies)
                    if found_proxies:
                        logger.info("Found %d proxies in %s/%s", len(found_proxies), repo.full_name, content_file.name)
                except Exception as e:
                    logger.exception("Failed to process file %s in %s: %s", content_file.name, repo.full_name, e, exc_info=True) # Use logger.exception
        time.sleep(1)
    except Exception as e:
        logger.exception("Error in repo %s: %s", repo.full_name, e, exc_info=True) # Use logger.exception
    return proxies

def crawl_github_for_proxies(search_query="proxy list"):
    g = init_github()
    proxies = []
    logger.info("Starting GitHub search for '%s'...", search_query)
    try:
        repos = list(g.search_repositories(query=search_query, sort="updated", order="desc"))[:10]
        logger.info("Found %d repositories", len(repos))
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_repo = {executor.submit(crawl_github_repo, repo): repo for repo in repos}
            for future in as_completed(future_to_repo):
                try:
                    proxies.extend(future.result())
                except Exception as e:
                    repo = future_to_repo[future]
                    logger.exception("Failed to process repo %s: %s", repo.full_name, e, exc_info=True) # Use logger.exception
    except Exception as e:
        logger.exception("GitHub crawl error: %s", e, exc_info=True) # Use logger.exception
    return proxies

def crawl_duckduckgo_result(result):
    """Process a single DuckDuckGo search result with error handling."""
    proxies = []
    text = f"{result.get('title', '')} {result.get('body', '')}"
    found_proxies = find_proxies_in_text(text)
    proxies.extend(found_proxies)

    url = result.get("href", "")
    if url:
        try:
            url_proxies = scrape_url(url)
            proxies.extend(url_proxies)
        except Exception as e:
            logger.exception("Failed to scrape DuckDuckGo URL %s: %s", url, e, exc_info=True) # Use logger.exception

    data = {
        "timestamp": datetime.now(pytz.UTC).isoformat(),
        "title": result.get("title", ""),
        "url": url,
        "proxies": found_proxies + url_proxies
    }
    try:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")
    except IOError as e:
        logger.exception("Failed to write DuckDuckGo result %s: %s", url, e, exc_info=True) # Use logger.exception
    return proxies

def crawl_duckduckgo_for_proxies(search_query="free proxy list site:*.org site:*.edu site:*.gov -inurl:(login signup)", max_results=50):
    proxies = []
    logger.info("Starting DuckDuckGo search for '%s'...", search_query)
    for attempt in range(3):
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(search_query, max_results=max_results))
                logger.info("Fetched %d results", len(results))
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_result = {executor.submit(crawl_duckduckgo_result, result): result for result in results}
                    for future in as_completed(future_to_result):
                        try:
                            proxies.extend(future.result())
                        except Exception as e:
                            result = future_to_result[future]
                            logger.exception("Failed to process DuckDuckGo result %s: %s", result.get("href", "unknown"), e, exc_info=True) # Use logger.exception
                        time.sleep(random.uniform(1, 3))
                break
        except Exception as e:
            logger.exception("DuckDuckGo attempt %d failed: %s", attempt + 1, e, exc_info=True) # Use logger.exception
            if attempt < 2:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                logger.error("DuckDuckGo crawl failed after 3 attempts")
    return proxies

@backoff.on_exception(backoff.expo, (requests.RequestException, requests.Timeout), max_tries=3)
def test_proxy(proxy, timeout=5):
    try:
        proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        response = requests.get("https://www.google.com", proxies=proxies, timeout=timeout)
        logger.debug("Proxy %s tested: %s", proxy, response.status_code)
        return response.status_code == 200
    except requests.RequestException as e:
        logger.debug("Proxy %s failed: %s", proxy, e)
        return False

def validate_and_filter_proxies(proxies, max_workers=20):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {executor.submit(test_proxy, proxy): proxy for proxy in proxies}
        results = []
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                results.append((proxy, future.result()))
            except Exception as e:
                logger.exception("Failed to validate proxy %s: %s", proxy, e, exc_info=True) # Use logger.exception
    valid_proxies = [p for p, r in results if r]
    logger.info("Validated %d/%d proxies", len(valid_proxies), len(proxies))
    return valid_proxies

def save_proxy_list(proxies):
    unique_proxies = sorted(set(proxies))
    try:
        with open(PROXY_LIST_FILE, "w", encoding="utf-8") as f:
            for proxy in unique_proxies:
                f.write(f"{proxy}\n")
        logger.info("Saved %d proxies to %s", len(unique_proxies), PROXY_LIST_FILE)
    except IOError as e:
        logger.exception("Failed to save proxy list: %s", e, exc_info=True) # Use logger.exception

def crawl_all_sources():
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_reddit = executor.submit(crawl_reddit_parallel)
        future_github = executor.submit(crawl_github_for_proxies)
        future_ddgo = executor.submit(crawl_duckduckgo_for_proxies)

        reddit_proxies = future_reddit.result()
        github_proxies = future_github.result()
        ddgo_proxies = future_ddgo.result()

    all_proxies = reddit_proxies + github_proxies + ddgo_proxies
    unique_proxies = list(set(all_proxies))
    logger.info("Collected %d unique proxies", len(unique_proxies))

    valid_proxies = validate_and_filter_proxies(unique_proxies)
    if valid_proxies:
        save_proxy_list(valid_proxies)
    return valid_proxies

async def webCrawler_proxyHunter():
    try:
        list_of_proxy_servers = crawl_all_sources()
        if not list_of_proxy_servers:
            logger.warning("No valid proxies found.")
        return {
            'list_of_proxy_servers': list_of_proxy_servers
        }
    except Exception as e:
        logger.critical("Script failed critically: %s", e, exc_info=True) # Add exc_info=True
        raise

if __name__ == "__main__":
    try:
        list_of_proxy_servers = crawl_all_sources()
        if not list_of_proxy_servers:
            logger.warning("No valid proxies found.")
    except Exception as e:
        logger.critical("Script failed critically: %s", e, exc_info=True) # Add exc_info=True
        raise
