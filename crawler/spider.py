"""
Web Crawler (Spider) Module

This module handles crawling web pages to discover:
- URLs (links) within the same domain
- HTML forms with their parameters
- GET parameters in URLs

The crawler respects:
- Domain boundaries (stays on target domain)
- Maximum depth limits
- Maximum URL limits
- Request delays (to avoid overwhelming the server)
"""

import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from collections import deque
from typing import Dict, List, Set, Any, Optional

import requests
from bs4 import BeautifulSoup

from utils.logger import get_logger


class WebCrawler:
    """
    A web crawler that discovers URLs and forms on a target website.
    
    The crawler performs breadth-first traversal of web pages,
    extracting links and forms while staying within the same domain.
    
    Attributes:
        base_url (str): Starting URL for crawling
        max_depth (int): Maximum depth to crawl
        max_urls (int): Maximum number of URLs to discover
        timeout (int): Request timeout in seconds
        delay (float): Delay between requests
        user_agent (str): User-Agent header for requests
    """
    
    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        max_urls: int = 100,
        timeout: int = 10,
        delay: float = 0.5,
        user_agent: str = "WebVulnScanner/1.0"
    ):
        """
        Initialize the web crawler.
        
        Args:
            base_url: The starting URL to begin crawling
            max_depth: Maximum link depth to follow (default: 2)
            max_urls: Maximum number of URLs to collect (default: 100)
            timeout: HTTP request timeout in seconds (default: 10)
            delay: Delay between requests in seconds (default: 0.5)
            user_agent: Custom User-Agent string
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.delay = delay
        
        # Parse the base URL to get domain info
        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        
        # Setup session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        
        # Disable SSL warnings for testing (in production, verify should be True)
        self.session.verify = False
        
        # Logger
        self.logger = get_logger()
        
        # Storage for discovered resources
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        
        # File extensions to skip (non-HTML resources)
        self.skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.exe', '.dll', '.bin'
        }
    
    def is_same_domain(self, url: str) -> bool:
        """
        Check if a URL belongs to the same domain as the base URL.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is on the same domain, False otherwise
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.domain or parsed.netloc == ""
        except Exception:
            return False
    
    def normalize_url(self, url: str, current_page: str) -> Optional[str]:
        """
        Normalize a URL to its absolute form.
        
        Args:
            url: URL to normalize (can be relative or absolute)
            current_page: The page where this URL was found
            
        Returns:
            Normalized absolute URL, or None if invalid
        """
        try:
            # Skip empty URLs, anchors, javascript, and mailto links
            if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                return None
            
            # Convert relative URLs to absolute
            absolute_url = urljoin(current_page, url)
            
            # Parse and reconstruct to normalize
            parsed = urlparse(absolute_url)
            
            # Ensure it's HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return None
            
            # Check if it's the same domain
            if not self.is_same_domain(absolute_url):
                return None
            
            # Check for skip extensions
            path_lower = parsed.path.lower()
            for ext in self.skip_extensions:
                if path_lower.endswith(ext):
                    return None
            
            # Reconstruct URL without fragment
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized
            
        except Exception:
            return None
    
    def extract_links(self, html: str, current_url: str) -> Set[str]:
        """
        Extract all links from HTML content.
        
        Args:
            html: HTML content to parse
            current_url: URL of the current page
            
        Returns:
            Set of normalized URLs found in the page
        """
        links = set()
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract from <a href="...">
            for anchor in soup.find_all('a', href=True):
                url = self.normalize_url(anchor['href'], current_url)
                if url:
                    links.add(url)
            
            # Extract from <form action="...">
            for form in soup.find_all('form', action=True):
                url = self.normalize_url(form['action'], current_url)
                if url:
                    links.add(url)
            
            # Extract from <frame src="..."> and <iframe src="...">
            for frame in soup.find_all(['frame', 'iframe'], src=True):
                url = self.normalize_url(frame['src'], current_url)
                if url:
                    links.add(url)
            
            # Extract from <link href="..."> (for sitemaps, etc.)
            for link in soup.find_all('link', href=True):
                if link.get('rel') and 'stylesheet' not in link.get('rel', []):
                    url = self.normalize_url(link['href'], current_url)
                    if url:
                        links.add(url)
                        
        except Exception as e:
            self.logger.debug(f"Error extracting links from {current_url}: {e}")
        
        return links
    
    def extract_forms(self, html: str, current_url: str) -> List[Dict[str, Any]]:
        """
        Extract all forms from HTML content.
        
        Forms are important for vulnerability testing as they
        contain input fields that accept user data.
        
        Args:
            html: HTML content to parse
            current_url: URL of the current page
            
        Returns:
            List of form dictionaries with action, method, and inputs
        """
        forms_list = []
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            for form in soup.find_all('form'):
                form_data = {
                    'page_url': current_url,
                    'action': '',
                    'method': 'GET',
                    'inputs': []
                }
                
                # Get form action URL
                action = form.get('action', '')
                form_data['action'] = urljoin(current_url, action) if action else current_url
                
                # Get form method
                method = form.get('method', 'GET').upper()
                form_data['method'] = method if method in ['GET', 'POST'] else 'GET'
                
                # Extract all input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    
                    # Only include inputs with names
                    if input_data['name']:
                        form_data['inputs'].append(input_data)
                
                # Only add forms that have at least one named input
                if form_data['inputs']:
                    forms_list.append(form_data)
                    
        except Exception as e:
            self.logger.debug(f"Error extracting forms from {current_url}: {e}")
        
        return forms_list
    
    def extract_url_params(self, url: str) -> Dict[str, Any]:
        """
        Extract GET parameters from a URL.
        
        Args:
            url: URL to parse
            
        Returns:
            Dictionary with URL info and parameters
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                return {
                    'url': url,
                    'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    'params': {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                }
        except Exception:
            pass
        
        return None
    
    def fetch_page(self, url: str) -> Optional[requests.Response]:
        """
        Fetch a web page with error handling.
        
        Args:
            url: URL to fetch
            
        Returns:
            Response object if successful, None otherwise
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Only return if it's HTML content
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type or 'application/xhtml' in content_type:
                return response
                
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout fetching {url}")
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"Connection error fetching {url}")
        except requests.exceptions.TooManyRedirects:
            self.logger.debug(f"Too many redirects for {url}")
        except Exception as e:
            self.logger.debug(f"Error fetching {url}: {e}")
        
        return None
    
    def crawl(self, already_crawled: Set[str] = None) -> Dict[str, Any]:
        """
        Start crawling from the base URL.
        
        This method performs a breadth-first search of the website,
        discovering URLs and forms while respecting the configured limits.
        
        Args:
            already_crawled: Set of URLs already crawled (for resuming)
            
        Returns:
            Dictionary containing discovered URLs and forms
        """
        self.logger.info(f"Starting crawl from: {self.base_url}")
        
        # Initialize with already crawled URLs if resuming
        if already_crawled:
            self.visited_urls = already_crawled.copy()
        
        # Queue for BFS: (url, depth)
        queue = deque([(self.base_url, 0)])
        self.discovered_urls.add(self.base_url)
        
        urls_with_params = []
        
        while queue and len(self.discovered_urls) < self.max_urls:
            current_url, depth = queue.popleft()
            
            # Skip if already visited
            if current_url in self.visited_urls:
                continue
            
            # Skip if max depth exceeded
            if depth > self.max_depth:
                continue
            
            self.logger.debug(f"Crawling: {current_url} (depth: {depth})")
            
            # Fetch the page
            response = self.fetch_page(current_url)
            
            if response is None:
                continue
            
            self.visited_urls.add(current_url)
            
            # Extract URL parameters if present
            url_params = self.extract_url_params(current_url)
            if url_params:
                urls_with_params.append(url_params)
            
            html = response.text
            
            # Extract links
            new_links = self.extract_links(html, current_url)
            
            for link in new_links:
                if link not in self.discovered_urls and len(self.discovered_urls) < self.max_urls:
                    self.discovered_urls.add(link)
                    queue.append((link, depth + 1))
            
            # Extract forms
            page_forms = self.extract_forms(html, current_url)
            self.forms.extend(page_forms)
            
            # Respect delay between requests
            time.sleep(self.delay)
        
        self.logger.info(f"Crawl complete. Found {len(self.discovered_urls)} URLs, {len(self.forms)} forms")
        
        return {
            'urls': list(self.discovered_urls),
            'urls_with_params': urls_with_params,
            'forms': self.forms,
            'visited': list(self.visited_urls)
        }


def extract_injectable_points(urls: List[str], forms: List[Dict]) -> List[Dict]:
    """
    Extract all points where payloads can be injected.
    
    This includes:
    - GET parameters in URLs
    - POST parameters in forms
    - GET parameters in form actions
    
    Args:
        urls: List of discovered URLs
        forms: List of discovered forms
        
    Returns:
        List of injection points with their details
    """
    injection_points = []
    
    # Extract from URLs with GET parameters
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            for param_name in params:
                injection_points.append({
                    'type': 'url_param',
                    'url': url,
                    'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    'method': 'GET',
                    'param_name': param_name,
                    'original_value': params[param_name][0] if params[param_name] else ''
                })
    
    # Extract from forms
    for form in forms:
        for input_field in form['inputs']:
            # Skip hidden, submit, and button types for injection
            if input_field['type'] in ['submit', 'button', 'image', 'reset']:
                continue
            
            injection_points.append({
                'type': 'form_param',
                'url': form['action'],
                'page_url': form['page_url'],
                'method': form['method'],
                'param_name': input_field['name'],
                'original_value': input_field['value'],
                'all_inputs': form['inputs']
            })
    
    return injection_points
