"""
Security Headers Scanner Module

Checks for missing or misconfigured security headers that
can leave the application vulnerable to various attacks.

Missing security headers can lead to:
- Clickjacking attacks (missing X-Frame-Options)
- XSS exploitation (missing Content-Security-Policy)
- MIME sniffing attacks (missing X-Content-Type-Options)
- Information disclosure (missing security headers)
"""

from typing import Dict, List, Any

from scanner.base import BaseScanner


class HeadersScanner(BaseScanner):
    """
    Scanner for checking security headers.
    
    This scanner analyzes HTTP response headers for common
    security headers that should be configured.
    """
    
    @property
    def name(self) -> str:
        return "Security Headers Scanner"
    
    @property
    def severity(self) -> str:
        return "Medium"
    
    def __init__(self, timeout: int = 10):
        super().__init__(timeout=timeout, delay=0)
        
        # Important security headers to check
        self.security_headers = {
            'X-Frame-Options': {
                'severity': 'Medium',
                'description': (
                    "X-Frame-Options header is missing. This header prevents "
                    "the page from being loaded in an iframe, protecting against "
                    "clickjacking attacks."
                ),
                'recommendation': (
                    "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' "
                    "header to responses. Alternatively, use Content-Security-Policy "
                    "frame-ancestors directive."
                ),
                'valid_values': ['DENY', 'SAMEORIGIN']
            },
            'X-Content-Type-Options': {
                'severity': 'Low',
                'description': (
                    "X-Content-Type-Options header is missing. This header "
                    "prevents MIME-type sniffing which can lead to security issues."
                ),
                'recommendation': "Add 'X-Content-Type-Options: nosniff' header.",
                'valid_values': ['nosniff']
            },
            'X-XSS-Protection': {
                'severity': 'Info',
                'description': (
                    "X-XSS-Protection header is missing. While deprecated in modern "
                    "browsers, it can provide protection in older browsers."
                ),
                'recommendation': (
                    "Add 'X-XSS-Protection: 1; mode=block' header. Note: Modern "
                    "browsers have removed XSS Auditor, rely on CSP instead."
                ),
                'valid_values': ['1', '1; mode=block']
            },
            'Content-Security-Policy': {
                'severity': 'Medium',
                'description': (
                    "Content-Security-Policy header is missing. CSP helps prevent "
                    "XSS, clickjacking, and other code injection attacks."
                ),
                'recommendation': (
                    "Implement a Content-Security-Policy header. Start with a "
                    "report-only policy to test, then enforce. Example: "
                    "Content-Security-Policy: default-src 'self'"
                ),
                'valid_values': None  # Complex header, any value is a start
            },
            'Strict-Transport-Security': {
                'severity': 'Medium',
                'description': (
                    "Strict-Transport-Security (HSTS) header is missing on HTTPS. "
                    "HSTS tells browsers to always use HTTPS, preventing "
                    "downgrade attacks and cookie hijacking."
                ),
                'recommendation': (
                    "Add HSTS header for HTTPS sites: "
                    "'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
                ),
                'valid_values': None,
                'https_only': True
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'description': (
                    "Referrer-Policy header is missing. This header controls how "
                    "much referrer information is included with requests."
                ),
                'recommendation': (
                    "Add 'Referrer-Policy: strict-origin-when-cross-origin' or "
                    "'Referrer-Policy: no-referrer' for sensitive pages."
                ),
                'valid_values': [
                    'no-referrer',
                    'no-referrer-when-downgrade',
                    'same-origin',
                    'origin',
                    'strict-origin',
                    'origin-when-cross-origin',
                    'strict-origin-when-cross-origin'
                ]
            },
            'Permissions-Policy': {
                'severity': 'Low',
                'description': (
                    "Permissions-Policy header is missing. This header controls "
                    "which browser features can be used (camera, microphone, etc.)."
                ),
                'recommendation': (
                    "Add Permissions-Policy header to restrict unnecessary features. "
                    "Example: 'Permissions-Policy: geolocation=(), microphone=()'"
                ),
                'valid_values': None
            }
        }
        
        # Headers that should NOT be present (information disclosure)
        self.bad_headers = {
            'Server': {
                'severity': 'Info',
                'description': (
                    "Server header reveals web server details which can help "
                    "attackers identify known vulnerabilities."
                ),
                'recommendation': "Remove or obfuscate the Server header."
            },
            'X-Powered-By': {
                'severity': 'Info',
                'description': (
                    "X-Powered-By header reveals technology stack details "
                    "(e.g., PHP version) which aids attacker reconnaissance."
                ),
                'recommendation': "Remove the X-Powered-By header."
            },
            'X-AspNet-Version': {
                'severity': 'Info',
                'description': "ASP.NET version is disclosed in response headers.",
                'recommendation': "Remove the X-AspNet-Version header."
            }
        }
    
    def check_headers(self, url: str, headers: Dict[str, str], is_https: bool) -> List[Dict]:
        """
        Check response headers for security issues.
        
        Args:
            url: The URL that was checked
            headers: Response headers dictionary
            is_https: Whether the URL uses HTTPS
            
        Returns:
            List of vulnerability dictionaries
        """
        vulns = []
        
        # Normalize header names to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for missing security headers
        for header_name, config in self.security_headers.items():
            header_lower = header_name.lower()
            
            # Skip HSTS check for non-HTTPS
            if config.get('https_only') and not is_https:
                continue
            
            if header_lower not in headers_lower:
                vuln = {
                    'type': f"Missing Security Header: {header_name}",
                    'url': url,
                    'parameter': header_name,
                    'payload': 'N/A',
                    'evidence': f"Header not present in response",
                    'severity': config['severity'],
                    'description': config['description'],
                    'recommendation': config['recommendation'],
                    'scanner': self.name
                }
                self.vulnerabilities.append(vuln)
                vulns.append(vuln)
        
        # Check for bad headers (information disclosure)
        for header_name, config in self.bad_headers.items():
            header_lower = header_name.lower()
            
            if header_lower in headers_lower:
                value = headers_lower[header_lower]
                
                # Skip if value is generic
                if header_lower == 'server' and value.lower() in ['', 'nginx', 'apache']:
                    continue
                
                vuln = {
                    'type': f"Information Disclosure: {header_name}",
                    'url': url,
                    'parameter': header_name,
                    'payload': 'N/A',
                    'evidence': f"{header_name}: {value}",
                    'severity': config['severity'],
                    'description': config['description'],
                    'recommendation': config['recommendation'],
                    'scanner': self.name
                }
                self.vulnerabilities.append(vuln)
                vulns.append(vuln)
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for security header issues.
        
        Only checks the main URLs (not each parameter variation).
        
        Args:
            urls: List of URLs to scan
            forms: Not used for this scanner
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        
        # We only need to check unique base URLs
        checked_urls = set()
        
        self.logger.info(f"  Checking security headers...")
        
        for url in urls:
            # Get base URL (without query string)
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            
            if base_url in checked_urls:
                continue
            
            checked_urls.add(base_url)
            
            try:
                response = self.make_request(url, method='GET')
                
                if response is None:
                    continue
                
                is_https = url.lower().startswith('https')
                self.check_headers(url, dict(response.headers), is_https)
                
            except Exception as e:
                self.logger.debug(f"Error checking headers for {url}: {e}")
        
        # Log summary
        if self.vulnerabilities:
            self.logger.info(
                f"  Found {len(self.vulnerabilities)} header issues"
            )
        
        return self.vulnerabilities
