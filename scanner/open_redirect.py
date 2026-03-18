"""
Open Redirect Scanner Module

Detects Open Redirect vulnerabilities where user input controls
the destination of a redirect, allowing attackers to redirect
users to malicious sites.

Open redirect allows attackers to:
- Phish users by redirecting from trusted domains
- Steal credentials by redirecting to fake login pages
- Distribute malware through trusted-looking URLs
- Bypass security controls that trust the domain
"""

import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any

from scanner.base import BaseScanner
from utils.http_helper import (
    inject_payload_in_url,
    inject_payload_in_form,
    extract_params
)


class OpenRedirectScanner(BaseScanner):
    """
    Scanner for detecting Open Redirect vulnerabilities.
    
    This scanner tests URL parameters for redirects to external domains
    by checking response headers and status codes.
    """
    
    @property
    def name(self) -> str:
        return "Open Redirect Scanner"
    
    @property
    def severity(self) -> str:
        return "Medium"
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        super().__init__(timeout=timeout, delay=delay)
        
        # Test domain for redirect detection
        self.test_domain = "evil.example.com"
        
        # Open redirect payloads
        self.payloads = [
            # Basic redirects
            f"http://{self.test_domain}",
            f"https://{self.test_domain}",
            f"//{self.test_domain}",
            
            # Protocol-relative
            f"/\\{self.test_domain}",
            f"\\{self.test_domain}",
            
            # URL encoding
            f"http%3A%2F%2F{self.test_domain}",
            f"https%3A%2F%2F{self.test_domain}",
            f"%2F%2F{self.test_domain}",
            
            # Double encoding
            f"http%253A%252F%252F{self.test_domain}",
            
            # Subdomain bypass attempts
            f"http://trusted.com@{self.test_domain}",
            f"http://{self.test_domain}%23trusted.com",
            f"http://{self.test_domain}%2523trusted.com",
            
            # Slash manipulation
            f"/{self.test_domain}",
            f"/.{self.test_domain}",
            f"/../{self.test_domain}",
            
            # CRLF injection for header manipulation
            f"%0d%0aLocation: http://{self.test_domain}",
            
            # JavaScript redirect
            f"javascript:document.location='http://{self.test_domain}'",
            
            # Data URI
            f"data:text/html,<script>location='http://{self.test_domain}'</script>",
            
            # Mixed case bypass
            f"hTTp://{self.test_domain}",
            f"HTTPS://{self.test_domain}",
            
            # Backslash tricks
            f"http:{self.test_domain}",
            f"http:/{self.test_domain}",
            f"http:\\\\{self.test_domain}",
        ]
        
        # Parameters commonly used for redirects
        self.redirect_params = [
            'url', 'redirect', 'redir', 'return', 'returnurl', 'return_url',
            'returnto', 'return_to', 'goto', 'go', 'next', 'target', 'dest',
            'destination', 'continue', 'redirect_uri', 'redirect_url',
            'out', 'view', 'ref', 'link', 'back', 'backurl', 'callback',
            'forward', 'jump', 'to', 'u', 'page', 'site', 'path'
        ]
    
    def is_redirect_to_external(
        self,
        response,
        target_domain: str,
        original_domain: str
    ) -> tuple:
        """
        Check if a response redirects to an external domain.
        
        Args:
            response: HTTP response object
            target_domain: The domain we're trying to redirect to
            original_domain: The original target's domain
            
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        # Check for redirect status codes
        if response.is_redirect or response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            
            # Check if Location header points to external domain
            if target_domain in location:
                return True, f"Redirect to: {location}"
        
        # Check for JavaScript redirects in response body
        if response.status_code == 200:
            js_redirect_patterns = [
                rf'window\.location\s*=\s*["\'][^"\']*{re.escape(target_domain)}',
                rf'document\.location\s*=\s*["\'][^"\']*{re.escape(target_domain)}',
                rf'location\.href\s*=\s*["\'][^"\']*{re.escape(target_domain)}',
                rf'location\.replace\s*\(["\'][^"\']*{re.escape(target_domain)}',
            ]
            
            for pattern in js_redirect_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True, f"JavaScript redirect to {target_domain}"
        
        # Check response history for redirects
        for hist_response in response.history:
            location = hist_response.headers.get('Location', '')
            if target_domain in location:
                return True, f"Redirect chain to: {location}"
        
        # Check final URL
        if response.url and target_domain in response.url:
            return True, f"Final URL: {response.url}"
        
        return False, None
    
    def test_open_redirect(
        self,
        url: str,
        param: str,
        original_domain: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test a parameter for open redirect.
        
        Args:
            url: Target URL
            param: Parameter to test
            original_domain: Original domain of the target
            method: HTTP method
            form_data: Base form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        for payload in self.payloads:
            try:
                if method == 'GET':
                    test_url = inject_payload_in_url(url, param, payload)
                    # Don't follow redirects so we can inspect them
                    response = self.make_request(
                        test_url,
                        method='GET',
                        allow_redirects=False
                    )
                else:
                    test_data = form_data.copy() if form_data else {}
                    test_data[param] = payload
                    response = self.make_request(
                        url,
                        method='POST',
                        data=test_data,
                        allow_redirects=False
                    )
                
                if response is None:
                    continue
                
                is_vulnerable, evidence = self.is_redirect_to_external(
                    response,
                    self.test_domain,
                    original_domain
                )
                
                if is_vulnerable:
                    self.add_vulnerability(
                        vuln_type="Open Redirect",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="Medium",
                        description=(
                            "The application allows redirects to external domains "
                            "based on user input. Attackers can use this to create "
                            "legitimate-looking URLs that redirect to malicious sites."
                        ),
                        recommendation=(
                            "Avoid using user input for redirects. If necessary, "
                            "use a whitelist of allowed redirect destinations. "
                            "Validate that redirect URLs belong to trusted domains. "
                            "Consider using indirect references (IDs) instead of URLs."
                        )
                    )
                    vulns.append(self.vulnerabilities[-1])
                    break
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error testing redirect on {url}: {e}")
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for open redirect vulnerabilities.
        
        Args:
            urls: List of URLs to scan
            forms: List of forms to test
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        self.logger.info(f"  Testing {len(urls)} URLs for Open Redirect...")
        
        # Test URL parameters
        for url in urls:
            parsed = urlparse(url)
            original_domain = parsed.netloc
            params = extract_params(url)
            
            for param in params:
                param_lower = param.lower()
                
                # Prioritize parameters that look like redirect params
                is_redirect_param = param_lower in self.redirect_params
                
                self.logger.debug(f"  Testing parameter: {param}")
                self.test_open_redirect(url, param, original_domain, method='GET')
        
        # Test form parameters
        if forms:
            self.logger.info(f"  Testing {len(forms)} forms for Open Redirect...")
            
            for form in forms:
                url = form['action']
                parsed = urlparse(url)
                original_domain = parsed.netloc
                method = form['method']
                
                base_data = {}
                for input_field in form['inputs']:
                    if input_field['name']:
                        base_data[input_field['name']] = input_field.get('value', 'test')
                
                for input_field in form['inputs']:
                    param = input_field['name']
                    if not param:
                        continue
                    
                    if input_field.get('type') in ['submit', 'button', 'image', 'reset']:
                        continue
                    
                    # Focus on hidden fields and redirect-like names
                    if (input_field.get('type') == 'hidden' or 
                        param.lower() in self.redirect_params):
                        self.test_open_redirect(
                            url, param, original_domain,
                            method=method, form_data=base_data
                        )
        
        return self.vulnerabilities
