"""
Cross-Site Scripting (XSS) Scanner Module

Detects reflected XSS vulnerabilities by:
1. Injecting payloads that would execute JavaScript
2. Checking if the payload is reflected in the response
3. Analyzing if the reflection is in a dangerous context

XSS allows attackers to:
- Steal session cookies and credentials
- Perform actions on behalf of users
- Redirect users to malicious sites
- Deface web pages
- Spread malware
"""

import re
import html
from typing import Dict, List, Any
from urllib.parse import urlparse, quote, unquote

from scanner.base import BaseScanner
from utils.http_helper import (
    inject_payload_in_url,
    inject_payload_in_form,
    extract_params,
    check_reflection
)


class XSSScanner(BaseScanner):
    """
    Scanner for detecting Cross-Site Scripting (XSS) vulnerabilities.
    
    This scanner tests for reflected XSS by injecting JavaScript
    payloads and checking if they appear in the response without
    proper encoding.
    """
    
    @property
    def name(self) -> str:
        return "XSS Scanner"
    
    @property
    def severity(self) -> str:
        return "High"
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        super().__init__(timeout=timeout, delay=delay)
        
        # XSS payloads for testing
        # Using various encoding and context-breaking techniques
        self.payloads = [
            # Basic script injection
            '<script>alert("XSS")</script>',
            '<script>alert(1)</script>',
            '<ScRiPt>alert("XSS")</ScRiPt>',
            
            # Event handlers
            '<img src=x onerror=alert("XSS")>',
            '<img src=x onerror="alert(\'XSS\')">',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>',
            '<video><source onerror=alert("XSS")>',
            '<audio src=x onerror=alert("XSS")>',
            
            # Breaking out of attributes
            '"><script>alert("XSS")</script>',
            "'>alert('XSS')<'",
            '" onmouseover="alert(\'XSS\')"',
            "' onmouseover='alert(1)'",
            '" onfocus="alert(1)" autofocus="',
            
            # Breaking out of tags
            '</title><script>alert("XSS")</script>',
            '</textarea><script>alert("XSS")</script>',
            '</style><script>alert("XSS")</script>',
            
            # JavaScript protocol
            'javascript:alert("XSS")',
            'javascript:alert(1)//',
            
            # Data URI
            'data:text/html,<script>alert("XSS")</script>',
            
            # HTML entities bypass
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',
            
            # Null byte injection
            '<script>alert("XSS")</script>\x00',
            
            # Simple reflection test marker
            'XSSTEST123',
            '<XSSTEST123>',
        ]
        
        # Patterns that indicate dangerous reflection contexts
        self.dangerous_patterns = [
            # Script tags
            r'<script[^>]*>[^<]*XSSTEST',
            r'<script[^>]*>.*?alert\s*\(',
            
            # Event handlers
            r'on\w+\s*=\s*["\'][^"\']*XSSTEST',
            r'on\w+\s*=\s*["\'][^"\']*alert\s*\(',
            
            # Unescaped in attributes
            r'<[^>]+\s+\w+\s*=\s*["\'][^"\']*<script',
            
            # JavaScript context
            r'javascript:[^"\']*XSSTEST',
            r'javascript:[^"\']*alert\s*\(',
            
            # SVG/IMG/etc with handlers
            r'<(?:img|svg|body|iframe)[^>]*on\w+\s*=',
        ]
        
        self.compiled_dangerous = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.dangerous_patterns
        ]
    
    def check_xss_reflection(
        self,
        response_text: str,
        payload: str
    ) -> tuple:
        """
        Check if an XSS payload is dangerously reflected.
        
        Args:
            response_text: HTTP response body
            payload: The injected payload
            
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        # Check for exact reflection (no encoding)
        if payload in response_text:
            # Check if it's in a dangerous context
            for pattern in self.compiled_dangerous:
                if pattern.search(response_text):
                    return True, f"Payload reflected unescaped: {payload[:50]}"
            
            # Check for script tags specifically
            if '<script' in payload.lower() and payload in response_text:
                return True, f"Script tag reflected: {payload[:50]}"
            
            # Check for event handlers
            if re.search(r'on\w+=', payload, re.IGNORECASE) and payload in response_text:
                return True, f"Event handler reflected: {payload[:50]}"
        
        # Check for partial reflection that's still dangerous
        # Extract the key part of the payload
        key_patterns = [
            r'alert\s*\(["\']?XSS["\']?\)',
            r'alert\s*\(\s*1\s*\)',
            r'<script>',
            r'onerror\s*=',
            r'onload\s*=',
            r'onmouseover\s*=',
        ]
        
        for pattern in key_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, f"Dangerous pattern in response: {pattern}"
        
        return False, None
    
    def test_xss(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test a parameter for XSS vulnerabilities.
        
        Args:
            url: Target URL
            param: Parameter to test
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
                    response = self.make_request(test_url, method='GET')
                else:
                    test_data = form_data.copy() if form_data else {}
                    test_data[param] = payload
                    response = self.make_request(url, method='POST', data=test_data)
                
                if response is None:
                    continue
                
                # Check for XSS reflection
                is_vulnerable, evidence = self.check_xss_reflection(
                    response.text,
                    payload
                )
                
                if is_vulnerable:
                    self.add_vulnerability(
                        vuln_type="Cross-Site Scripting (Reflected XSS)",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="High",
                        description=(
                            "The application reflects user input in the response without "
                            "proper HTML encoding. This allows attackers to inject malicious "
                            "JavaScript that will execute in the victim's browser."
                        ),
                        recommendation=(
                            "Encode all user input before reflecting it in HTML. Use "
                            "context-aware encoding (HTML entity encoding for HTML context, "
                            "JavaScript encoding for JS context). Implement Content Security "
                            "Policy (CSP) headers as a defense-in-depth measure."
                        )
                    )
                    vulns.append(self.vulnerabilities[-1])
                    break  # Found vulnerability, move to next parameter
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error testing XSS on {url}: {e}")
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for XSS vulnerabilities.
        
        Args:
            urls: List of URLs to scan
            forms: List of forms to test
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        self.logger.info(f"  Testing {len(urls)} URLs for XSS...")
        
        # Test URL parameters
        for url in urls:
            params = extract_params(url)
            
            for param in params:
                self.logger.debug(f"  Testing parameter: {param}")
                self.test_xss(url, param, method='GET')
        
        # Test form parameters
        if forms:
            self.logger.info(f"  Testing {len(forms)} forms for XSS...")
            
            for form in forms:
                url = form['action']
                method = form['method']
                
                # Build base form data
                base_data = {}
                for input_field in form['inputs']:
                    if input_field['name']:
                        base_data[input_field['name']] = input_field.get('value', 'test')
                
                # Test each input field
                for input_field in form['inputs']:
                    param = input_field['name']
                    if not param:
                        continue
                    
                    # Skip certain input types
                    if input_field.get('type') in ['submit', 'button', 'image', 'reset']:
                        continue
                    
                    self.test_xss(url, param, method=method, form_data=base_data)
        
        return self.vulnerabilities
