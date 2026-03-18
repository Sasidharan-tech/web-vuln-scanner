"""
Command Injection Scanner Module

Detects OS command injection vulnerabilities by:
1. Injecting command execution payloads
2. Looking for evidence of command execution in responses
3. Using time-based detection for blind injection

Command injection allows attackers to:
- Execute arbitrary system commands
- Access sensitive files
- Pivot to internal systems
- Establish reverse shells
- Completely compromise the server
"""

import re
import time
from typing import Dict, List, Any

from scanner.base import BaseScanner
from utils.http_helper import (
    inject_payload_in_url,
    inject_payload_in_form,
    extract_params
)


class CommandInjectionScanner(BaseScanner):
    """
    Scanner for detecting OS Command Injection vulnerabilities.
    
    This scanner tests for command injection by injecting various
    command execution payloads and analyzing responses for signs
    of successful execution.
    """
    
    @property
    def name(self) -> str:
        return "Command Injection Scanner"
    
    @property
    def severity(self) -> str:
        return "Critical"
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        super().__init__(timeout=timeout, delay=delay)
        
        # Command injection payloads
        # These attempt to execute commands that produce recognizable output
        self.payloads = [
            # Basic command chaining (Unix)
            "; id",
            "| id",
            "|| id",
            "&& id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            
            # Basic command chaining (Windows)
            "& whoami",
            "| whoami",
            "|| whoami",
            "&& whoami",
            
            # Command with output markers
            "; echo CMDTEST123",
            "| echo CMDTEST123",
            "& echo CMDTEST123",
            "$(echo CMDTEST123)",
            "`echo CMDTEST123`",
            
            # Windows echo
            "& echo CMDTEST123",
            "| echo CMDTEST123",
            
            # Breaking out of quotes
            "'; id; '",
            "\"; id; \"",
            "'; echo CMDTEST123; '",
            "' | id | '",
            
            # Newline injection
            "%0a id",
            "%0d%0a id",
            "\n id",
            "\r\n id",
            
            # Cat /etc/passwd (Unix)
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            
            # Type file (Windows)
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
        
        # Time-based payloads for blind detection
        self.time_payloads = [
            ("; sleep 5", 5),
            ("| sleep 5", 5),
            ("& sleep 5", 5),
            ("$(sleep 5)", 5),
            ("`sleep 5`", 5),
            ("& ping -n 5 127.0.0.1", 5),  # Windows
            ("| ping -c 5 127.0.0.1", 5),  # Unix
        ]
        
        # Evidence patterns that indicate successful command execution
        self.evidence_patterns = [
            # Unix id command output
            r"uid=\d+\([^)]+\)\s+gid=\d+",
            
            # Unix whoami/user info
            r"(?:root|www-data|apache|nginx|nobody|daemon):",
            
            # /etc/passwd file content
            r"root:x?:\d+:\d+:",
            r"/bin/(?:ba)?sh",
            
            # Windows user info
            r"(?:SYSTEM|Administrator|NT AUTHORITY)",
            r"\\Users\\[a-zA-Z0-9]+",
            
            # Windows hosts file
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
            
            # Our test marker
            r"CMDTEST123",
            
            # Directory listing artifacts
            r"(?:total\s+\d+|drwx|Directory of)",
        ]
        
        self.compiled_evidence = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.evidence_patterns
        ]
    
    def check_command_execution(self, response_text: str) -> tuple:
        """
        Check response for evidence of command execution.
        
        Args:
            response_text: HTTP response body
            
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        for pattern in self.compiled_evidence:
            match = pattern.search(response_text)
            if match:
                return True, match.group()[:100]
        return False, None
    
    def test_command_injection(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test a parameter for command injection.
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            form_data: Base form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # First, get baseline response for comparison
        if method == 'GET':
            baseline = self.make_request(url, method='GET')
        else:
            baseline = self.make_request(url, method='POST', data=form_data)
        
        baseline_text = baseline.text if baseline else ""
        
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
                
                # Check for command execution evidence
                is_vulnerable, evidence = self.check_command_execution(response.text)
                
                # Also check if evidence wasn't in baseline
                if is_vulnerable:
                    baseline_match, _ = self.check_command_execution(baseline_text)
                    if not baseline_match:
                        self.add_vulnerability(
                            vuln_type="OS Command Injection",
                            url=url,
                            param=param,
                            payload=payload,
                            evidence=evidence,
                            severity="Critical",
                            description=(
                                "The application is vulnerable to OS command injection. "
                                "User input is being passed to a system shell without proper "
                                "sanitization, allowing execution of arbitrary commands."
                            ),
                            recommendation=(
                                "Never pass user input directly to system commands. "
                                "Use parameterized library functions instead of shell commands. "
                                "If shell commands are necessary, use strict allowlisting "
                                "for acceptable input values."
                            )
                        )
                        vulns.append(self.vulnerabilities[-1])
                        break
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error testing cmd injection on {url}: {e}")
        
        return vulns
    
    def test_time_based(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test for blind command injection using time delays.
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method
            form_data: Base form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # Get baseline timing
        baseline_times = []
        for _ in range(2):
            if method == 'GET':
                _, elapsed = self.make_request_timed(url, method='GET')
            else:
                _, elapsed = self.make_request_timed(url, method='POST', data=form_data)
            if elapsed:
                baseline_times.append(elapsed)
            time.sleep(0.5)
        
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 2
        
        for payload, expected_delay in self.time_payloads:
            try:
                if method == 'GET':
                    test_url = inject_payload_in_url(url, param, payload)
                    response, elapsed = self.make_request_timed(test_url, method='GET')
                else:
                    test_data = form_data.copy() if form_data else {}
                    test_data[param] = payload
                    response, elapsed = self.make_request_timed(
                        url, method='POST', data=test_data
                    )
                
                if response is None:
                    continue
                
                # Check for significant delay
                delay_threshold = avg_baseline + (expected_delay * 0.7)
                
                if elapsed >= delay_threshold:
                    self.add_vulnerability(
                        vuln_type="OS Command Injection (Blind/Time-based)",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (baseline: {avg_baseline:.2f}s)",
                        severity="Critical",
                        description=(
                            "The application appears vulnerable to blind command injection. "
                            "A time delay command was successfully executed on the server."
                        ),
                        recommendation=(
                            "Avoid passing user input to shell commands. Use language-native "
                            "functions instead of shell execution. Implement strict input "
                            "validation and allowlisting."
                        )
                    )
                    vulns.append(self.vulnerabilities[-1])
                    break
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error in time-based cmd test: {e}")
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for command injection vulnerabilities.
        
        Args:
            urls: List of URLs to scan
            forms: List of forms to test
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        self.logger.info(f"  Testing {len(urls)} URLs for Command Injection...")
        
        # Test URL parameters
        for url in urls:
            params = extract_params(url)
            
            for param in params:
                self.logger.debug(f"  Testing parameter: {param}")
                self.test_command_injection(url, param, method='GET')
                self.test_time_based(url, param, method='GET')
        
        # Test form parameters
        if forms:
            self.logger.info(f"  Testing {len(forms)} forms for Command Injection...")
            
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
                    
                    self.test_command_injection(url, param, method=method, form_data=base_data)
                    self.test_time_based(url, param, method=method, form_data=base_data)
        
        return self.vulnerabilities
