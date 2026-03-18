"""
Base Scanner Module

Provides the abstract base class for all vulnerability scanners.
Each scanner module should inherit from this class.
"""

import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

import requests

from utils.logger import get_logger
from utils.http_helper import make_request, make_request_with_timing


class BaseScanner(ABC):
    """
    Abstract base class for vulnerability scanners.
    
    All scanner modules should inherit from this class and implement
    the scan() method. This provides common functionality like:
    - HTTP request handling
    - Payload loading
    - Result formatting
    - Logging
    
    Attributes:
        timeout (int): Request timeout in seconds
        delay (float): Delay between requests
        logger: Logger instance
        vulnerabilities: List of found vulnerabilities
    """
    
    def __init__(
        self,
        timeout: int = 10,
        delay: float = 0.5,
        user_agent: str = "WebVulnScanner/1.0"
    ):
        """
        Initialize the base scanner.
        
        Args:
            timeout: Request timeout in seconds
            delay: Delay between requests in seconds
            user_agent: User-Agent string for requests
        """
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.logger = get_logger()
        self.vulnerabilities: List[Dict[str, Any]] = []
        
        # Setup session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.verify = False  # Disable SSL verification for testing
    
    @abstractmethod
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Perform vulnerability scanning.
        
        This method must be implemented by each scanner module.
        
        Args:
            urls: List of URLs to scan
            forms: List of forms to test (optional)
            
        Returns:
            List of vulnerability dictionaries
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass
    
    @property
    @abstractmethod
    def severity(self) -> str:
        """Return the default severity level for this vulnerability type."""
        pass
    
    def load_payloads(self, payload_file: str) -> List[str]:
        """
        Load payloads from a file.
        
        Args:
            payload_file: Path to the payload file
            
        Returns:
            List of payload strings
        """
        payloads = []
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            self.logger.warning(f"Payload file not found: {payload_file}")
        except Exception as e:
            self.logger.error(f"Error loading payloads: {e}")
        
        return payloads
    
    def make_request(
        self,
        url: str,
        method: str = 'GET',
        params: Dict = None,
        data: Dict = None,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request through the scanner's session.
        
        Args:
            url: Target URL
            method: HTTP method
            params: URL parameters
            data: POST data
            **kwargs: Additional request options
            
        Returns:
            Response object or None
        """
        return make_request(
            url=url,
            method=method,
            params=params,
            data=data,
            timeout=self.timeout,
            **kwargs
        )
    
    def make_request_timed(
        self,
        url: str,
        method: str = 'GET',
        params: Dict = None,
        data: Dict = None,
        **kwargs
    ) -> tuple:
        """
        Make an HTTP request and measure response time.
        
        Args:
            url: Target URL
            method: HTTP method
            params: URL parameters
            data: POST data
            **kwargs: Additional request options
            
        Returns:
            Tuple of (Response object, elapsed time in seconds)
        """
        return make_request_with_timing(
            url=url,
            method=method,
            params=params,
            data=data,
            timeout=max(self.timeout, 30),  # Use longer timeout for timing attacks
            **kwargs
        )
    
    def add_vulnerability(
        self,
        vuln_type: str,
        url: str,
        param: str,
        payload: str,
        evidence: str = "",
        severity: str = None,
        description: str = "",
        recommendation: str = ""
    ):
        """
        Record a discovered vulnerability.
        
        Args:
            vuln_type: Type of vulnerability
            url: Affected URL
            param: Vulnerable parameter
            payload: Payload that triggered the vulnerability
            evidence: Evidence of the vulnerability
            severity: Severity level (defaults to scanner's default)
            description: Detailed description
            recommendation: Remediation recommendation
        """
        vuln = {
            'type': vuln_type,
            'url': url,
            'parameter': param,
            'payload': payload,
            'evidence': evidence[:500] if evidence else "",  # Truncate long evidence
            'severity': severity or self.severity,
            'description': description,
            'recommendation': recommendation,
            'scanner': self.name
        }
        
        self.vulnerabilities.append(vuln)
        
        # Log the finding
        self.logger.warning(
            f"  [!] {vuln_type} - {url} (param: {param})"
        )
    
    def throttle(self):
        """
        Apply delay between requests to avoid overwhelming the target.
        """
        if self.delay > 0:
            time.sleep(self.delay)
