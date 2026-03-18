"""
Cookie Security Scanner Module

Checks for insecure cookie configurations that can lead
to session hijacking and other attacks.

Insecure cookies can lead to:
- Session hijacking via XSS (missing HttpOnly)
- Session theft via MITM (missing Secure flag)
- CSRF attacks (missing SameSite)
- Session fixation attacks
"""

from typing import Dict, List, Any
from http.cookies import SimpleCookie

from scanner.base import BaseScanner


class CookieScanner(BaseScanner):
    """
    Scanner for checking cookie security flags.
    
    This scanner analyzes Set-Cookie headers for missing
    security attributes.
    """
    
    @property
    def name(self) -> str:
        return "Cookie Security Scanner"
    
    @property
    def severity(self) -> str:
        return "Medium"
    
    def __init__(self, timeout: int = 10):
        super().__init__(timeout=timeout, delay=0)
        
        # Sensitive cookie name patterns (case-insensitive)
        self.sensitive_patterns = [
            'session', 'sess', 'auth', 'token', 'jwt', 'user',
            'login', 'credential', 'id', 'key', 'api', 'access',
            'refresh', 'remember', 'phpsessid', 'jsessionid',
            'asp.net_sessionid', 'aspsessionid', 'cfid', 'cftoken'
        ]
    
    def is_sensitive_cookie(self, name: str) -> bool:
        """
        Check if a cookie name suggests it's security-sensitive.
        
        Args:
            name: Cookie name
            
        Returns:
            True if cookie appears to be sensitive
        """
        name_lower = name.lower()
        return any(pattern in name_lower for pattern in self.sensitive_patterns)
    
    def parse_set_cookie(self, header_value: str) -> Dict[str, Any]:
        """
        Parse a Set-Cookie header value.
        
        Args:
            header_value: The Set-Cookie header value
            
        Returns:
            Dictionary with cookie details
        """
        parts = header_value.split(';')
        
        if not parts:
            return {}
        
        # First part is name=value
        main_part = parts[0].strip()
        if '=' not in main_part:
            return {}
        
        name, value = main_part.split('=', 1)
        
        cookie_info = {
            'name': name.strip(),
            'value': value.strip(),
            'secure': False,
            'httponly': False,
            'samesite': None,
            'path': '/',
            'domain': None,
            'expires': None,
            'max_age': None
        }
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip().lower()
            
            if part == 'secure':
                cookie_info['secure'] = True
            elif part == 'httponly':
                cookie_info['httponly'] = True
            elif part.startswith('samesite='):
                cookie_info['samesite'] = part.split('=', 1)[1].strip()
            elif part.startswith('path='):
                cookie_info['path'] = part.split('=', 1)[1].strip()
            elif part.startswith('domain='):
                cookie_info['domain'] = part.split('=', 1)[1].strip()
            elif part.startswith('expires='):
                cookie_info['expires'] = part.split('=', 1)[1].strip()
            elif part.startswith('max-age='):
                try:
                    cookie_info['max_age'] = int(part.split('=', 1)[1].strip())
                except ValueError:
                    pass
        
        return cookie_info
    
    def check_cookie_security(
        self,
        url: str,
        cookie_info: Dict[str, Any],
        is_https: bool
    ) -> List[Dict]:
        """
        Check a cookie for security issues.
        
        Args:
            url: The URL where cookie was set
            cookie_info: Parsed cookie information
            is_https: Whether the URL uses HTTPS
            
        Returns:
            List of vulnerability dictionaries
        """
        vulns = []
        cookie_name = cookie_info['name']
        is_sensitive = self.is_sensitive_cookie(cookie_name)
        
        # Determine severity based on cookie sensitivity
        base_severity = "Medium" if is_sensitive else "Low"
        
        # Check for missing Secure flag on HTTPS
        if is_https and not cookie_info['secure']:
            vuln = {
                'type': "Missing Secure Flag on Cookie",
                'url': url,
                'parameter': cookie_name,
                'payload': 'N/A',
                'evidence': f"Cookie '{cookie_name}' missing Secure flag",
                'severity': "High" if is_sensitive else "Medium",
                'description': (
                    f"The cookie '{cookie_name}' is set without the Secure flag. "
                    "This allows the cookie to be transmitted over unencrypted HTTP, "
                    "making it vulnerable to interception via man-in-the-middle attacks."
                ),
                'recommendation': (
                    "Add the Secure flag to all cookies that contain sensitive data. "
                    "Example: Set-Cookie: name=value; Secure"
                ),
                'scanner': self.name
            }
            self.vulnerabilities.append(vuln)
            vulns.append(vuln)
        
        # Check for missing HttpOnly flag
        if not cookie_info['httponly']:
            vuln = {
                'type': "Missing HttpOnly Flag on Cookie",
                'url': url,
                'parameter': cookie_name,
                'payload': 'N/A',
                'evidence': f"Cookie '{cookie_name}' missing HttpOnly flag",
                'severity': "High" if is_sensitive else "Low",
                'description': (
                    f"The cookie '{cookie_name}' is set without the HttpOnly flag. "
                    "This allows JavaScript to access the cookie, making it "
                    "vulnerable to theft via XSS attacks."
                ),
                'recommendation': (
                    "Add the HttpOnly flag to all cookies that don't need "
                    "JavaScript access. Example: Set-Cookie: name=value; HttpOnly"
                ),
                'scanner': self.name
            }
            self.vulnerabilities.append(vuln)
            vulns.append(vuln)
        
        # Check for missing or weak SameSite attribute
        samesite = cookie_info['samesite']
        if samesite is None or samesite == 'none':
            severity = "Medium" if is_sensitive else "Low"
            if samesite == 'none' and not cookie_info['secure']:
                # SameSite=None without Secure is particularly bad
                severity = "High" if is_sensitive else "Medium"
            
            vuln = {
                'type': "Missing or Weak SameSite Attribute",
                'url': url,
                'parameter': cookie_name,
                'payload': 'N/A',
                'evidence': (
                    f"Cookie '{cookie_name}' has SameSite={samesite or 'not set'}"
                ),
                'severity': severity,
                'description': (
                    f"The cookie '{cookie_name}' has {'SameSite=None' if samesite == 'none' else 'no SameSite attribute'}. "
                    "This can make the application vulnerable to CSRF attacks as the "
                    "cookie will be sent with cross-site requests."
                ),
                'recommendation': (
                    "Set SameSite=Strict or SameSite=Lax for cookies. "
                    "Use SameSite=None only if cross-site access is required, "
                    "and always combine with the Secure flag. "
                    "Example: Set-Cookie: name=value; SameSite=Lax"
                ),
                'scanner': self.name
            }
            self.vulnerabilities.append(vuln)
            vulns.append(vuln)
        
        return vulns
    
    def scan(self, urls: List[str], forms: List[Dict] = None) -> List[Dict]:
        """
        Scan for cookie security issues.
        
        Args:
            urls: List of URLs to scan
            forms: Not used for this scanner
            
        Returns:
            List of discovered vulnerabilities
        """
        self.vulnerabilities = []
        
        # Track cookies we've already checked
        checked_cookies = set()
        
        self.logger.info(f"  Checking cookie security...")
        
        # Check unique base URLs
        checked_urls = set()
        
        for url in urls:
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
                
                # Get all Set-Cookie headers
                set_cookies = response.headers.get_all('Set-Cookie') if hasattr(
                    response.headers, 'get_all'
                ) else []
                
                # Fallback for requests library
                if not set_cookies:
                    set_cookie = response.headers.get('Set-Cookie', '')
                    if set_cookie:
                        set_cookies = [set_cookie]
                    
                    # Also check response.cookies
                    for cookie in response.cookies:
                        cookie_id = f"{cookie.name}:{cookie.domain}"
                        if cookie_id not in checked_cookies:
                            checked_cookies.add(cookie_id)
                            
                            cookie_info = {
                                'name': cookie.name,
                                'value': cookie.value,
                                'secure': cookie.secure,
                                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                                'samesite': getattr(cookie, '_rest', {}).get('SameSite'),
                            }
                            
                            self.check_cookie_security(url, cookie_info, is_https)
                
                # Parse Set-Cookie headers
                for set_cookie in set_cookies:
                    cookie_info = self.parse_set_cookie(set_cookie)
                    if cookie_info:
                        cookie_id = f"{cookie_info['name']}:{cookie_info.get('domain', '')}"
                        if cookie_id not in checked_cookies:
                            checked_cookies.add(cookie_id)
                            self.check_cookie_security(url, cookie_info, is_https)
                
            except Exception as e:
                self.logger.debug(f"Error checking cookies for {url}: {e}")
        
        if self.vulnerabilities:
            self.logger.info(
                f"  Found {len(self.vulnerabilities)} cookie security issues"
            )
        
        return self.vulnerabilities
