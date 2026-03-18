"""
HTTP Helper Module

Provides utility functions for making HTTP requests
and handling responses during vulnerability scanning.
"""

import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, List, Optional, Any, Tuple

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from utils.logger import get_logger


# Default request headers
DEFAULT_HEADERS = {
    'User-Agent': 'WebVulnScanner/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
}


def make_request(
    url: str,
    method: str = 'GET',
    params: Dict = None,
    data: Dict = None,
    headers: Dict = None,
    cookies: Dict = None,
    timeout: int = 10,
    allow_redirects: bool = True,
    verify_ssl: bool = False
) -> Optional[requests.Response]:
    """
    Make an HTTP request with error handling.
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        params: URL query parameters
        data: POST data
        headers: Custom headers to include
        cookies: Cookies to send
        timeout: Request timeout in seconds
        allow_redirects: Whether to follow redirects
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Response object if successful, None if failed
    """
    logger = get_logger()
    
    # Merge headers with defaults
    request_headers = DEFAULT_HEADERS.copy()
    if headers:
        request_headers.update(headers)
    
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            headers=request_headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify_ssl
        )
        return response
        
    except Timeout:
        logger.debug(f"Request timeout: {url}")
    except ConnectionError:
        logger.debug(f"Connection error: {url}")
    except RequestException as e:
        logger.debug(f"Request error for {url}: {str(e)}")
    
    return None


def make_request_with_timing(
    url: str,
    method: str = 'GET',
    params: Dict = None,
    data: Dict = None,
    timeout: int = 30,
    **kwargs
) -> Tuple[Optional[requests.Response], float]:
    """
    Make an HTTP request and measure response time.
    
    Useful for time-based vulnerability detection.
    
    Args:
        url: Target URL
        method: HTTP method
        params: URL query parameters
        data: POST data
        timeout: Request timeout in seconds
        **kwargs: Additional arguments for make_request
        
    Returns:
        Tuple of (Response object, response time in seconds)
    """
    start_time = time.time()
    
    response = make_request(
        url=url,
        method=method,
        params=params,
        data=data,
        timeout=timeout,
        **kwargs
    )
    
    elapsed_time = time.time() - start_time
    
    return response, elapsed_time


def extract_params(url: str) -> Dict[str, str]:
    """
    Extract query parameters from a URL.
    
    Args:
        url: URL to parse
        
    Returns:
        Dictionary of parameter names to values
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Convert lists to single values
    return {k: v[0] if len(v) == 1 else v for k, v in params.items()}


def build_url_with_params(base_url: str, params: Dict[str, str]) -> str:
    """
    Build a URL with query parameters.
    
    Args:
        base_url: Base URL (without query string)
        params: Dictionary of parameters
        
    Returns:
        Complete URL with query string
    """
    parsed = urlparse(base_url)
    
    # Build new URL with params
    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        '',
        urlencode(params),
        ''
    ))
    
    return new_url


def inject_payload_in_url(url: str, param_name: str, payload: str) -> str:
    """
    Inject a payload into a specific URL parameter.
    
    Args:
        url: Original URL
        param_name: Name of parameter to inject into
        payload: Payload to inject
        
    Returns:
        URL with injected payload
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Inject payload
    params[param_name] = [payload]
    
    # Flatten params
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    
    # Rebuild URL
    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        '',
        urlencode(flat_params),
        ''
    ))
    
    return new_url


def inject_payload_in_form(
    form_inputs: List[Dict],
    target_param: str,
    payload: str
) -> Dict[str, str]:
    """
    Prepare form data with payload injected into a specific field.
    
    Args:
        form_inputs: List of form input dictionaries
        target_param: Name of parameter to inject into
        payload: Payload to inject
        
    Returns:
        Dictionary of form data ready to submit
    """
    form_data = {}
    
    for input_field in form_inputs:
        name = input_field.get('name', '')
        if not name:
            continue
        
        if name == target_param:
            form_data[name] = payload
        else:
            # Keep original value or use default
            form_data[name] = input_field.get('value', 'test')
    
    return form_data


def check_reflection(response_text: str, payload: str) -> bool:
    """
    Check if a payload is reflected in the response.
    
    Args:
        response_text: Response body text
        payload: Payload to look for
        
    Returns:
        True if payload is found in response
    """
    return payload in response_text


def get_base_url(url: str) -> str:
    """
    Get the base URL (without query string or fragment).
    
    Args:
        url: Full URL
        
    Returns:
        Base URL
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
