"""
Logger Module

Provides centralized logging functionality for the scanner.
Supports different verbosity levels and colored output.
"""

import logging
import sys
from typing import Optional

# Try to import colorama for colored output on Windows
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORS = True
except ImportError:
    HAS_COLORS = False


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds colors to log messages based on level.
    """
    
    COLORS = {
        'DEBUG': Fore.CYAN if HAS_COLORS else '',
        'INFO': Fore.GREEN if HAS_COLORS else '',
        'WARNING': Fore.YELLOW if HAS_COLORS else '',
        'ERROR': Fore.RED if HAS_COLORS else '',
        'CRITICAL': Fore.RED + Style.BRIGHT if HAS_COLORS else '',
    }
    
    RESET = Style.RESET_ALL if HAS_COLORS else ''
    
    def format(self, record):
        # Get color for this level
        color = self.COLORS.get(record.levelname, '')
        
        # Format the message
        message = super().format(record)
        
        # Add color if available
        if color:
            return f"{color}{message}{self.RESET}"
        return message


class VulnerabilityFormatter(logging.Formatter):
    """
    Special formatter for vulnerability findings.
    Uses different colors for severity levels.
    """
    
    SEVERITY_COLORS = {
        'Critical': Fore.RED + Style.BRIGHT if HAS_COLORS else '[CRITICAL]',
        'High': Fore.RED if HAS_COLORS else '[HIGH]',
        'Medium': Fore.YELLOW if HAS_COLORS else '[MEDIUM]',
        'Low': Fore.CYAN if HAS_COLORS else '[LOW]',
        'Info': Fore.BLUE if HAS_COLORS else '[INFO]',
    }


# Global logger instance
_logger: Optional[logging.Logger] = None


def setup_logger(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """
    Setup and configure the global logger.
    
    Args:
        verbose: Enable debug-level logging
        quiet: Suppress non-essential output
        
    Returns:
        Configured logger instance
    """
    global _logger
    
    # Create logger
    _logger = logging.getLogger('WebVulnScanner')
    _logger.handlers.clear()  # Clear any existing handlers
    
    # Set level based on verbosity
    if quiet:
        _logger.setLevel(logging.WARNING)
    elif verbose:
        _logger.setLevel(logging.DEBUG)
    else:
        _logger.setLevel(logging.INFO)
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    
    # Create formatter
    if verbose:
        formatter = ColoredFormatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
    else:
        formatter = ColoredFormatter('%(message)s')
    
    handler.setFormatter(formatter)
    _logger.addHandler(handler)
    
    return _logger


def get_logger() -> logging.Logger:
    """
    Get the global logger instance.
    
    Returns:
        Logger instance (creates default if not initialized)
    """
    global _logger
    
    if _logger is None:
        _logger = setup_logger()
    
    return _logger


def log_vulnerability(
    vuln_type: str,
    url: str,
    param: str,
    severity: str,
    payload: str = None
):
    """
    Log a discovered vulnerability with appropriate formatting.
    
    Args:
        vuln_type: Type of vulnerability (e.g., "SQL Injection")
        url: Affected URL
        param: Vulnerable parameter
        severity: Severity level (Critical, High, Medium, Low, Info)
        payload: Payload that triggered the vulnerability
    """
    logger = get_logger()
    
    if HAS_COLORS:
        severity_colors = {
            'Critical': Fore.RED + Style.BRIGHT,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.CYAN,
            'Info': Fore.BLUE,
        }
        color = severity_colors.get(severity, '')
        reset = Style.RESET_ALL
        
        logger.warning(
            f"{color}[{severity.upper()}]{reset} {vuln_type} found!"
        )
    else:
        logger.warning(f"[{severity.upper()}] {vuln_type} found!")
    
    logger.warning(f"  URL: {url}")
    logger.warning(f"  Parameter: {param}")
    if payload:
        logger.warning(f"  Payload: {payload}")
