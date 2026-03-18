"""
Scanner module for the Web Vulnerability Scanner.
Contains all vulnerability detection modules.
"""

from .base import BaseScanner
from .sql_injection import SQLInjectionScanner
from .xss import XSSScanner
from .command_injection import CommandInjectionScanner
from .file_inclusion import FileInclusionScanner
from .open_redirect import OpenRedirectScanner
from .headers import HeadersScanner
from .cookies import CookieScanner

__all__ = [
    "BaseScanner",
    "SQLInjectionScanner",
    "XSSScanner",
    "CommandInjectionScanner",
    "FileInclusionScanner",
    "OpenRedirectScanner",
    "HeadersScanner",
    "CookieScanner",
]
