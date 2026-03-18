"""
Database module for the Web Vulnerability Scanner.
Handles session persistence using SQLite.
"""

from .session import ScanSession

__all__ = ["ScanSession"]
