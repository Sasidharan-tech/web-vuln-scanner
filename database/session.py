"""
Session Management Module

Handles scan session persistence using SQLite for:
- Saving scan progress
- Resuming interrupted scans
- Storing discovered vulnerabilities

This allows users to stop a scan and continue later,
preserving all crawled URLs and partial results.
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Set, Any, Tuple, Optional
from datetime import datetime


class ScanSession:
    """
    Manages scan session persistence using SQLite.
    
    Sessions are stored in a local database file, allowing
    scans to be paused and resumed.
    
    Attributes:
        session_name (str): Unique identifier for this scan session
        db_path (Path): Path to the SQLite database file
    """
    
    def __init__(self, session_name: str, db_dir: str = "database"):
        """
        Initialize a scan session.
        
        Args:
            session_name: Unique name for this session
            db_dir: Directory to store database files
        """
        self.session_name = session_name
        
        # Ensure database directory exists
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        
        # Database file path
        self.db_path = self.db_dir / f"{session_name}.db"
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """
        Initialize the SQLite database with required tables.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Session metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_info (
                    id INTEGER PRIMARY KEY,
                    session_name TEXT NOT NULL,
                    target_url TEXT,
                    start_time TEXT,
                    last_update TEXT,
                    status TEXT DEFAULT 'in_progress'
                )
            """)
            
            # Crawled URLs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    crawled INTEGER DEFAULT 0,
                    depth INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Forms table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    page_url TEXT NOT NULL,
                    action TEXT NOT NULL,
                    method TEXT DEFAULT 'GET',
                    inputs TEXT,  -- JSON encoded
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    parameter TEXT,
                    payload TEXT,
                    evidence TEXT,
                    severity TEXT,
                    description TEXT,
                    recommendation TEXT,
                    scanner TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Scan progress table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_progress (
                    id INTEGER PRIMARY KEY,
                    urls_scanned TEXT,  -- JSON array
                    current_module TEXT,
                    modules_completed TEXT,  -- JSON array
                    last_update TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    def can_resume(self) -> bool:
        """
        Check if there's a previous session that can be resumed.
        
        Returns:
            True if resumable session exists
        """
        if not self.db_path.exists():
            return False
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM urls WHERE crawled = 1")
                count = cursor.fetchone()[0]
                return count > 0
        except Exception:
            return False
    
    def load_progress(self) -> Tuple[Set[str], Set[str], List[Dict]]:
        """
        Load previous scan progress.
        
        Returns:
            Tuple of (crawled_urls, scanned_urls, vulnerabilities)
        """
        crawled_urls = set()
        scanned_urls = set()
        vulnerabilities = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Load crawled URLs
                cursor.execute("SELECT url FROM urls WHERE crawled = 1")
                crawled_urls = {row[0] for row in cursor.fetchall()}
                
                # Load scanned URLs from progress
                cursor.execute("SELECT urls_scanned FROM scan_progress WHERE id = 1")
                row = cursor.fetchone()
                if row and row[0]:
                    scanned_urls = set(json.loads(row[0]))
                
                # Load vulnerabilities
                cursor.execute("""
                    SELECT vuln_type, url, parameter, payload, evidence,
                           severity, description, recommendation, scanner
                    FROM vulnerabilities
                """)
                
                for row in cursor.fetchall():
                    vulnerabilities.append({
                        'type': row[0],
                        'url': row[1],
                        'parameter': row[2],
                        'payload': row[3],
                        'evidence': row[4],
                        'severity': row[5],
                        'description': row[6],
                        'recommendation': row[7],
                        'scanner': row[8]
                    })
                    
        except Exception as e:
            print(f"Error loading session: {e}")
        
        return crawled_urls, scanned_urls, vulnerabilities
    
    def save_crawl_progress(self, urls: List[str], forms: List[Dict]):
        """
        Save crawl progress to the database.
        
        Args:
            urls: List of discovered URLs
            forms: List of discovered forms
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Save URLs
                for url in urls:
                    cursor.execute("""
                        INSERT OR REPLACE INTO urls (url, crawled)
                        VALUES (?, 1)
                    """, (url,))
                
                # Save forms
                for form in forms:
                    cursor.execute("""
                        INSERT INTO forms (page_url, action, method, inputs)
                        VALUES (?, ?, ?, ?)
                    """, (
                        form.get('page_url', ''),
                        form.get('action', ''),
                        form.get('method', 'GET'),
                        json.dumps(form.get('inputs', []))
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error saving crawl progress: {e}")
    
    def save_vulnerabilities(self, vulnerabilities: List[Dict]):
        """
        Save discovered vulnerabilities to the database.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for vuln in vulnerabilities:
                    cursor.execute("""
                        INSERT INTO vulnerabilities 
                        (vuln_type, url, parameter, payload, evidence,
                         severity, description, recommendation, scanner)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        vuln.get('type', ''),
                        vuln.get('url', ''),
                        vuln.get('parameter', ''),
                        vuln.get('payload', ''),
                        vuln.get('evidence', ''),
                        vuln.get('severity', ''),
                        vuln.get('description', ''),
                        vuln.get('recommendation', ''),
                        vuln.get('scanner', '')
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error saving vulnerabilities: {e}")
    
    def update_scan_progress(
        self,
        scanned_urls: Set[str],
        current_module: str = "",
        completed_modules: List[str] = None
    ):
        """
        Update scan progress in the database.
        
        Args:
            scanned_urls: Set of URLs that have been scanned
            current_module: Name of currently running module
            completed_modules: List of completed module names
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO scan_progress 
                    (id, urls_scanned, current_module, modules_completed, last_update)
                    VALUES (1, ?, ?, ?, ?)
                """, (
                    json.dumps(list(scanned_urls)),
                    current_module,
                    json.dumps(completed_modules or []),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error updating scan progress: {e}")
    
    def get_session_info(self) -> Optional[Dict]:
        """
        Get session metadata.
        
        Returns:
            Dictionary with session info or None
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get URL counts
                cursor.execute("SELECT COUNT(*) FROM urls")
                url_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM forms")
                form_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
                vuln_count = cursor.fetchone()[0]
                
                return {
                    'session_name': self.session_name,
                    'urls_found': url_count,
                    'forms_found': form_count,
                    'vulnerabilities_found': vuln_count
                }
                
        except Exception as e:
            print(f"Error getting session info: {e}")
            return None
    
    def clear(self):
        """
        Clear all data from the session.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("DELETE FROM urls")
                cursor.execute("DELETE FROM forms")
                cursor.execute("DELETE FROM vulnerabilities")
                cursor.execute("DELETE FROM scan_progress")
                cursor.execute("DELETE FROM session_info")
                
                conn.commit()
                
        except Exception as e:
            print(f"Error clearing session: {e}")
    
    def delete(self):
        """
        Delete the session database file.
        """
        try:
            if self.db_path.exists():
                self.db_path.unlink()
        except Exception as e:
            print(f"Error deleting session: {e}")
