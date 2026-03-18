#!/usr/bin/env python3
"""
Web Vulnerability Scanner - A Black-Box Web Security Testing Tool
Inspired by Wapiti

This tool crawls websites and tests for common vulnerabilities
without accessing the source code (black-box testing).

Author: Security Researcher
License: MIT
"""

import argparse
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from crawler.spider import WebCrawler
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss import XSSScanner
from scanner.command_injection import CommandInjectionScanner
from scanner.file_inclusion import FileInclusionScanner
from scanner.open_redirect import OpenRedirectScanner
from scanner.headers import HeadersScanner
from scanner.cookies import CookieScanner
from database.session import ScanSession
from reports.generator import ReportGenerator
from utils.logger import setup_logger, get_logger
from utils.banner import print_banner, print_disclaimer


def parse_arguments():
    """
    Parse command line arguments for the scanner.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner - Black-box security testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u http://example.com
  python main.py -u http://example.com -m sql,xss --depth 3
  python main.py -u http://example.com -o report.html -f html
  python main.py -u http://example.com --resume
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to scan (e.g., http://example.com)"
    )
    
    # Module selection
    parser.add_argument(
        "-m", "--modules",
        default="all",
        help="Comma-separated list of modules to run (sql,xss,cmd,lfi,redirect,headers,cookies) or 'all'"
    )
    
    # Crawling options
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)"
    )
    
    parser.add_argument(
        "--max-urls",
        type=int,
        default=100,
        help="Maximum number of URLs to crawl (default: 100)"
    )
    
    # Request options
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests in seconds (default: 0.5)"
    )
    
    parser.add_argument(
        "--user-agent",
        default="WebVulnScanner/1.0",
        help="Custom User-Agent string"
    )
    
    # Session options
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume a previous scan session"
    )
    
    parser.add_argument(
        "--session-name",
        help="Custom session name for saving/resuming scans"
    )
    
    # Output options
    parser.add_argument(
        "-o", "--output",
        default="scan_report",
        help="Output file name (without extension)"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["html", "json", "both"],
        default="both",
        help="Report format (default: both)"
    )
    
    # Verbosity
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and non-essential output"
    )
    
    # Skip disclaimer
    parser.add_argument(
        "--accept-terms",
        action="store_true",
        help="Accept the legal disclaimer automatically"
    )
    
    return parser.parse_args()


def get_enabled_modules(module_string: str) -> list:
    """
    Parse the module string and return list of enabled modules.
    
    Args:
        module_string: Comma-separated string of module names or 'all'
        
    Returns:
        List of module names to enable
    """
    all_modules = ["sql", "xss", "cmd", "lfi", "redirect", "headers", "cookies"]
    
    if module_string.lower() == "all":
        return all_modules
    
    requested = [m.strip().lower() for m in module_string.split(",")]
    enabled = [m for m in requested if m in all_modules]
    
    return enabled


def validate_url(url: str) -> bool:
    """
    Validate that the URL is properly formatted.
    
    Args:
        url: URL string to validate
        
    Returns:
        True if URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except Exception:
        return False


def run_scanner(args):
    """
    Main scanner execution function.
    
    Args:
        args: Parsed command line arguments
    """
    logger = get_logger()
    
    # Validate URL
    if not validate_url(args.url):
        logger.error(f"Invalid URL: {args.url}")
        logger.error("URL must start with http:// or https://")
        sys.exit(1)
    
    # Initialize session
    session_name = args.session_name or urlparse(args.url).netloc.replace(".", "_")
    session = ScanSession(session_name)
    
    # Check for resume
    if args.resume:
        if session.can_resume():
            logger.info("Resuming previous scan session...")
            crawled_urls, scanned_urls, vulnerabilities = session.load_progress()
        else:
            logger.warning("No previous session found. Starting new scan...")
            crawled_urls, scanned_urls, vulnerabilities = set(), set(), []
    else:
        crawled_urls, scanned_urls, vulnerabilities = set(), set(), []
        session.clear()
    
    scan_start_time = datetime.now()
    logger.info(f"Starting scan on: {args.url}")
    logger.info(f"Scan started at: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Phase 1: Crawling
    logger.info("\n" + "="*50)
    logger.info("PHASE 1: CRAWLING")
    logger.info("="*50)
    
    crawler = WebCrawler(
        base_url=args.url,
        max_depth=args.depth,
        max_urls=args.max_urls,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent
    )
    
    # Crawl the website
    crawl_results = crawler.crawl(already_crawled=crawled_urls)
    urls = crawl_results["urls"]
    forms = crawl_results["forms"]
    
    logger.info(f"Discovered {len(urls)} URLs and {len(forms)} forms")
    
    # Save crawl progress
    session.save_crawl_progress(urls, forms)
    
    # Phase 2: Scanning
    logger.info("\n" + "="*50)
    logger.info("PHASE 2: VULNERABILITY SCANNING")
    logger.info("="*50)
    
    enabled_modules = get_enabled_modules(args.modules)
    logger.info(f"Enabled modules: {', '.join(enabled_modules)}")
    
    # Initialize scanners
    scanners = {}
    
    if "sql" in enabled_modules:
        scanners["SQL Injection"] = SQLInjectionScanner(
            timeout=args.timeout,
            delay=args.delay
        )
    
    if "xss" in enabled_modules:
        scanners["XSS"] = XSSScanner(
            timeout=args.timeout,
            delay=args.delay
        )
    
    if "cmd" in enabled_modules:
        scanners["Command Injection"] = CommandInjectionScanner(
            timeout=args.timeout,
            delay=args.delay
        )
    
    if "lfi" in enabled_modules:
        scanners["File Inclusion"] = FileInclusionScanner(
            timeout=args.timeout,
            delay=args.delay
        )
    
    if "redirect" in enabled_modules:
        scanners["Open Redirect"] = OpenRedirectScanner(
            timeout=args.timeout,
            delay=args.delay
        )
    
    if "headers" in enabled_modules:
        scanners["Security Headers"] = HeadersScanner(
            timeout=args.timeout
        )
    
    if "cookies" in enabled_modules:
        scanners["Cookie Security"] = CookieScanner(
            timeout=args.timeout
        )
    
    # Run each scanner
    for scanner_name, scanner in scanners.items():
        logger.info(f"\nRunning {scanner_name} scanner...")
        
        try:
            # Different scanners need different inputs
            if scanner_name in ["Security Headers", "Cookie Security"]:
                # These only need URLs
                results = scanner.scan(urls)
            else:
                # These need URLs and forms for parameter injection
                results = scanner.scan(urls, forms)
            
            vulnerabilities.extend(results)
            
            if results:
                logger.warning(f"  Found {len(results)} potential {scanner_name} vulnerabilities")
            else:
                logger.info(f"  No {scanner_name} vulnerabilities found")
                
        except Exception as e:
            logger.error(f"  Error in {scanner_name} scanner: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
    
    # Save scan progress
    session.save_vulnerabilities(vulnerabilities)
    
    scan_end_time = datetime.now()
    scan_duration = scan_end_time - scan_start_time
    
    # Phase 3: Reporting
    logger.info("\n" + "="*50)
    logger.info("PHASE 3: GENERATING REPORTS")
    logger.info("="*50)
    
    report_generator = ReportGenerator(
        target_url=args.url,
        vulnerabilities=vulnerabilities,
        urls_crawled=len(urls),
        forms_found=len(forms),
        scan_duration=str(scan_duration),
        modules_used=enabled_modules
    )
    
    if args.format in ["html", "both"]:
        html_file = report_generator.generate_html(f"{args.output}.html")
        logger.info(f"HTML report saved to: {html_file}")
    
    if args.format in ["json", "both"]:
        json_file = report_generator.generate_json(f"{args.output}.json")
        logger.info(f"JSON report saved to: {json_file}")
    
    # Summary
    logger.info("\n" + "="*50)
    logger.info("SCAN COMPLETE")
    logger.info("="*50)
    logger.info(f"Target: {args.url}")
    logger.info(f"URLs crawled: {len(urls)}")
    logger.info(f"Forms found: {len(forms)}")
    logger.info(f"Vulnerabilities found: {len(vulnerabilities)}")
    logger.info(f"Scan duration: {scan_duration}")
    
    # Severity breakdown
    severity_count = {}
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "Unknown")
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    if severity_count:
        logger.info("\nVulnerabilities by severity:")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in severity_count:
                logger.info(f"  {sev}: {severity_count[sev]}")


def main():
    """Main entry point for the scanner."""
    args = parse_arguments()
    
    # Setup logging
    setup_logger(verbose=args.verbose, quiet=args.quiet)
    logger = get_logger()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Show disclaimer
    if not args.accept_terms:
        if not print_disclaimer():
            logger.info("Scan cancelled by user.")
            sys.exit(0)
    
    try:
        run_scanner(args)
    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user.")
        logger.info("Progress has been saved. Use --resume to continue.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
