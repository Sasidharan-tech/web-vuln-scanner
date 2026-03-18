"""
Banner and Disclaimer Module

Displays the scanner banner and legal disclaimer.
"""

import sys


def print_banner():
    """
    Print the scanner's ASCII art banner.
    """
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗  ║
║   ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗ ║
║   ██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗║
║   ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██║
║   ╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚█║
║    ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ║
║                                                               ║
║            Web Vulnerability Scanner v1.0                     ║
║            Black-Box Security Testing Tool                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_disclaimer() -> bool:
    """
    Display legal disclaimer and get user acknowledgment.
    
    Returns:
        True if user accepts, False otherwise
    """
    disclaimer = """
╔═══════════════════════════════════════════════════════════════╗
║                    LEGAL DISCLAIMER                           ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  This tool is intended for AUTHORIZED SECURITY TESTING ONLY. ║
║                                                               ║
║  By using this scanner, you confirm that:                     ║
║                                                               ║
║  1. You have explicit written permission to test the target   ║
║  2. You are authorized to perform security assessments        ║
║  3. You understand that unauthorized scanning is ILLEGAL      ║
║  4. You accept full responsibility for your actions           ║
║                                                               ║
║  Unauthorized access to computer systems is a criminal        ║
║  offense in most jurisdictions. Penalties may include:        ║
║  - Heavy fines                                                ║
║  - Imprisonment                                               ║
║  - Civil liability                                            ║
║                                                               ║
║  The authors of this tool are NOT responsible for any         ║
║  misuse or damage caused by this program.                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(disclaimer)
    
    try:
        response = input("\nDo you accept these terms? (yes/no): ").strip().lower()
        return response in ['yes', 'y']
    except (KeyboardInterrupt, EOFError):
        return False


def print_scan_header(target_url: str, modules: list):
    """
    Print scan configuration header.
    
    Args:
        target_url: Target URL being scanned
        modules: List of enabled modules
    """
    print("\n" + "="*60)
    print("SCAN CONFIGURATION")
    print("="*60)
    print(f"Target URL: {target_url}")
    print(f"Modules: {', '.join(modules)}")
    print("="*60 + "\n")
