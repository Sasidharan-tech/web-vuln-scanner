"""
Report Generator Module

Generates vulnerability reports in HTML and JSON formats.
Reports include:
- Scan summary
- Vulnerability details
- Severity statistics
- Remediation recommendations
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from html import escape


class ReportGenerator:
    """
    Generates security scan reports in multiple formats.
    
    Attributes:
        target_url (str): The scanned target URL
        vulnerabilities (List[Dict]): List of discovered vulnerabilities
        urls_crawled (int): Number of URLs crawled
        forms_found (int): Number of forms discovered
        scan_duration (str): Total scan duration
        modules_used (List[str]): List of scanner modules used
    """
    
    def __init__(
        self,
        target_url: str,
        vulnerabilities: List[Dict],
        urls_crawled: int = 0,
        forms_found: int = 0,
        scan_duration: str = "",
        modules_used: List[str] = None
    ):
        """
        Initialize the report generator.
        
        Args:
            target_url: Target URL that was scanned
            vulnerabilities: List of vulnerability dictionaries
            urls_crawled: Number of URLs crawled
            forms_found: Number of forms found
            scan_duration: Duration of the scan
            modules_used: List of scanner modules used
        """
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.urls_crawled = urls_crawled
        self.forms_found = forms_found
        self.scan_duration = scan_duration
        self.modules_used = modules_used or []
        self.report_time = datetime.now()
    
    def get_severity_stats(self) -> Dict[str, int]:
        """
        Calculate vulnerability counts by severity.
        
        Returns:
            Dictionary mapping severity levels to counts
        """
        stats = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Info')
            if severity in stats:
                stats[severity] += 1
            else:
                stats['Info'] += 1
        
        return stats
    
    def get_vuln_by_type(self) -> Dict[str, List[Dict]]:
        """
        Group vulnerabilities by type.
        
        Returns:
            Dictionary mapping vulnerability types to lists of vulns
        """
        by_type = {}
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(vuln)
        
        return by_type
    
    def generate_json(self, output_path: str) -> str:
        """
        Generate a JSON format report.
        
        Args:
            output_path: Path to save the JSON file
            
        Returns:
            Path to the generated file
        """
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_time': self.report_time.isoformat(),
                'duration': self.scan_duration,
                'urls_crawled': self.urls_crawled,
                'forms_found': self.forms_found,
                'modules_used': self.modules_used,
                'scanner_version': '1.0'
            },
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': self.get_severity_stats(),
                'vulnerability_types': list(self.get_vuln_by_type().keys())
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(output_file)
    
    def generate_html(self, output_path: str) -> str:
        """
        Generate an HTML format report.
        
        Args:
            output_path: Path to save the HTML file
            
        Returns:
            Path to the generated file
        """
        severity_stats = self.get_severity_stats()
        vulns_by_type = self.get_vuln_by_type()
        
        # Severity colors
        severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#17a2b8',
            'Info': '#6c757d'
        }
        
        # Build HTML content
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {escape(self.target_url)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 10px;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header .target-url {{
            font-size: 1.2em;
            opacity: 0.9;
            word-break: break-all;
        }}
        
        .card {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .card-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .card-body {{
            padding: 20px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
        }}
        
        .stat-box {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin-top: 20px;
        }}
        
        .severity-box {{
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            color: white;
        }}
        
        .severity-box.critical {{ background-color: #dc3545; }}
        .severity-box.high {{ background-color: #fd7e14; }}
        .severity-box.medium {{ background-color: #ffc107; color: #333; }}
        .severity-box.low {{ background-color: #17a2b8; }}
        .severity-box.info {{ background-color: #6c757d; }}
        
        .vuln-card {{
            border-left: 4px solid #ddd;
            margin-bottom: 15px;
            padding: 15px;
            background: #fafafa;
            border-radius: 0 8px 8px 0;
        }}
        
        .vuln-card.critical {{ border-left-color: #dc3545; }}
        .vuln-card.high {{ border-left-color: #fd7e14; }}
        .vuln-card.medium {{ border-left-color: #ffc107; }}
        .vuln-card.low {{ border-left-color: #17a2b8; }}
        .vuln-card.info {{ border-left-color: #6c757d; }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .vuln-type {{
            font-weight: bold;
            font-size: 1.1em;
        }}
        
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        
        .severity-badge.critical {{ background-color: #dc3545; }}
        .severity-badge.high {{ background-color: #fd7e14; }}
        .severity-badge.medium {{ background-color: #ffc107; color: #333; }}
        .severity-badge.low {{ background-color: #17a2b8; }}
        .severity-badge.info {{ background-color: #6c757d; }}
        
        .vuln-detail {{
            margin: 8px 0;
        }}
        
        .vuln-detail strong {{
            color: #555;
        }}
        
        .vuln-detail code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', monospace;
            word-break: break-all;
        }}
        
        .description-box {{
            background: #fff;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
            border: 1px solid #eee;
        }}
        
        .recommendation-box {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
            border: 1px solid #c8e6c9;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        
        .no-vulns {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 1.2em;
        }}
        
        .no-vulns::before {{
            content: '✓';
            display: block;
            font-size: 3em;
            margin-bottom: 10px;
        }}
        
        @media (max-width: 768px) {{
            .severity-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Vulnerability Scan Report</h1>
            <p class="target-url">{escape(self.target_url)}</p>
        </header>
        
        <!-- Scan Summary -->
        <div class="card">
            <div class="card-header">📊 Scan Summary</div>
            <div class="card-body">
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-number">{self.urls_crawled}</div>
                        <div class="stat-label">URLs Crawled</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{self.forms_found}</div>
                        <div class="stat-label">Forms Found</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(self.vulnerabilities)}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(self.modules_used)}</div>
                        <div class="stat-label">Modules Used</div>
                    </div>
                </div>
                
                <div class="severity-grid">
                    <div class="severity-box critical">
                        <div style="font-size: 1.5em; font-weight: bold;">{severity_stats['Critical']}</div>
                        <div>Critical</div>
                    </div>
                    <div class="severity-box high">
                        <div style="font-size: 1.5em; font-weight: bold;">{severity_stats['High']}</div>
                        <div>High</div>
                    </div>
                    <div class="severity-box medium">
                        <div style="font-size: 1.5em; font-weight: bold;">{severity_stats['Medium']}</div>
                        <div>Medium</div>
                    </div>
                    <div class="severity-box low">
                        <div style="font-size: 1.5em; font-weight: bold;">{severity_stats['Low']}</div>
                        <div>Low</div>
                    </div>
                    <div class="severity-box info">
                        <div style="font-size: 1.5em; font-weight: bold;">{severity_stats['Info']}</div>
                        <div>Info</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Scan Details -->
        <div class="card">
            <div class="card-header">ℹ️ Scan Details</div>
            <div class="card-body">
                <p><strong>Scan Time:</strong> {self.report_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Duration:</strong> {escape(self.scan_duration)}</p>
                <p><strong>Modules:</strong> {escape(', '.join(self.modules_used))}</p>
            </div>
        </div>
        
        <!-- Vulnerabilities -->
        <div class="card">
            <div class="card-header">🔍 Vulnerabilities Found</div>
            <div class="card-body">
"""
        
        if not self.vulnerabilities:
            html += """
                <div class="no-vulns">
                    No vulnerabilities were detected during this scan.
                </div>
"""
        else:
            # Group by type and display
            for vuln_type, vulns in vulns_by_type.items():
                html += f"""
                <h3 style="margin: 20px 0 15px 0; padding-bottom: 10px; border-bottom: 2px solid #eee;">
                    {escape(vuln_type)} ({len(vulns)})
                </h3>
"""
                for vuln in vulns:
                    severity = vuln.get('severity', 'Info').lower()
                    html += f"""
                <div class="vuln-card {severity}">
                    <div class="vuln-header">
                        <span class="vuln-type">{escape(vuln.get('type', 'Unknown'))}</span>
                        <span class="severity-badge {severity}">{escape(vuln.get('severity', 'Info'))}</span>
                    </div>
                    
                    <div class="vuln-detail">
                        <strong>URL:</strong> <code>{escape(vuln.get('url', 'N/A'))}</code>
                    </div>
                    
                    <div class="vuln-detail">
                        <strong>Parameter:</strong> <code>{escape(vuln.get('parameter', 'N/A'))}</code>
                    </div>
                    
                    <div class="vuln-detail">
                        <strong>Payload:</strong> <code>{escape(vuln.get('payload', 'N/A'))}</code>
                    </div>
                    
                    <div class="vuln-detail">
                        <strong>Evidence:</strong> <code>{escape(vuln.get('evidence', 'N/A')[:200])}</code>
                    </div>
                    
                    <div class="description-box">
                        <strong>Description:</strong><br>
                        {escape(vuln.get('description', 'No description available.'))}
                    </div>
                    
                    <div class="recommendation-box">
                        <strong>✅ Recommendation:</strong><br>
                        {escape(vuln.get('recommendation', 'No recommendation available.'))}
                    </div>
                </div>
"""
        
        html += f"""
            </div>
        </div>
        
        <footer>
            <p>Generated by Web Vulnerability Scanner v1.0</p>
            <p>Report generated on {self.report_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Disclaimer:</strong> This report is for authorized security testing only.</p>
        </footer>
    </div>
</body>
</html>
"""
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(output_file)
