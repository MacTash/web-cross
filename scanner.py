#!/usr/bin/env python3
"""
Web-Cross Vulnerability Scanner v2.0
Professional web security scanner with comprehensive detection and reporting.
"""

import argparse
import shutil
import sys
import time
import warnings
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Import scanner modules
from modules import (
    # Advanced
    CommandInjectionScanner,
    CORSScanner,
    CSRFScanner,
    DirectoryScanner,
    HeaderScanner,
    HTMLAttackScanner,
    InputFieldScanner,
    JWTScanner,
    PathTraversalScanner,
    # Core
    SQLiScanner,
    SSRFScanner,
    # Recon
    TechFingerprinter,
    WAFDetector,
    XSSScanner,
    XXEScanner,
)
from modules.llm_analyzer import get_analyzer
from reporting import ReportGenerator, RiskCalculator

# Suppress SSL warnings (placed after imports to satisfy E402)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

console = Console()
VERSION = "2.0"


class WebCrossScanner:
    """Main scanner orchestrator"""

    def __init__(self, target_url: str, timeout: int = 10,
                 scan_mode: str = "full", threads: int = 10, use_ai: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.scan_mode = scan_mode
        self.threads = threads
        self.use_ai = use_ai
        self.user_agent = f"WebCross-Scanner/{VERSION}"
        self.findings = []
        self.forms = []
        self.urls_to_scan = set()
        self.technologies = []

        # Initialize LLM analyzer if AI mode enabled
        self.llm = None
        if use_ai:
            self.llm = get_analyzer()
            if not self.llm.is_available():
                print("⚠️ AI mode requested but Ollama not available. Continuing without AI.")
                self.llm = None

        # Initialize all scanners
        self.scanners = {
            # Core
            'headers': HeaderScanner(timeout, self.user_agent),
            'sqli': SQLiScanner(timeout, self.user_agent),
            'xss': XSSScanner(timeout, self.user_agent),
            'csrf': CSRFScanner(timeout, self.user_agent),
            'html': HTMLAttackScanner(timeout, self.user_agent),
            'input': InputFieldScanner(timeout, self.user_agent),
            # Advanced
            'cmdi': CommandInjectionScanner(timeout, self.user_agent),
            'lfi': PathTraversalScanner(timeout, self.user_agent),
            'ssrf': SSRFScanner(timeout, self.user_agent),
            'xxe': XXEScanner(timeout, self.user_agent),
            'cors': CORSScanner(timeout, self.user_agent),
            'jwt': JWTScanner(timeout, self.user_agent),
            # Recon
            'fingerprint': TechFingerprinter(timeout, self.user_agent),
            'waf': WAFDetector(timeout, self.user_agent),
            'directory': DirectoryScanner(timeout, self.user_agent, threads),
        }

    def _make_request(self, url: str) -> requests.Response:
        try:
            headers = {"User-Agent": self.user_agent}
            return requests.get(url, headers=headers, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list[dict]:
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '') or base_url
            if not action.startswith(('http://', 'https://')):
                action = urljoin(base_url, action)

            inputs = {}
            input_types = {}
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    inputs[name] = inp.get('value', '')
                    input_types[name] = inp.get('type', 'text')

            if inputs:
                forms.append({
                    'action': action,
                    'method': form.get('method', 'GET').upper(),
                    'inputs': inputs,
                    'input_types': input_types
                })
        return forms

    def _extract_urls(self, soup: BeautifulSoup, base_url: str) -> set:
        urls = set()
        parsed_base = urlparse(base_url)
        for link in soup.find_all('a', href=True):
            href = link['href']
            if not href or href.startswith('#'):
                continue
            if not href.startswith(('http://', 'https://')):
                href = urljoin(base_url, href)
            parsed = urlparse(href)
            if parsed.netloc == parsed_base.netloc:
                urls.add(href)
        return urls

    def crawl(self, depth: int = 2) -> None:
        self.urls_to_scan.add(self.target_url)
        visited = set()

        for _ in range(depth):
            new_urls = set()
            for url in list(self.urls_to_scan):
                if url in visited:
                    continue
                visited.add(url)

                response = self._make_request(url)
                if not response:
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                page_forms = self._extract_forms(soup, url)
                for f in page_forms:
                    f['source_url'] = url
                self.forms.extend(page_forms)
                page_urls = self._extract_urls(soup, url)
                new_urls.update(page_urls)

            self.urls_to_scan.update(new_urls)

    def run_recon(self) -> None:
        """Run reconnaissance modules"""
        # Fingerprint technologies
        tech = self.scanners['fingerprint'].scan_url(self.target_url)
        self.technologies = tech
        self.findings.extend([t for t in tech if t.get('type') in ['GIT_EXPOSED']])

        # Detect WAF
        waf = self.scanners['waf'].detect_waf(self.target_url)
        self.findings.extend(waf)

        # Directory discovery (quick mode)
        if self.scan_mode in ['full', 'recon']:
            dirs = self.scanners['directory'].scan_url(self.target_url)
            self.findings.extend([d for d in dirs if d.get('confidence') == 'HIGH'])

    def run_core_scans(self) -> None:
        """Run core vulnerability scans"""
        # Headers
        self.findings.extend(self.scanners['headers'].scan_url(self.target_url))

        # SQL Injection
        for url in self.urls_to_scan:
            if '?' in url:
                self.findings.extend(self.scanners['sqli'].scan_url(url))
        for form in self.forms:
            self.findings.extend(self.scanners['sqli'].scan_form(form['source_url'], form))

        # XSS
        for url in self.urls_to_scan:
            if '?' in url:
                self.findings.extend(self.scanners['xss'].scan_url(url))
        for form in self.forms:
            self.findings.extend(self.scanners['xss'].scan_form(form['source_url'], form))

        # CSRF
        for url in self.urls_to_scan:
            self.findings.extend(self.scanners['csrf'].scan_url(url))

        # HTML Attacks
        for url in self.urls_to_scan:
            self.findings.extend(self.scanners['html'].scan_url(url))

        # Input fields
        for url in self.urls_to_scan:
            self.findings.extend(self.scanners['input'].scan_url(url))

    def run_advanced_scans(self) -> None:
        """Run advanced vulnerability scans"""
        # Command Injection
        for url in self.urls_to_scan:
            if '?' in url:
                self.findings.extend(self.scanners['cmdi'].scan_url(url))

        # Path Traversal (LFI)
        for url in self.urls_to_scan:
            if '?' in url:
                self.findings.extend(self.scanners['lfi'].scan_url(url))

        # SSRF
        for url in self.urls_to_scan:
            if '?' in url:
                self.findings.extend(self.scanners['ssrf'].scan_url(url))

        # CORS
        self.findings.extend(self.scanners['cors'].scan_url(self.target_url))

        # JWT
        self.findings.extend(self.scanners['jwt'].scan_url(self.target_url))

        # XXE (only on endpoints that might accept XML)
        self.findings.extend(self.scanners['xxe'].scan_endpoint(self.target_url))

    def run_full_scan(self) -> list[dict]:
        """Run complete scan based on mode"""
        scan_steps = []

        if self.scan_mode in ['full', 'quick', 'recon']:
            scan_steps.append(("Crawling website...", self.crawl))
            scan_steps.append(("Running reconnaissance...", self.run_recon))

        if self.scan_mode in ['full', 'quick', 'core']:
            scan_steps.append(("Running core scans...", self.run_core_scans))

        if self.scan_mode in ['full', 'advanced']:
            scan_steps.append(("Running advanced scans...", self.run_advanced_scans))

        # Add AI analysis step if enabled
        if self.use_ai and self.llm:
            scan_steps.append(("Running AI analysis...", self.run_ai_analysis))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(scan_steps))

            for desc, func in scan_steps:
                progress.update(task, description=f"[cyan]{desc}")
                func()
                progress.advance(task)

        return self.findings

    def run_ai_analysis(self) -> None:
        """Run AI-powered vulnerability analysis using LLM"""
        if not self.llm or not self.llm.is_available():
            return

        # Analyze main page
        response = self._make_request(self.target_url)
        if response:
            result = self.llm.analyze_response(
                response.text,
                url=self.target_url,
                context={"headers": dict(response.headers)}
            )

            # Add AI findings
            for vuln in result.vulnerabilities:
                self.findings.append({
                    "type": f"AI_{vuln.get('type', 'UNKNOWN')}",
                    "evidence": vuln.get('evidence', ''),
                    "severity": vuln.get('severity', 'Medium'),
                    "url": self.target_url,
                    "recommendation": vuln.get('recommendation', ''),
                    "source": "llm_analysis",
                    "risk_score": self._severity_to_score(vuln.get('severity', 'Medium')),
                })

        # Generate risk assessment for all findings
        if self.findings:
            assessment = self.llm.assess_risk(self.findings, self.target_url)
            # Add assessment as a meta-finding
            self.findings.append({
                "type": "AI_RISK_ASSESSMENT",
                "evidence": f"Overall Risk: {assessment.get('risk_level', 'Unknown')}",
                "severity": assessment.get('risk_level', 'Medium'),
                "url": self.target_url,
                "source": "llm_analysis",
                "risk_score": 0,  # Meta finding, not a vulnerability
            })

    def _severity_to_score(self, severity: str) -> int:
        """Convert severity string to risk score"""
        mapping = {
            "Critical": 10,
            "High": 8,
            "Medium": 5,
            "Low": 2,
        }
        return mapping.get(severity, 5)


def display_results(findings: list[dict], technologies: list[dict] = None) -> None:
    """Display scan results"""
    # Show technologies
    if technologies:
        tech_table = Table(title="🔧 Detected Technologies", show_lines=False)
        tech_table.add_column("Technology", style="cyan")
        tech_table.add_column("Category", style="dim")

        seen = set()
        for tech in technologies[:10]:
            key = tech.get('technology', '')
            if key and key not in seen:
                seen.add(key)
                tech_table.add_row(key, tech.get('category', ''))

        if seen:
            console.print(tech_table)
            console.print()

    if not findings:
        console.print(Panel("[green]No vulnerabilities found![/green]",
                          title="Scan Complete"))
        return

    # Calculate risk
    risk = RiskCalculator.calculate_overall_score(findings)

    # Summary panel
    console.print(Panel(
        f"[bold]Overall Risk Score:[/bold] {risk['score']} ({risk['severity']})\n"
        f"[red]Critical: {risk['critical_count']}[/red] | "
        f"[orange1]High: {risk['high_count']}[/orange1] | "
        f"[yellow]Medium: {risk['medium_count']}[/yellow] | "
        f"[green]Low: {risk['low_count']}[/green]",
        title="📊 Scan Summary"
    ))

    # Findings table
    table = Table(title="🔍 Vulnerability Findings", show_lines=True)
    table.add_column("Type", style="cyan", width=25)
    table.add_column("Risk", width=8)
    table.add_column("URL/Parameter", width=40)
    table.add_column("Evidence", width=40)

    for finding in findings[:25]:
        risk_score = finding.get('risk_score', 0)

        if risk_score >= 9:
            risk_style = "[red]"
        elif risk_score >= 7:
            risk_style = "[orange1]"
        elif risk_score >= 4:
            risk_style = "[yellow]"
        else:
            risk_style = "[green]"

        url_info = finding.get('url', 'N/A')[:35]
        if finding.get('parameter'):
            url_info = f"[{finding['parameter']}]"

        evidence = finding.get('evidence', 'N/A') or 'N/A'
        table.add_row(
            finding.get('type', 'N/A')[:25],
            f"{risk_style}{risk_score}[/]",
            url_info,
            evidence[:35] + '...' if len(evidence) > 35 else evidence
        )

    console.print(table)

    if len(findings) > 25:
        console.print(f"[dim]Showing 25 of {len(findings)} findings. See report for full details.[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="Web-Cross Vulnerability Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Modes:
  full      All scans (recon + core + advanced)
  quick     Fast scan (crawl + core only)
  core      Core vulnerabilities (SQLi, XSS, CSRF, etc.)
  advanced  Advanced vulns (CMDI, LFI, SSRF, XXE, etc.)
  recon     Reconnaissance only (fingerprint, WAF, dirs)

Examples:
  python scanner.py -u https://example.com
  python scanner.py -u https://example.com --mode full
  python scanner.py -u https://example.com --mode recon
  python scanner.py --server
        """
    )

    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--report', choices=['html', 'json', 'text', 'all'],
                       default='html', help='Report format')
    parser.add_argument('--mode', choices=['full', 'quick', 'core', 'advanced', 'recon'],
                       default='full', help='Scan mode')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--threads', type=int, default=10, help='Thread count')
    parser.add_argument('--server', action='store_true', help='Start web server')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--clean', action='store_true', help='Clean pycache, .pyc, and old reports')
    parser.add_argument('--ai', action='store_true', help='Enable AI-powered analysis (Ollama)')

    args = parser.parse_args()

    # Banner
    console.print(Panel.fit(
        f"[bold cyan]WEB-CROSS[/bold cyan] [dim]v{VERSION}[/dim]\n"
        "[dim]Professional Web Vulnerability Scanner[/dim]\n"
        "[dim cyan]15 Modules | Detection + Remediation[/dim cyan]",
        border_style="cyan"
    ))

    # Server mode
    if args.server:
        console.print(f"[green]Starting server at http://localhost:{args.port}[/green]")
        try:
            from server import app
            app.run(host='0.0.0.0', port=args.port, debug=False)
        except ImportError:
            console.print("[red]Run: python server.py[/red]")
        return

    # Clean mode
    if args.clean:
        base_dir = Path(__file__).parent
        removed = 0

        # Remove __pycache__ directories
        for pycache in base_dir.rglob('__pycache__'):
            if pycache.is_dir():
                shutil.rmtree(pycache)
                removed += 1
                console.print(f"[dim]Removed: {pycache}[/dim]")

        # Remove .pyc files
        for pyc in base_dir.rglob('*.pyc'):
            pyc.unlink()
            removed += 1

        # Remove old reports
        for pattern in ['webcross_report_*.html', 'webcross_report_*.json', 'webcross_report_*.txt']:
            for report in base_dir.glob(pattern):
                report.unlink()
                removed += 1
                console.print(f"[dim]Removed: {report.name}[/dim]")

        console.print(f"[green]✓ Cleaned {removed} items[/green]")
        return

    # Validate URL
    if not args.url:
        console.print("[red]Error: URL required. Use -u/--url[/red]")
        sys.exit(1)

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        console.print("[red]Error: Invalid URL[/red]")
        sys.exit(1)

    # Run scan
    start_time = time.time()
    console.print(f"\n[cyan]Target:[/cyan] {args.url}")
    console.print(f"[cyan]Mode:[/cyan] {args.mode}")
    if args.ai:
        console.print("[cyan]AI Mode:[/cyan] Enabled (llama3.2:3b)")
    console.print()

    scanner = WebCrossScanner(args.url, args.timeout, args.mode, args.threads, use_ai=args.ai)
    findings = scanner.run_full_scan()

    duration = time.time() - start_time
    duration_str = f"{duration:.1f}s"

    # Display
    display_results(findings, scanner.technologies)

    # Reports
    if findings:
        reporter = ReportGenerator(args.url, findings, duration_str)
        output_base = args.output or f"webcross_report_{int(time.time())}"

        if args.report in ['html', 'all']:
            path = f"{output_base}.html" if not output_base.endswith('.html') else output_base
            reporter.generate_html(path)
            console.print(f"\n[green]HTML report:[/green] {path}")

        if args.report in ['json', 'all']:
            path = f"{output_base}.json" if not output_base.endswith('.json') else output_base
            reporter.generate_json(path)
            console.print(f"[green]JSON report:[/green] {path}")

        if args.report in ['text', 'all']:
            path = f"{output_base}.txt" if not output_base.endswith('.txt') else output_base
            reporter.generate_text(path)
            console.print(f"[green]Text report:[/green] {path}")

    console.print(f"\n[dim]Completed in {duration_str}[/dim]")


if __name__ == "__main__":
    main()

