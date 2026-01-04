"""
PDF Report Generator
Creates professional PDF security reports using WeasyPrint.
"""

import html as html_module
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from weasyprint import CSS, HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

from .compliance import get_compliance_mapper


class PDFReportGenerator:
    """
    Generates professional PDF security reports.

    Features:
    - Executive summary
    - Detailed findings
    - Compliance mapping
    - Risk scoring
    - Remediation guidance
    """

    # CSS styles for PDF
    PDF_STYLES = """
        @page {
            size: A4;
            margin: 2cm;
            @top-right {
                content: "Web-Cross Security Report";
                font-size: 10px;
                color: #666;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10px;
                color: #666;
            }
        }

        body {
            font-family: 'Helvetica Neue', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }

        h1 {
            color: #1a1a2e;
            border-bottom: 3px solid #16213e;
            padding-bottom: 10px;
            font-size: 24pt;
        }

        h2 {
            color: #16213e;
            border-bottom: 2px solid #0f3460;
            padding-bottom: 8px;
            margin-top: 30px;
            font-size: 18pt;
        }

        h3 {
            color: #0f3460;
            font-size: 14pt;
            margin-top: 20px;
        }

        .cover {
            text-align: center;
            padding: 100px 0;
            page-break-after: always;
        }

        .cover h1 {
            font-size: 36pt;
            border: none;
            color: #16213e;
        }

        .cover .subtitle {
            font-size: 18pt;
            color: #666;
            margin-top: 20px;
        }

        .cover .date {
            font-size: 14pt;
            color: #888;
            margin-top: 40px;
        }

        .summary-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .severity-critical {
            background: #dc3545;
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: bold;
        }

        .severity-high {
            background: #fd7e14;
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: bold;
        }

        .severity-medium {
            background: #ffc107;
            color: #333;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: bold;
        }

        .severity-low {
            background: #28a745;
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: bold;
        }

        .severity-info {
            background: #17a2b8;
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: bold;
        }

        .finding {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            page-break-inside: avoid;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }

        .finding-title {
            font-size: 14pt;
            font-weight: bold;
            color: #16213e;
        }

        .finding-url {
            font-family: monospace;
            font-size: 10pt;
            color: #666;
            background: #f8f9fa;
            padding: 5px 10px;
            border-radius: 4px;
            word-break: break-all;
        }

        .finding-section {
            margin: 15px 0;
        }

        .finding-section-title {
            font-weight: bold;
            color: #0f3460;
            margin-bottom: 5px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }

        th, td {
            border: 1px solid #dee2e6;
            padding: 10px;
            text-align: left;
        }

        th {
            background: #16213e;
            color: white;
        }

        tr:nth-child(even) {
            background: #f8f9fa;
        }

        .compliance-badge {
            display: inline-block;
            background: #e9ecef;
            padding: 3px 8px;
            border-radius: 4px;
            margin: 2px;
            font-size: 9pt;
        }

        .toc {
            page-break-after: always;
        }

        .toc a {
            text-decoration: none;
            color: #333;
        }

        code {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 2px 5px;
            border-radius: 3px;
        }

        .page-break {
            page-break-before: always;
        }
    """

    def __init__(
        self,
        output_dir: Path = None,
        company_name: str = None,
        include_toc: bool = True,
        include_compliance: bool = True,
    ):
        self.output_dir = output_dir or Path.cwd() / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.company_name = company_name
        self.include_toc = include_toc
        self.include_compliance = include_compliance
        self.compliance_mapper = get_compliance_mapper()

    def generate(
        self,
        findings: list[dict[str, Any]],
        target: str,
        scan_info: dict[str, Any] = None,
        output_path: Path = None,
    ) -> Path:
        """
        Generate PDF security report.

        Args:
            findings: List of vulnerability findings
            target: Target URL/application
            scan_info: Additional scan information
            output_path: Output file path

        Returns:
            Path to generated PDF
        """
        if not WEASYPRINT_AVAILABLE:
            raise RuntimeError("WeasyPrint not installed. Run: pip install weasyprint")

        scan_info = scan_info or {}

        # Enrich findings with compliance data
        if self.include_compliance:
            findings = self.compliance_mapper.enrich_findings(findings)

        # Generate HTML
        html_content = self._generate_html(findings, target, scan_info)

        # Generate PDF
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"security_report_{timestamp}.pdf"

        html_doc = HTML(string=html_content)
        css = CSS(string=self.PDF_STYLES)
        html_doc.write_pdf(output_path, stylesheets=[css])

        return output_path

    def _generate_html(
        self,
        findings: list[dict[str, Any]],
        target: str,
        scan_info: dict[str, Any],
    ) -> str:
        """Generate HTML content for PDF"""
        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(
                x.get("severity_label", x.get("severity", "MEDIUM")).upper(), 2
            )
        )

        # Count severities
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity_label", f.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Generate compliance summary
        compliance_summary = None
        if self.include_compliance:
            compliance_summary = self.compliance_mapper.generate_compliance_summary(findings)

        # Build HTML
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Security Assessment Report - {html_module.escape(target)}</title>
        </head>
        <body>
            {self._generate_cover(target, scan_info)}
            {self._generate_executive_summary(findings, target, severity_counts, scan_info)}
            {self._generate_findings_summary_table(sorted_findings)}
            {self._generate_detailed_findings(sorted_findings)}
            {self._generate_compliance_section(compliance_summary) if compliance_summary else ""}
            {self._generate_appendix(scan_info)}
        </body>
        </html>
        """

        return html

    def _generate_cover(self, target: str, scan_info: dict) -> str:
        """Generate cover page"""
        date = datetime.now().strftime("%B %d, %Y")
        company = self.company_name or "Web-Cross Security Scanner"

        return f"""
        <div class="cover">
            <h1>🔒 Security Assessment Report</h1>
            <div class="subtitle">Vulnerability Scan Results for</div>
            <div class="subtitle"><strong>{html_module.escape(target)}</strong></div>
            <div class="date">Generated: {date}</div>
            <div class="date" style="margin-top: 60px;">Prepared by: {html_module.escape(company)}</div>
        </div>
        """

    def _generate_executive_summary(
        self,
        findings: list[dict],
        target: str,
        severity_counts: dict,
        scan_info: dict,
    ) -> str:
        """Generate executive summary section"""
        total = len(findings)
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)

        # Determine overall risk
        if critical > 0:
            risk_level = "CRITICAL"
            risk_description = "Immediate action required. Critical vulnerabilities present."
        elif high > 0:
            risk_level = "HIGH"
            risk_description = "High priority remediation needed."
        elif severity_counts.get("MEDIUM", 0) > 0:
            risk_level = "MEDIUM"
            risk_description = "Moderate risk. Address in next development cycle."
        else:
            risk_level = "LOW"
            risk_description = "Low risk. Minor issues identified."

        return f"""
        <h2>Executive Summary</h2>

        <div class="summary-box">
            <h3>Assessment Overview</h3>
            <p><strong>Target:</strong> {html_module.escape(target)}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
            <p><strong>Scan Mode:</strong> {scan_info.get("mode", "Full")}</p>
            <p><strong>Total Vulnerabilities:</strong> {total}</p>
        </div>

        <div class="summary-box">
            <h3>Risk Assessment</h3>
            <p><strong>Overall Risk Level:</strong> <span class="severity-{risk_level.lower()}">{risk_level}</span></p>
            <p>{risk_description}</p>
        </div>

        <h3>Vulnerability Distribution</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
            <tr>
                <td><span class="severity-critical">CRITICAL</span></td>
                <td>{critical}</td>
                <td>{(critical/total*100) if total else 0:.1f}%</td>
            </tr>
            <tr>
                <td><span class="severity-high">HIGH</span></td>
                <td>{high}</td>
                <td>{(high/total*100) if total else 0:.1f}%</td>
            </tr>
            <tr>
                <td><span class="severity-medium">MEDIUM</span></td>
                <td>{severity_counts.get("MEDIUM", 0)}</td>
                <td>{(severity_counts.get("MEDIUM", 0)/total*100) if total else 0:.1f}%</td>
            </tr>
            <tr>
                <td><span class="severity-low">LOW</span></td>
                <td>{severity_counts.get("LOW", 0)}</td>
                <td>{(severity_counts.get("LOW", 0)/total*100) if total else 0:.1f}%</td>
            </tr>
        </table>
        """

    def _generate_findings_summary_table(self, findings: list[dict]) -> str:
        """Generate findings summary table"""
        rows = ""
        for i, f in enumerate(findings[:50], 1):  # Limit to 50 for summary
            vuln_type = html_module.escape(f.get("type", "Unknown"))
            severity = f.get("severity_label", f.get("severity", "MEDIUM")).upper()
            url = html_module.escape(f.get("url", "N/A")[:60])

            rows += f"""
            <tr>
                <td>{i}</td>
                <td>{vuln_type}</td>
                <td><span class="severity-{severity.lower()}">{severity}</span></td>
                <td><code>{url}</code></td>
            </tr>
            """

        return f"""
        <h2 class="page-break">Findings Summary</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Location</th>
            </tr>
            {rows}
        </table>
        """

    def _generate_detailed_findings(self, findings: list[dict]) -> str:
        """Generate detailed findings section"""
        content = '<h2 class="page-break">Detailed Findings</h2>'

        for i, finding in enumerate(findings[:30], 1):  # Limit detailed to 30
            content += self._generate_finding_block(i, finding)

        if len(findings) > 30:
            content += f'<p><em>...and {len(findings) - 30} additional findings.</em></p>'

        return content

    def _generate_finding_block(self, index: int, finding: dict) -> str:
        """Generate a single finding block"""
        vuln_type = html_module.escape(finding.get("type", "Unknown"))
        severity = finding.get("severity_label", finding.get("severity", "MEDIUM")).upper()
        url = html_module.escape(finding.get("url", "N/A"))
        description = html_module.escape(finding.get("description", "No description available."))
        evidence = html_module.escape(str(finding.get("evidence", "N/A")))
        remediation = html_module.escape(finding.get("remediation", "Consult security best practices."))

        # Compliance info
        compliance_html = ""
        if "compliance" in finding:
            comp = finding["compliance"]
            badges = []
            if comp.get("owasp_top_10"):
                badges.append(f'<span class="compliance-badge">OWASP: {comp["owasp_top_10"]}</span>')
            if comp.get("cwe_id"):
                badges.append(f'<span class="compliance-badge">{comp["cwe_id"]}</span>')
            if comp.get("cvss_base"):
                badges.append(f'<span class="compliance-badge">CVSS: {comp["cvss_base"]}</span>')
            if badges:
                compliance_html = f'<div class="finding-section"><div class="finding-section-title">Compliance:</div>{"".join(badges)}</div>'

        return f"""
        <div class="finding">
            <div class="finding-header">
                <span class="finding-title">{index}. {vuln_type}</span>
                <span class="severity-{severity.lower()}">{severity}</span>
            </div>

            <div class="finding-url">{url}</div>

            <div class="finding-section">
                <div class="finding-section-title">Description:</div>
                <p>{description}</p>
            </div>

            <div class="finding-section">
                <div class="finding-section-title">Evidence:</div>
                <code>{evidence[:300]}</code>
            </div>

            <div class="finding-section">
                <div class="finding-section-title">Remediation:</div>
                <p>{remediation}</p>
            </div>

            {compliance_html}
        </div>
        """

    def _generate_compliance_section(self, summary: dict) -> str:
        """Generate compliance mapping section"""
        owasp_rows = ""
        for code, info in summary.get("owasp_top_10", {}).items():
            owasp_rows += f'<tr><td>{code}</td><td>{info["category"]}</td><td>{info["count"]}</td></tr>'

        cwe_rows = ""
        for cwe_id, info in summary.get("cwe", {}).items():
            cwe_rows += f'<tr><td>{cwe_id}</td><td>{info["name"]}</td><td>{info["count"]}</td></tr>'

        return f"""
        <h2 class="page-break">Compliance Mapping</h2>

        <h3>OWASP Top 10 (2021)</h3>
        <table>
            <tr><th>Category</th><th>Description</th><th>Findings</th></tr>
            {owasp_rows if owasp_rows else '<tr><td colspan="3">No mapped findings</td></tr>'}
        </table>

        <h3>CWE Mapping</h3>
        <table>
            <tr><th>CWE ID</th><th>Name</th><th>Findings</th></tr>
            {cwe_rows if cwe_rows else '<tr><td colspan="3">No mapped findings</td></tr>'}
        </table>

        <h3>Other Standards</h3>
        <p><strong>PCI-DSS Requirements:</strong> {', '.join(summary.get('pci_dss', [])) or 'None'}</p>
        <p><strong>NIST Controls:</strong> {', '.join(summary.get('nist', [])) or 'None'}</p>
        <p><strong>GDPR Articles:</strong> {', '.join(summary.get('gdpr', [])) or 'None'}</p>
        """

    def _generate_appendix(self, scan_info: dict) -> str:
        """Generate appendix section"""
        return f"""
        <h2 class="page-break">Appendix</h2>

        <h3>Scan Configuration</h3>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>Scanner Version</td><td>Web-Cross v3.0</td></tr>
            <tr><td>Scan Mode</td><td>{scan_info.get("mode", "Full")}</td></tr>
            <tr><td>AI Analysis</td><td>{"Enabled" if scan_info.get("ai_enabled") else "Disabled"}</td></tr>
            <tr><td>Threads</td><td>{scan_info.get("threads", 10)}</td></tr>
        </table>

        <h3>Disclaimer</h3>
        <p style="font-size: 10pt; color: #666;">
            This security assessment report is provided "as is" without any warranty.
            The findings represent the state of the application at the time of testing.
            This is not a guarantee of security. Regular testing and continuous
            monitoring are recommended.
        </p>
        """


# Singleton
_generator: PDFReportGenerator | None = None


def get_pdf_generator(**kwargs) -> PDFReportGenerator:
    """Get singleton PDF generator"""
    global _generator
    if _generator is None:
        _generator = PDFReportGenerator(**kwargs)
    return _generator
