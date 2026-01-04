"""
HTML Report Generator
Creates modern, interactive HTML security reports.
"""

import html as html_escape_module
from datetime import datetime
from pathlib import Path
from typing import Any

from .compliance import get_compliance_mapper


class HTMLReportGenerator:
    """
    Generates modern, interactive HTML security reports.

    Features:
    - Dark/light mode toggle
    - Interactive filtering
    - Collapsible findings
    - Charts and visualizations
    - Export options
    """

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="en" data-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Report - {target}</title>
        <style>
            :root {{
                --bg-primary: #1a1a2e;
                --bg-secondary: #16213e;
                --bg-card: #0f3460;
                --text-primary: #eee;
                --text-secondary: #aaa;
                --accent: #e94560;
                --success: #00d26a;
                --warning: #ffd200;
                --danger: #ff4757;
                --info: #3742fa;
            }}

            [data-theme="light"] {{
                --bg-primary: #f8f9fa;
                --bg-secondary: #ffffff;
                --bg-card: #ffffff;
                --text-primary: #212529;
                --text-secondary: #6c757d;
            }}

            * {{
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }}

            body {{
                font-family: 'Segoe UI', system-ui, sans-serif;
                background: var(--bg-primary);
                color: var(--text-primary);
                line-height: 1.6;
            }}

            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }}

            header {{
                background: var(--bg-secondary);
                padding: 30px;
                border-radius: 12px;
                margin-bottom: 30px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            .logo {{
                font-size: 28px;
                font-weight: bold;
            }}

            .header-info {{
                text-align: right;
                color: var(--text-secondary);
            }}

            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}

            .stat-card {{
                background: var(--bg-card);
                padding: 25px;
                border-radius: 12px;
                text-align: center;
                border-left: 4px solid var(--accent);
            }}

            .stat-card.critical {{ border-color: #dc3545; }}
            .stat-card.high {{ border-color: #fd7e14; }}
            .stat-card.medium {{ border-color: #ffc107; }}
            .stat-card.low {{ border-color: #28a745; }}

            .stat-value {{
                font-size: 36px;
                font-weight: bold;
                margin-bottom: 5px;
            }}

            .stat-label {{
                color: var(--text-secondary);
                font-size: 14px;
            }}

            .section {{
                background: var(--bg-secondary);
                padding: 25px;
                border-radius: 12px;
                margin-bottom: 20px;
            }}

            .section-title {{
                font-size: 20px;
                margin-bottom: 20px;
                display: flex;
                align-items: center;
                gap: 10px;
            }}

            .filter-bar {{
                display: flex;
                gap: 15px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }}

            .filter-btn {{
                padding: 8px 16px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                background: var(--bg-card);
                color: var(--text-primary);
                transition: all 0.3s;
            }}

            .filter-btn:hover, .filter-btn.active {{
                background: var(--accent);
            }}

            .finding {{
                background: var(--bg-card);
                border-radius: 8px;
                margin-bottom: 15px;
                overflow: hidden;
            }}

            .finding-header {{
                padding: 15px 20px;
                cursor: pointer;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            .finding-header:hover {{
                background: rgba(255,255,255,0.05);
            }}

            .finding-title {{
                display: flex;
                align-items: center;
                gap: 15px;
            }}

            .finding-body {{
                padding: 0 20px 20px;
                display: none;
                border-top: 1px solid rgba(255,255,255,0.1);
            }}

            .finding.expanded .finding-body {{
                display: block;
            }}

            .severity-badge {{
                padding: 4px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
            }}

            .severity-critical {{ background: #dc3545; }}
            .severity-high {{ background: #fd7e14; }}
            .severity-medium {{ background: #ffc107; color: #333; }}
            .severity-low {{ background: #28a745; }}
            .severity-info {{ background: #17a2b8; }}

            .finding-detail {{
                margin: 15px 0;
            }}

            .finding-detail-label {{
                font-weight: bold;
                color: var(--text-secondary);
                margin-bottom: 5px;
            }}

            .code-block {{
                background: #0d1117;
                padding: 15px;
                border-radius: 6px;
                font-family: 'Fira Code', monospace;
                font-size: 13px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-all;
            }}

            .compliance-tags {{
                display: flex;
                gap: 8px;
                flex-wrap: wrap;
                margin-top: 10px;
            }}

            .compliance-tag {{
                background: rgba(255,255,255,0.1);
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
            }}

            .theme-toggle {{
                padding: 10px 20px;
                background: var(--bg-card);
                border: none;
                border-radius: 6px;
                color: var(--text-primary);
                cursor: pointer;
            }}

            .chart-container {{
                height: 300px;
                margin: 20px 0;
            }}

            @media (max-width: 768px) {{
                .stats-grid {{
                    grid-template-columns: repeat(2, 1fr);
                }}
                header {{
                    flex-direction: column;
                    text-align: center;
                }}
                .header-info {{
                    text-align: center;
                    margin-top: 15px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div>
                    <div class="logo">🔒 Web-Cross Security Report</div>
                    <div style="color: var(--text-secondary); margin-top: 5px;">
                        Target: {target}
                    </div>
                </div>
                <div class="header-info">
                    <div>Generated: {date}</div>
                    <button class="theme-toggle" onclick="toggleTheme()">🌙 Toggle Theme</button>
                </div>
            </header>

            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="stat-value" style="color: #dc3545;">{critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-value" style="color: #fd7e14;">{high_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-value" style="color: #ffc107;">{medium_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-value" style="color: #28a745;">{low_count}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>

            <div class="section">
                <div class="section-title">📋 Findings ({total_count})</div>

                <div class="filter-bar">
                    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                    <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
                    <button class="filter-btn" onclick="filterFindings('high')">High</button>
                    <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
                    <button class="filter-btn" onclick="filterFindings('low')">Low</button>
                </div>

                <div id="findings-container">
                    {findings_html}
                </div>
            </div>

            <div class="section">
                <div class="section-title">📊 Scan Information</div>
                <p><strong>Scan Mode:</strong> {scan_mode}</p>
                <p><strong>AI Analysis:</strong> {ai_enabled}</p>
                <p><strong>Scanner Version:</strong> Web-Cross v3.0</p>
            </div>
        </div>

        <script>
            function toggleTheme() {{
                const html = document.documentElement;
                const current = html.getAttribute('data-theme');
                html.setAttribute('data-theme', current === 'dark' ? 'light' : 'dark');
            }}

            function filterFindings(severity) {{
                const findings = document.querySelectorAll('.finding');
                const buttons = document.querySelectorAll('.filter-btn');

                buttons.forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');

                findings.forEach(finding => {{
                    if (severity === 'all' || finding.dataset.severity === severity) {{
                        finding.style.display = 'block';
                    }} else {{
                        finding.style.display = 'none';
                    }}
                }});
            }}

            document.querySelectorAll('.finding-header').forEach(header => {{
                header.addEventListener('click', () => {{
                    header.parentElement.classList.toggle('expanded');
                }});
            }});
        </script>
    </body>
    </html>
    """

    def __init__(
        self,
        output_dir: Path = None,
        include_compliance: bool = True,
    ):
        self.output_dir = output_dir or Path.cwd() / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.include_compliance = include_compliance
        self.compliance_mapper = get_compliance_mapper()

    def generate(
        self,
        findings: list[dict[str, Any]],
        target: str,
        scan_info: dict[str, Any] = None,
        output_path: Path = None,
    ) -> Path:
        """Generate HTML report"""
        scan_info = scan_info or {}

        # Enrich with compliance
        if self.include_compliance:
            findings = self.compliance_mapper.enrich_findings(findings)

        # Count severities
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity_label", f.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Generate findings HTML
        findings_html = self._generate_findings_html(findings)

        # Fill template
        html_content = self.HTML_TEMPLATE.format(
            target=html_escape_module.escape(target),
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            total_count=len(findings),
            findings_html=findings_html,
            scan_mode=scan_info.get("mode", "Full"),
            ai_enabled="Enabled" if scan_info.get("ai_enabled") else "Disabled",
        )

        # Write file
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"security_report_{timestamp}.html"

        with open(output_path, "w") as f:
            f.write(html_content)

        return output_path

    def _generate_findings_html(self, findings: list[dict]) -> str:
        """Generate HTML for findings list"""
        html_parts = []

        for i, finding in enumerate(findings, 1):
            vuln_type = html_escape_module.escape(finding.get("type", "Unknown"))
            severity = finding.get("severity_label", finding.get("severity", "MEDIUM")).upper()
            url = html_escape_module.escape(finding.get("url", "N/A"))
            description = html_escape_module.escape(finding.get("description", "No description"))
            evidence = html_escape_module.escape(str(finding.get("evidence", "N/A"))[:500])
            remediation = html_escape_module.escape(finding.get("remediation", "Consult security practices"))

            # Compliance tags
            compliance_html = ""
            if "compliance" in finding:
                comp = finding["compliance"]
                tags = []
                if comp.get("owasp_top_10"):
                    tags.append(f'<span class="compliance-tag">{comp["owasp_top_10"]}</span>')
                if comp.get("cwe_id"):
                    tags.append(f'<span class="compliance-tag">{comp["cwe_id"]}</span>')
                if comp.get("cvss_base"):
                    tags.append(f'<span class="compliance-tag">CVSS: {comp["cvss_base"]}</span>')
                if tags:
                    compliance_html = f'<div class="compliance-tags">{"".join(tags)}</div>'

            html_parts.append(f'''
                <div class="finding" data-severity="{severity.lower()}">
                    <div class="finding-header">
                        <div class="finding-title">
                            <span class="severity-badge severity-{severity.lower()}">{severity}</span>
                            <span>{i}. {vuln_type}</span>
                        </div>
                        <span>▼</span>
                    </div>
                    <div class="finding-body">
                        <div class="finding-detail">
                            <div class="finding-detail-label">URL</div>
                            <div class="code-block">{url}</div>
                        </div>
                        <div class="finding-detail">
                            <div class="finding-detail-label">Description</div>
                            <p>{description}</p>
                        </div>
                        <div class="finding-detail">
                            <div class="finding-detail-label">Evidence</div>
                            <div class="code-block">{evidence}</div>
                        </div>
                        <div class="finding-detail">
                            <div class="finding-detail-label">Remediation</div>
                            <p>{remediation}</p>
                        </div>
                        {compliance_html}
                    </div>
                </div>
            ''')

        return "".join(html_parts)


# Singleton
_html_generator: HTMLReportGenerator | None = None


def get_html_generator(**kwargs) -> HTMLReportGenerator:
    """Get singleton HTML generator"""
    global _html_generator
    if _html_generator is None:
        _html_generator = HTMLReportGenerator(**kwargs)
    return _html_generator
