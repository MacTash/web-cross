"""Report Generator - HTML, JSON, and text reports"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Template

from .risk_calculator import RiskCalculator
from .remediation import RemediationEngine


class ReportGenerator:
    """Generate professional security reports"""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web-Cross Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f23; color: #e0e0e0; line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 40px; border-radius: 12px; margin-bottom: 30px;
            border: 1px solid #333;
        }
        h1 { color: #00d4ff; font-size: 2.5em; margin-bottom: 10px; }
        .subtitle { color: #888; font-size: 1.1em; }
        .meta-info { margin-top: 20px; display: flex; gap: 30px; flex-wrap: wrap; }
        .meta-item { 
            background: rgba(255,255,255,0.05); padding: 15px 25px;
            border-radius: 8px; border-left: 3px solid #00d4ff;
        }
        .meta-label { color: #888; font-size: 0.9em; }
        .meta-value { font-size: 1.4em; font-weight: bold; color: #fff; }
        
        .summary-card {
            background: #1a1a2e; border-radius: 12px; padding: 30px;
            margin-bottom: 30px; border: 1px solid #333;
        }
        .summary-title { color: #00d4ff; font-size: 1.5em; margin-bottom: 20px; }
        .risk-gauge {
            display: flex; align-items: center; gap: 20px;
            background: rgba(0,0,0,0.3); padding: 20px; border-radius: 8px;
        }
        .risk-score { 
            font-size: 3em; font-weight: bold;
            width: 100px; height: 100px; display: flex;
            align-items: center; justify-content: center;
            border-radius: 50%; border: 4px solid;
        }
        .risk-critical { border-color: #ff4757; color: #ff4757; }
        .risk-high { border-color: #ff7f50; color: #ff7f50; }
        .risk-medium { border-color: #ffd93d; color: #ffd93d; }
        .risk-low { border-color: #4ade80; color: #4ade80; }
        
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
        .stat-box { 
            background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px;
            text-align: center;
        }
        .stat-count { font-size: 2em; font-weight: bold; }
        .stat-critical { color: #ff4757; }
        .stat-high { color: #ff7f50; }
        .stat-medium { color: #ffd93d; }
        .stat-low { color: #4ade80; }
        
        .section { margin-bottom: 30px; }
        .section-title { 
            color: #00d4ff; font-size: 1.3em; margin-bottom: 15px;
            padding-bottom: 10px; border-bottom: 1px solid #333;
        }
        
        .finding {
            background: #1a1a2e; border-radius: 8px; padding: 20px;
            margin-bottom: 15px; border: 1px solid #333;
            border-left: 4px solid;
        }
        .finding-critical { border-left-color: #ff4757; }
        .finding-high { border-left-color: #ff7f50; }
        .finding-medium { border-left-color: #ffd93d; }
        .finding-low { border-left-color: #4ade80; }
        
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .finding-type { font-weight: bold; color: #fff; }
        .finding-score { 
            padding: 3px 10px; border-radius: 4px; font-size: 0.9em;
            font-weight: bold;
        }
        .bg-critical { background: #ff4757; color: #fff; }
        .bg-high { background: #ff7f50; color: #fff; }
        .bg-medium { background: #ffd93d; color: #000; }
        .bg-low { background: #4ade80; color: #000; }
        
        .finding-details { color: #aaa; font-size: 0.95em; }
        .finding-url { color: #00d4ff; word-break: break-all; }
        .finding-evidence { 
            background: rgba(0,0,0,0.3); padding: 10px; margin-top: 10px;
            border-radius: 4px; font-family: monospace; font-size: 0.9em;
        }
        
        .remediation {
            background: #162236; border-radius: 8px; padding: 20px;
            margin-bottom: 15px; border: 1px solid #1e3a5f;
        }
        .rem-title { color: #4ade80; font-weight: bold; margin-bottom: 10px; }
        .rem-steps { list-style-position: inside; }
        .rem-steps li { margin: 8px 0; }
        
        .code-block {
            background: #0a0a15; padding: 15px; border-radius: 4px;
            margin: 10px 0; overflow-x: auto;
        }
        .code-block code { color: #4ade80; font-family: 'Fira Code', monospace; }
        .code-vulnerable { border-left: 3px solid #ff4757; }
        .code-secure { border-left: 3px solid #4ade80; }
        
        footer {
            text-align: center; padding: 30px; color: #666;
            border-top: 1px solid #333; margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Web-Cross Security Report</h1>
            <p class="subtitle">Comprehensive Vulnerability Assessment</p>
            <div class="meta-info">
                <div class="meta-item">
                    <div class="meta-label">Target URL</div>
                    <div class="meta-value">{{ target_url }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Date</div>
                    <div class="meta-value">{{ scan_date }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Duration</div>
                    <div class="meta-value">{{ scan_duration }}</div>
                </div>
            </div>
        </header>
        
        <div class="summary-card">
            <h2 class="summary-title">📊 Executive Summary</h2>
            <div class="risk-gauge">
                <div class="risk-score risk-{{ overall_risk.severity|lower }}">
                    {{ overall_risk.score }}
                </div>
                <div>
                    <div style="font-size: 1.3em; font-weight: bold;">Overall Risk: {{ overall_risk.severity }}</div>
                    <div style="color: #888;">{{ overall_risk.total_findings }} vulnerabilities detected</div>
                </div>
            </div>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-count stat-critical">{{ overall_risk.critical_count }}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-box">
                    <div class="stat-count stat-high">{{ overall_risk.high_count }}</div>
                    <div>High</div>
                </div>
                <div class="stat-box">
                    <div class="stat-count stat-medium">{{ overall_risk.medium_count }}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-box">
                    <div class="stat-count stat-low">{{ overall_risk.low_count }}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">🔍 Vulnerability Findings</h2>
            {% for finding in findings %}
            <div class="finding finding-{{ finding.severity_label|lower }}">
                <div class="finding-header">
                    <span class="finding-type">{{ finding.type }}</span>
                    <span class="finding-score bg-{{ finding.severity_label|lower }}">
                        {{ finding.risk_score }} - {{ finding.severity_label }}
                    </span>
                </div>
                <div class="finding-details">
                    <p><strong>URL:</strong> <span class="finding-url">{{ finding.url }}</span></p>
                    {% if finding.parameter %}
                    <p><strong>Parameter:</strong> {{ finding.parameter }}</p>
                    {% endif %}
                    <div class="finding-evidence">{{ finding.evidence }}</div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2 class="section-title">🛡️ Remediation Strategies</h2>
            {% for rem in remediations %}
            <div class="remediation">
                <div class="rem-title">{{ rem.title }}</div>
                <p style="color: #aaa; margin-bottom: 10px;">{{ rem.description }}</p>
                <p><strong>Impact:</strong> {{ rem.impact }}</p>
                <h4 style="margin: 15px 0 10px;">Recommended Actions:</h4>
                <ul class="rem-steps">
                    {% for step in rem.remediation %}
                    <li>{{ step }}</li>
                    {% endfor %}
                </ul>
                {% if rem.code_example %}
                <h4 style="margin: 15px 0 10px;">Code Examples:</h4>
                <div class="code-block code-vulnerable">
                    <div style="color: #ff4757; font-size: 0.8em; margin-bottom: 5px;">❌ Vulnerable:</div>
                    <code>{{ rem.code_example.vulnerable }}</code>
                </div>
                <div class="code-block code-secure">
                    <div style="color: #4ade80; font-size: 0.8em; margin-bottom: 5px;">✅ Secure:</div>
                    <code>{{ rem.code_example.secure }}</code>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <footer>
            <p>Generated by Web-Cross Security Scanner | MacTash</p>
            <p style="font-size: 0.9em;">{{ scan_date }}</p>
        </footer>
    </div>
</body>
</html>
"""
    
    def __init__(self, target_url: str, findings: List[Dict], scan_duration: str = "N/A"):
        self.target_url = target_url
        self.findings = findings
        self.scan_duration = scan_duration
        self.scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate risk scores
        self.overall_risk = RiskCalculator.calculate_overall_score(findings)
        
        # Get remediations
        self.remediations = RemediationEngine.get_all_remediations(findings)
    
    def generate_html(self, output_path: str = None) -> str:
        """Generate HTML report"""
        template = Template(self.HTML_TEMPLATE)
        
        html_content = template.render(
            target_url=self.target_url,
            scan_date=self.scan_date,
            scan_duration=self.scan_duration,
            overall_risk=self.overall_risk,
            findings=self.findings,
            remediations=self.remediations
        )
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        return html_content
    
    def generate_json(self, output_path: str = None) -> Dict:
        """Generate JSON report"""
        report = {
            "metadata": {
                "target_url": self.target_url,
                "scan_date": self.scan_date,
                "scan_duration": self.scan_duration,
                "generator": "Web-Cross Security Scanner"
            },
            "summary": self.overall_risk,
            "findings": self.findings,
            "remediations": [
                {
                    "title": r["title"],
                    "description": r["description"],
                    "impact": r["impact"],
                    "steps": r["remediation"],
                    "references": r.get("references", [])
                }
                for r in self.remediations
            ]
        }
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def generate_text(self, output_path: str = None) -> str:
        """Generate text report"""
        lines = []
        lines.append("=" * 70)
        lines.append("WEB-CROSS SECURITY REPORT")
        lines.append("=" * 70)
        lines.append(f"\nTarget: {self.target_url}")
        lines.append(f"Date: {self.scan_date}")
        lines.append(f"Duration: {self.scan_duration}")
        
        lines.append("\n" + "-" * 70)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Overall Risk Score: {self.overall_risk['score']} ({self.overall_risk['severity']})")
        lines.append(f"Total Findings: {self.overall_risk['total_findings']}")
        lines.append(f"  Critical: {self.overall_risk['critical_count']}")
        lines.append(f"  High: {self.overall_risk['high_count']}")
        lines.append(f"  Medium: {self.overall_risk['medium_count']}")
        lines.append(f"  Low: {self.overall_risk['low_count']}")
        
        lines.append("\n" + "-" * 70)
        lines.append("FINDINGS")
        lines.append("-" * 70)
        
        for i, finding in enumerate(self.findings, 1):
            lines.append(f"\n[{i}] {finding['type']}")
            lines.append(f"    Risk: {finding.get('risk_score', 'N/A')} ({finding.get('severity_label', 'N/A')})")
            lines.append(f"    URL: {finding.get('url', 'N/A')}")
            if finding.get('parameter'):
                lines.append(f"    Parameter: {finding['parameter']}")
            lines.append(f"    Evidence: {finding.get('evidence', 'N/A')}")
        
        lines.append("\n" + "-" * 70)
        lines.append("REMEDIATIONS")
        lines.append("-" * 70)
        
        for rem in self.remediations:
            lines.append(f"\n>> {rem['title']}")
            lines.append(f"   {rem['description']}")
            lines.append("\n   Steps:")
            for step in rem['remediation']:
                lines.append(f"   - {step}")
        
        lines.append("\n" + "=" * 70)
        lines.append("Generated by Web-Cross Security Scanner | MacTash")
        lines.append("=" * 70)
        
        content = "\n".join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        return content
