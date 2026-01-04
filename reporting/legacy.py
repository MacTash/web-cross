"""
Legacy Reporting Classes
Compatibility layer for the original reporting.py module.
"""

from typing import List, Dict, Any
import json
from datetime import datetime


class RiskCalculator:
    """Calculate risk scores for vulnerabilities"""
    
    BASE_SCORES = {
        # SQL Injection
        "ERROR_BASED": 9.0,
        "BOOLEAN_BLIND": 8.5,
        "TIME_BLIND": 8.0,
        "UNION_BASED": 9.0,
        "SQL_INJECTION": 9.0,
        
        # XSS
        "REFLECTED_XSS": 6.0,
        "STORED_XSS": 8.0,
        "DOM_XSS": 7.0,
        "XSS": 6.5,
        
        # Command Injection
        "COMMAND_INJECTION": 9.5,
        "CMDI": 9.5,
        
        # Path Traversal
        "PATH_TRAVERSAL": 7.5,
        "LFI": 7.5,
        
        # SSRF
        "SSRF": 8.0,
        
        # XXE
        "XXE": 8.0,
        
        # CSRF
        "CSRF": 6.0,
        
        # Headers
        "MISSING_SECURITY_HEADER": 3.0,
        "INSECURE_HEADER": 4.0,
        "SECURITY_HEADER": 3.5,
        
        # CORS
        "CORS_MISCONFIGURATION": 5.0,
        "CORS": 5.0,
        
        # JWT
        "JWT_NONE_ALGORITHM": 9.0,
        "JWT_WEAK_SECRET": 7.0,
        "JWT": 7.0,
        
        # Access Control
        "IDOR": 7.0,
        "BROKEN_ACCESS_CONTROL": 7.5,
        
        # Open Redirect
        "OPEN_REDIRECT": 4.5,
        
        # Deserialization
        "INSECURE_DESERIALIZATION": 9.0,
        
        # Rate Limiting
        "MISSING_RATE_LIMITING": 4.0,
        
        # WebSocket
        "WEBSOCKET_VULNERABILITY": 6.0,
        
        # Subdomain
        "SUBDOMAIN_TAKEOVER": 8.0,
        
        # Tech
        "GIT_EXPOSED": 8.0,
        "DIRECTORY_LISTING": 4.0,
        
        # AI
        "AI_RISK_ASSESSMENT": 0.0,
    }
    
    CONFIDENCE_MODIFIERS = {
        "HIGH": 1.0,
        "MEDIUM": 0.8,
        "LOW": 0.5,
    }
    
    @classmethod
    def calculate_risk_score(cls, finding: Dict) -> float:
        """Calculate risk score for a single finding"""
        vuln_type = finding.get("type", "").upper().replace("-", "_")
        
        # Get base score
        base_score = cls.BASE_SCORES.get(vuln_type, 5.0)
        
        # Try subtype if main type not found
        if base_score == 5.0 and "subtype" in finding:
            subtype = finding["subtype"].upper().replace("-", "_")
            base_score = cls.BASE_SCORES.get(subtype, 5.0)
        
        # Apply confidence modifier
        confidence = finding.get("confidence", "MEDIUM").upper()
        modifier = cls.CONFIDENCE_MODIFIERS.get(confidence, 0.8)
        
        return round(base_score * modifier, 1)
    
    @classmethod
    def get_severity_label(cls, score: float) -> str:
        """Get severity label from score"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    @classmethod
    def get_severity_color(cls, score: float) -> str:
        """Get color for severity"""
        if score >= 9.0:
            return "red"
        elif score >= 7.0:
            return "orange"
        elif score >= 4.0:
            return "yellow"
        else:
            return "green"
    
    @classmethod
    def calculate_overall_score(cls, findings: List[Dict]) -> Dict:
        """Calculate overall risk score for all findings"""
        if not findings:
            return {
                "score": 0,
                "severity": "None",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }
        
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        scores = []
        
        for finding in findings:
            score = finding.get("risk_score")
            if score is None:
                score = cls.calculate_risk_score(finding)
                finding["risk_score"] = score
            
            scores.append(score)
            severity = cls.get_severity_label(score).lower()
            if severity in counts:
                counts[severity] += 1
        
        # Overall score: weighted average with emphasis on critical
        if counts["critical"] > 0:
            overall = 10.0
        elif counts["high"] > 0:
            overall = 8.0 + (counts["high"] * 0.2)
        elif counts["medium"] > 0:
            overall = 5.0 + (counts["medium"] * 0.3)
        else:
            overall = sum(scores) / len(scores) if scores else 0
        
        return {
            "score": round(min(overall, 10.0), 1),
            "severity": cls.get_severity_label(overall),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
        }


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
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
                   background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
            h1 {{ color: #00d4ff; margin-bottom: 20px; }}
            h2 {{ color: #00d4ff; margin: 30px 0 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
            .summary {{ background: #1a1a1a; padding: 25px; border-radius: 10px; margin: 20px 0; }}
            .stat {{ display: inline-block; margin: 0 30px 0 0; }}
            .stat-value {{ font-size: 36px; font-weight: bold; }}
            .stat-label {{ color: #888; font-size: 14px; }}
            .critical {{ color: #ff4757; }}
            .high {{ color: #ffa502; }}
            .medium {{ color: #ffdd59; }}
            .low {{ color: #7bed9f; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
            th {{ background: #1a1a1a; color: #00d4ff; }}
            tr:hover {{ background: #1a1a1a; }}
            .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; }}
            .badge-critical {{ background: #ff4757; color: white; }}
            .badge-high {{ background: #ffa502; color: black; }}
            .badge-medium {{ background: #ffdd59; color: black; }}
            .badge-low {{ background: #7bed9f; color: black; }}
            footer {{ text-align: center; padding: 30px; color: #666; border-top: 1px solid #333; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔒 Web-Cross Security Report</h1>
                <p style="color:#888">Target: {target} | Generated: {date}</p>
            </header>
            
            <div class="summary">
                <div class="stat">
                    <div class="stat-value">{total_findings}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value critical">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value high">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-value medium">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-value low">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            
            <h2>Vulnerability Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>URL</th>
                        <th>Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
            
            <footer>
                <p>Generated by Web-Cross Vulnerability Scanner v3.0</p>
                <p>Scan Duration: {duration}</p>
            </footer>
        </div>
    </body>
    </html>
    """
    
    def __init__(self, target: str, findings: List[Dict], duration: str = "N/A"):
        self.target = target
        self.findings = findings
        self.duration = duration
        self.risk = RiskCalculator.calculate_overall_score(findings)
    
    def generate_html(self, output_path: str) -> str:
        """Generate HTML report"""
        rows = ""
        for f in self.findings:
            score = f.get("risk_score", 5)
            severity = RiskCalculator.get_severity_label(score)
            badge_class = f"badge-{severity.lower()}"
            
            evidence = str(f.get("evidence", "N/A"))[:100]
            url = str(f.get("url", "N/A"))[:60]
            
            rows += f"""
            <tr>
                <td>{f.get('type', 'Unknown')}</td>
                <td><span class="badge {badge_class}">{severity}</span></td>
                <td>{url}</td>
                <td>{evidence}</td>
            </tr>
            """
        
        html = self.HTML_TEMPLATE.format(
            target=self.target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            total_findings=len(self.findings),
            critical=self.risk["critical_count"],
            high=self.risk["high_count"],
            medium=self.risk["medium_count"],
            low=self.risk["low_count"],
            findings_rows=rows,
            duration=self.duration,
        )
        
        with open(output_path, "w") as f:
            f.write(html)
        
        return output_path
    
    def generate_json(self, output_path: str) -> str:
        """Generate JSON report"""
        report = {
            "target": self.target,
            "generated": datetime.now().isoformat(),
            "duration": self.duration,
            "risk_summary": self.risk,
            "findings": self.findings,
        }
        
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_path
    
    def generate_text(self, output_path: str) -> str:
        """Generate text report"""
        lines = [
            "=" * 60,
            "WEB-CROSS SECURITY REPORT",
            "=" * 60,
            f"Target: {self.target}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"Duration: {self.duration}",
            "",
            "SUMMARY",
            "-" * 40,
            f"Total Findings: {len(self.findings)}",
            f"Critical: {self.risk['critical_count']}",
            f"High: {self.risk['high_count']}",
            f"Medium: {self.risk['medium_count']}",
            f"Low: {self.risk['low_count']}",
            "",
            "FINDINGS",
            "-" * 40,
        ]
        
        for i, f in enumerate(self.findings, 1):
            score = f.get("risk_score", 5)
            severity = RiskCalculator.get_severity_label(score)
            lines.append(f"\n{i}. [{severity}] {f.get('type', 'Unknown')}")
            lines.append(f"   URL: {f.get('url', 'N/A')}")
            lines.append(f"   Evidence: {str(f.get('evidence', 'N/A'))[:80]}")
        
        lines.append("\n" + "=" * 60)
        
        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        
        return output_path
