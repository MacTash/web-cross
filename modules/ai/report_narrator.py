"""
Natural Language Report Narrator
Generates human-readable reports from scan findings using AI.
"""

import json
from dataclasses import dataclass
from typing import Any

from .providers.groq_provider import get_groq_provider
from .providers.ollama_provider import get_ollama_provider


@dataclass
class NarrativeReport:
    """A narrative security report"""
    executive_summary: str
    key_findings: list[str]
    risk_assessment: str
    recommendations: list[str]
    technical_details: str
    conclusion: str


class ReportNarrator:
    """
    Generates natural language security reports from vulnerability findings.

    Creates:
    - Executive summaries for non-technical stakeholders
    - Technical narratives for security teams
    - Prioritized remediation guidance
    """

    EXECUTIVE_SUMMARY_PROMPT = """You are a senior security consultant writing an executive summary.

Write a clear, non-technical summary that:
1. States the overall security posture
2. Highlights the most critical risks in business terms
3. Provides actionable recommendations
4. Uses no technical jargon

Keep it under 200 words. Be direct and professional."""

    TECHNICAL_REPORT_PROMPT = """You are a penetration tester writing a technical report.

For each finding:
1. Explain the vulnerability clearly
2. Describe the potential impact
3. Provide exploitation steps (conceptually)
4. Give specific remediation guidance

Use proper security terminology. Be thorough but concise."""

    def __init__(
        self,
        provider: str = "auto",
        groq_api_key: str = None,
        ollama_host: str = None,
    ):
        self.provider_preference = provider

        self.groq = get_groq_provider(api_key=groq_api_key)
        self.ollama = get_ollama_provider(host=ollama_host)

        self._active_provider = None
        if provider == "groq" and self.groq.is_available():
            self._active_provider = self.groq
        elif provider == "ollama" and self.ollama.is_available():
            self._active_provider = self.ollama
        elif provider == "auto":
            if self.groq.is_available():
                self._active_provider = self.groq
            elif self.ollama.is_available():
                self._active_provider = self.ollama

    def generate_executive_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        scan_duration: str = "N/A",
    ) -> str:
        """
        Generate an executive summary for non-technical stakeholders.

        Args:
            findings: List of vulnerability findings
            target: Target URL/application
            scan_duration: How long the scan took

        Returns:
            Executive summary text
        """
        if not findings:
            return self._empty_findings_summary(target)

        # Prepare summary statistics
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity_label", f.get("severity", "MEDIUM")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        if not self._active_provider:
            return self._fallback_executive_summary(findings, target, severity_counts)

        findings_brief = [
            {
                "type": f.get("type"),
                "severity": f.get("severity_label", f.get("severity")),
                "impact": f.get("description", "")[:100],
            }
            for f in findings[:10]
        ]

        prompt = f"""Write an executive summary for this security assessment.

Target: {target}
Scan Duration: {scan_duration}
Total Findings: {len(findings)}
Critical: {severity_counts['CRITICAL']}, High: {severity_counts['HIGH']}, Medium: {severity_counts['MEDIUM']}, Low: {severity_counts['LOW']}

Key Findings:
{json.dumps(findings_brief, indent=2)}

Write a professional executive summary."""

        result = self._active_provider.generate(
            prompt=prompt,
            system_prompt=self.EXECUTIVE_SUMMARY_PROMPT,
            temperature=0.4,
            max_tokens=500,
        )

        if result.success:
            return result.text

        return self._fallback_executive_summary(findings, target, severity_counts)

    def generate_technical_narrative(
        self,
        findings: list[dict[str, Any]],
        target: str,
    ) -> str:
        """
        Generate a technical narrative of findings.

        Args:
            findings: List of vulnerability findings
            target: Target URL/application

        Returns:
            Technical narrative text
        """
        if not findings:
            return "No vulnerabilities were discovered during this assessment."

        if not self._active_provider:
            return self._fallback_technical_narrative(findings)

        findings_data = json.dumps(findings[:15], indent=2)

        prompt = f"""Write a technical security assessment narrative.

Target: {target}

Findings:
{findings_data}

Write a comprehensive technical description of each vulnerability."""

        result = self._active_provider.generate(
            prompt=prompt,
            system_prompt=self.TECHNICAL_REPORT_PROMPT,
            temperature=0.3,
            max_tokens=2000,
        )

        if result.success:
            return result.text

        return self._fallback_technical_narrative(findings)

    def generate_full_report(
        self,
        findings: list[dict[str, Any]],
        target: str,
        scan_info: dict[str, Any] = None,
    ) -> NarrativeReport:
        """
        Generate a complete narrative report.

        Args:
            findings: List of vulnerability findings
            target: Target URL/application
            scan_info: Additional scan information

        Returns:
            Complete NarrativeReport
        """
        scan_info = scan_info or {}

        executive_summary = self.generate_executive_summary(
            findings,
            target,
            scan_info.get("duration", "N/A"),
        )

        # Extract key findings (top severity)
        sorted_findings = sorted(
            findings,
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                x.get("severity_label", x.get("severity", "MEDIUM")).upper(), 2
            ),
        )

        key_findings = [
            f"{f.get('type')}: {f.get('description', 'No description')[:100]}"
            for f in sorted_findings[:5]
        ]

        # Risk assessment
        max_severity = "LOW"
        for f in findings:
            sev = f.get("severity_label", f.get("severity", "MEDIUM")).upper()
            if sev == "CRITICAL":
                max_severity = "CRITICAL"
                break
            elif sev == "HIGH" and max_severity not in ["CRITICAL"]:
                max_severity = "HIGH"
            elif sev == "MEDIUM" and max_severity == "LOW":
                max_severity = "MEDIUM"

        risk_assessment = f"Overall risk level: {max_severity}. "
        if max_severity == "CRITICAL":
            risk_assessment += "Immediate action required. Critical vulnerabilities present that could lead to complete system compromise."
        elif max_severity == "HIGH":
            risk_assessment += "High priority remediation needed. Significant vulnerabilities that could result in data breach or system compromise."
        elif max_severity == "MEDIUM":
            risk_assessment += "Moderate risk. Issues should be addressed in the next development cycle."
        else:
            risk_assessment += "Low risk. Minor issues identified that should be addressed as part of regular maintenance."

        # Recommendations
        recommendations = []
        vuln_types = {f.get("type", "") for f in findings}

        if any("SQL" in t for t in vuln_types):
            recommendations.append("Implement parameterized queries and prepared statements for all database operations.")
        if any("XSS" in t for t in vuln_types):
            recommendations.append("Apply output encoding and implement Content Security Policy headers.")
        if any("IDOR" in t or "ACCESS" in t for t in vuln_types):
            recommendations.append("Implement proper authorization checks on all resource access.")
        if any("CSRF" in t for t in vuln_types):
            recommendations.append("Implement CSRF tokens and validate Origin headers.")

        if not recommendations:
            recommendations.append("Continue regular security assessments and maintain security best practices.")

        technical_details = self.generate_technical_narrative(findings, target)

        conclusion = f"This security assessment of {target} identified {len(findings)} vulnerabilities. "
        conclusion += f"The overall risk level is {max_severity}. "
        conclusion += "Remediation should be prioritized based on severity and exploitability."

        return NarrativeReport(
            executive_summary=executive_summary,
            key_findings=key_findings,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            technical_details=technical_details,
            conclusion=conclusion,
        )

    def _empty_findings_summary(self, target: str) -> str:
        """Summary for when no findings are present"""
        return (
            f"Security Assessment Summary: {target}\n\n"
            "The automated security scan completed successfully with no vulnerabilities detected. "
            "This indicates a strong security posture for the tested scope. "
            "However, this should not be considered a guarantee of security. "
            "Regular assessments and manual penetration testing are recommended."
        )

    def _fallback_executive_summary(
        self,
        findings: list[dict],
        target: str,
        severity_counts: dict[str, int],
    ) -> str:
        """Fallback summary generation"""
        total = len(findings)
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)

        summary = f"Security Assessment: {target}\n\n"
        summary += f"Total vulnerabilities identified: {total}\n"
        summary += f"- Critical: {critical}\n"
        summary += f"- High: {high}\n"
        summary += f"- Medium: {severity_counts.get('MEDIUM', 0)}\n"
        summary += f"- Low: {severity_counts.get('LOW', 0)}\n\n"

        if critical > 0:
            summary += "IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected that could lead to complete system compromise.\n"
        elif high > 0:
            summary += "HIGH PRIORITY: Significant vulnerabilities require prompt remediation.\n"
        else:
            summary += "MODERATE RISK: Issues identified should be addressed in upcoming maintenance.\n"

        return summary

    def _fallback_technical_narrative(self, findings: list[dict]) -> str:
        """Fallback technical narrative"""
        narrative = "## Technical Findings\n\n"

        for i, finding in enumerate(findings[:10], 1):
            vuln_type = finding.get("type", "Unknown")
            severity = finding.get("severity_label", finding.get("severity", "MEDIUM"))
            url = finding.get("url", "N/A")
            description = finding.get("description", "No description available.")
            remediation = finding.get("remediation", "Consult security best practices.")

            narrative += f"### {i}. {vuln_type} ({severity})\n\n"
            narrative += f"**Location:** {url}\n\n"
            narrative += f"**Description:** {description}\n\n"
            narrative += f"**Remediation:** {remediation}\n\n"
            narrative += "---\n\n"

        if len(findings) > 10:
            narrative += f"\n*...and {len(findings) - 10} additional findings.*\n"

        return narrative


# Singleton
_narrator: ReportNarrator | None = None


def get_report_narrator(**kwargs) -> ReportNarrator:
    """Get singleton report narrator"""
    global _narrator
    if _narrator is None:
        _narrator = ReportNarrator(**kwargs)
    return _narrator
