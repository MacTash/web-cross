"""
Compliance Mapper
Maps vulnerabilities to compliance frameworks (OWASP, CWE, PCI-DSS, etc.).
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ComplianceMapping:
    """Mapping of a vulnerability to compliance frameworks"""
    vuln_type: str
    owasp_top_10: str = ""
    owasp_category: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    cvss_base: float = 0.0
    pci_dss: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    gdpr: list[str] = field(default_factory=list)


class ComplianceMapper:
    """
    Maps vulnerability findings to compliance frameworks.

    Supports:
    - OWASP Top 10 (2021)
    - CWE
    - CVSS scoring guidance
    - PCI-DSS
    - NIST
    - GDPR
    """

    # OWASP Top 10 2021 mappings
    OWASP_2021 = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery (SSRF)",
    }

    # Vulnerability type to compliance mapping
    VULN_MAPPINGS: dict[str, ComplianceMapping] = {
        # Injection vulnerabilities
        "SQL_INJECTION": ComplianceMapping(
            vuln_type="SQL_INJECTION",
            owasp_top_10="A03:2021",
            owasp_category="Injection",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            cvss_base=9.8,
            pci_dss=["6.5.1", "6.5.2"],
            nist=["SI-10", "SI-11"],
            gdpr=["Article 32"],
        ),
        "XSS": ComplianceMapping(
            vuln_type="XSS",
            owasp_top_10="A03:2021",
            owasp_category="Injection",
            cwe_id="CWE-79",
            cwe_name="Cross-site Scripting",
            cvss_base=6.1,
            pci_dss=["6.5.7"],
            nist=["SI-10"],
            gdpr=["Article 32"],
        ),
        "COMMAND_INJECTION": ComplianceMapping(
            vuln_type="COMMAND_INJECTION",
            owasp_top_10="A03:2021",
            owasp_category="Injection",
            cwe_id="CWE-78",
            cwe_name="OS Command Injection",
            cvss_base=9.8,
            pci_dss=["6.5.1"],
            nist=["SI-10", "SI-11"],
            gdpr=["Article 32"],
        ),
        "SSTI": ComplianceMapping(
            vuln_type="SSTI",
            owasp_top_10="A03:2021",
            owasp_category="Injection",
            cwe_id="CWE-94",
            cwe_name="Code Injection",
            cvss_base=9.8,
            pci_dss=["6.5.1"],
            nist=["SI-10"],
            gdpr=["Article 32"],
        ),
        "XXE": ComplianceMapping(
            vuln_type="XXE",
            owasp_top_10="A05:2021",
            owasp_category="Security Misconfiguration",
            cwe_id="CWE-611",
            cwe_name="XXE",
            cvss_base=7.5,
            pci_dss=["6.5.1"],
            nist=["SI-10"],
            gdpr=["Article 32"],
        ),

        # Access control
        "IDOR": ComplianceMapping(
            vuln_type="IDOR",
            owasp_top_10="A01:2021",
            owasp_category="Broken Access Control",
            cwe_id="CWE-639",
            cwe_name="Insecure Direct Object Reference",
            cvss_base=6.5,
            pci_dss=["6.5.8", "7.1"],
            nist=["AC-3", "AC-4"],
            gdpr=["Article 25", "Article 32"],
        ),
        "BROKEN_ACCESS_CONTROL": ComplianceMapping(
            vuln_type="BROKEN_ACCESS_CONTROL",
            owasp_top_10="A01:2021",
            owasp_category="Broken Access Control",
            cwe_id="CWE-284",
            cwe_name="Improper Access Control",
            cvss_base=7.5,
            pci_dss=["6.5.8", "7.1", "7.2"],
            nist=["AC-3", "AC-4"],
            gdpr=["Article 25", "Article 32"],
        ),

        # Authentication
        "MISSING_RATE_LIMITING": ComplianceMapping(
            vuln_type="MISSING_RATE_LIMITING",
            owasp_top_10="A07:2021",
            owasp_category="Identification and Authentication Failures",
            cwe_id="CWE-770",
            cwe_name="Allocation of Resources Without Limits",
            cvss_base=5.3,
            pci_dss=["6.5.10"],
            nist=["SC-5", "SI-10"],
            gdpr=["Article 32"],
        ),
        "CSRF": ComplianceMapping(
            vuln_type="CSRF",
            owasp_top_10="A01:2021",
            owasp_category="Broken Access Control",
            cwe_id="CWE-352",
            cwe_name="Cross-Site Request Forgery",
            cvss_base=6.5,
            pci_dss=["6.5.9"],
            nist=["SC-23"],
            gdpr=["Article 32"],
        ),

        # SSRF
        "SSRF": ComplianceMapping(
            vuln_type="SSRF",
            owasp_top_10="A10:2021",
            owasp_category="Server-Side Request Forgery",
            cwe_id="CWE-918",
            cwe_name="SSRF",
            cvss_base=7.5,
            pci_dss=["6.5.1"],
            nist=["SI-10"],
            gdpr=["Article 32"],
        ),

        # Path traversal
        "PATH_TRAVERSAL": ComplianceMapping(
            vuln_type="PATH_TRAVERSAL",
            owasp_top_10="A01:2021",
            owasp_category="Broken Access Control",
            cwe_id="CWE-22",
            cwe_name="Path Traversal",
            cvss_base=7.5,
            pci_dss=["6.5.1"],
            nist=["SI-10", "AC-3"],
            gdpr=["Article 32"],
        ),

        # Deserialization
        "INSECURE_DESERIALIZATION": ComplianceMapping(
            vuln_type="INSECURE_DESERIALIZATION",
            owasp_top_10="A08:2021",
            owasp_category="Software and Data Integrity Failures",
            cwe_id="CWE-502",
            cwe_name="Deserialization of Untrusted Data",
            cvss_base=9.8,
            pci_dss=["6.5.1"],
            nist=["SI-10"],
            gdpr=["Article 32"],
        ),

        # Redirect
        "OPEN_REDIRECT": ComplianceMapping(
            vuln_type="OPEN_REDIRECT",
            owasp_top_10="A01:2021",
            owasp_category="Broken Access Control",
            cwe_id="CWE-601",
            cwe_name="Open Redirect",
            cvss_base=4.7,
            pci_dss=["6.5.1"],
            nist=["SI-10"],
            gdpr=[],
        ),

        # Subdomain takeover
        "SUBDOMAIN_TAKEOVER": ComplianceMapping(
            vuln_type="SUBDOMAIN_TAKEOVER",
            owasp_top_10="A05:2021",
            owasp_category="Security Misconfiguration",
            cwe_id="CWE-284",
            cwe_name="Improper Access Control",
            cvss_base=7.5,
            pci_dss=["2.2"],
            nist=["CM-7"],
            gdpr=["Article 32"],
        ),

        # Headers/Config
        "SECURITY_HEADERS": ComplianceMapping(
            vuln_type="SECURITY_HEADERS",
            owasp_top_10="A05:2021",
            owasp_category="Security Misconfiguration",
            cwe_id="CWE-693",
            cwe_name="Protection Mechanism Failure",
            cvss_base=5.3,
            pci_dss=["6.5.10"],
            nist=["SC-8"],
            gdpr=["Article 32"],
        ),

        # CORS
        "CORS": ComplianceMapping(
            vuln_type="CORS",
            owasp_top_10="A05:2021",
            owasp_category="Security Misconfiguration",
            cwe_id="CWE-942",
            cwe_name="Permissive CORS Policy",
            cvss_base=5.3,
            pci_dss=["6.5.10"],
            nist=["SC-8"],
            gdpr=["Article 32"],
        ),

        # JWT
        "JWT": ComplianceMapping(
            vuln_type="JWT",
            owasp_top_10="A02:2021",
            owasp_category="Cryptographic Failures",
            cwe_id="CWE-347",
            cwe_name="Improper Verification of Cryptographic Signature",
            cvss_base=7.5,
            pci_dss=["4.1", "6.5.3"],
            nist=["SC-12", "SC-13"],
            gdpr=["Article 32"],
        ),

        # WebSocket
        "WEBSOCKET": ComplianceMapping(
            vuln_type="WEBSOCKET",
            owasp_top_10="A01:2021",
            owasp_category="Broken Access Control",
            cwe_id="CWE-1385",
            cwe_name="Missing Origin Validation in WebSocket",
            cvss_base=6.5,
            pci_dss=["6.5.1"],
            nist=["SC-8"],
            gdpr=["Article 32"],
        ),
    }

    def __init__(self):
        pass

    def get_mapping(self, vuln_type: str) -> ComplianceMapping | None:
        """
        Get compliance mapping for a vulnerability type.

        Args:
            vuln_type: Vulnerability type identifier

        Returns:
            ComplianceMapping if found
        """
        # Normalize type
        normalized = vuln_type.upper().replace("-", "_").replace(" ", "_")

        # Direct match
        if normalized in self.VULN_MAPPINGS:
            return self.VULN_MAPPINGS[normalized]

        # Partial match
        for key, mapping in self.VULN_MAPPINGS.items():
            if key in normalized or normalized in key:
                return mapping

        return None

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a finding with compliance information.

        Args:
            finding: Vulnerability finding dictionary

        Returns:
            Finding with added compliance fields
        """
        vuln_type = finding.get("type", "")
        mapping = self.get_mapping(vuln_type)

        if mapping:
            finding["compliance"] = {
                "owasp_top_10": mapping.owasp_top_10,
                "owasp_category": mapping.owasp_category,
                "cwe_id": mapping.cwe_id,
                "cwe_name": mapping.cwe_name,
                "cvss_base": mapping.cvss_base,
                "pci_dss": mapping.pci_dss,
                "nist": mapping.nist,
                "gdpr": mapping.gdpr,
            }

        return finding

    def enrich_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich multiple findings with compliance data"""
        return [self.enrich_finding(f) for f in findings]

    def generate_compliance_summary(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Generate compliance summary from findings.

        Returns summary by each standard/framework.
        """
        summary = {
            "owasp_top_10": {},
            "cwe": {},
            "pci_dss": set(),
            "nist": set(),
            "gdpr": set(),
        }

        for finding in findings:
            vuln_type = finding.get("type", "")
            mapping = self.get_mapping(vuln_type)

            if mapping:
                # OWASP
                owasp = mapping.owasp_top_10
                if owasp:
                    if owasp not in summary["owasp_top_10"]:
                        summary["owasp_top_10"][owasp] = {
                            "category": mapping.owasp_category,
                            "count": 0,
                        }
                    summary["owasp_top_10"][owasp]["count"] += 1

                # CWE
                cwe = mapping.cwe_id
                if cwe:
                    if cwe not in summary["cwe"]:
                        summary["cwe"][cwe] = {"name": mapping.cwe_name, "count": 0}
                    summary["cwe"][cwe]["count"] += 1

                # PCI-DSS
                summary["pci_dss"].update(mapping.pci_dss)

                # NIST
                summary["nist"].update(mapping.nist)

                # GDPR
                summary["gdpr"].update(mapping.gdpr)

        # Convert sets to lists for JSON serialization
        summary["pci_dss"] = sorted(summary["pci_dss"])
        summary["nist"] = sorted(summary["nist"])
        summary["gdpr"] = sorted(summary["gdpr"])

        return summary


# Singleton
_mapper: ComplianceMapper | None = None


def get_compliance_mapper() -> ComplianceMapper:
    """Get singleton compliance mapper"""
    global _mapper
    if _mapper is None:
        _mapper = ComplianceMapper()
    return _mapper
