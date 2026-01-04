"""CORS Misconfiguration Scanner Module"""

from typing import Any
from urllib.parse import urlparse

import requests


class CORSScanner:
    """CORS Misconfiguration vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # Test origins
        self.test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "http://localhost",
            "null",
        ]

    def _make_request(self, url: str, origin: str) -> requests.Response | None:
        try:
            headers = {
                "User-Agent": self.user_agent,
                "Origin": origin
            }
            return requests.get(url, headers=headers, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _check_cors(self, response: requests.Response,
                    test_origin: str, url: str) -> list[dict]:
        """Check CORS headers for misconfigurations"""
        findings = []

        if not response:
            return findings

        headers = response.headers
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '')

        parsed_url = urlparse(url)
        target_domain = parsed_url.netloc

        # Wildcard CORS
        if acao == '*':
            findings.append({
                "type": "CORS_WILDCARD",
                "url": url,
                "evidence": "Access-Control-Allow-Origin: * allows any origin",
                "confidence": "MEDIUM" if acac.lower() != 'true' else "HIGH"
            })

        # Origin reflection
        if acao == test_origin and test_origin not in ['null', url]:
            severity = "HIGH" if acac.lower() == 'true' else "MEDIUM"
            findings.append({
                "type": "CORS_ORIGIN_REFLECTION",
                "url": url,
                "reflected_origin": test_origin,
                "evidence": f"Origin {test_origin} is reflected in ACAO header",
                "credentials_allowed": acac.lower() == 'true',
                "confidence": severity
            })

        # Null origin accepted
        if acao == 'null':
            findings.append({
                "type": "CORS_NULL_ORIGIN",
                "url": url,
                "evidence": "Access-Control-Allow-Origin: null is dangerous",
                "confidence": "HIGH" if acac.lower() == 'true' else "MEDIUM"
            })

        # Prefix/suffix bypass
        if acao and acao != '*':
            # Check if attacker can create matching subdomain
            if target_domain in acao:
                findings.append({
                    "type": "CORS_SUBDOMAIN",
                    "url": url,
                    "allowed_origin": acao,
                    "evidence": "Subdomain matching may allow bypass",
                    "confidence": "LOW"
                })

        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan URL for CORS misconfigurations"""
        findings = []

        for origin in self.test_origins:
            response = self._make_request(url, origin)
            cors_findings = self._check_cors(response, origin, url)
            findings.extend(cors_findings)

        # Test with target domain variations
        parsed = urlparse(url)
        domain_variations = [
            f"https://evil.{parsed.netloc}",
            f"https://{parsed.netloc}.evil.com",
            f"https://not{parsed.netloc}",
        ]

        for origin in domain_variations:
            response = self._make_request(url, origin)
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                if acao == origin:
                    findings.append({
                        "type": "CORS_ORIGIN_BYPASS",
                        "url": url,
                        "reflected_origin": origin,
                        "evidence": f"Domain variation {origin} accepted",
                        "confidence": "HIGH"
                    })

        return findings
