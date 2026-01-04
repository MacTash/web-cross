"""XSS (Cross-Site Scripting) Scanner Module"""

import html
import os
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from bs4 import BeautifulSoup


class XSSScanner:
    """Cross-Site Scripting vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        self.payloads = self._load_payloads()

        # Patterns indicating XSS reflection
        self.reflection_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
            r"<body[^>]+onload",
            r"<input[^>]+onfocus",
            r"<iframe[^>]+src\s*=\s*[\"']?javascript:",
            r"<a[^>]+href\s*=\s*[\"']?javascript:",
            r"expression\s*\(",
            r"eval\s*\(",
            r"alert\s*\(",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
        ]

        # Context-specific payloads
        self.context_payloads = {
            "html": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
            ],
            "attribute": [
                "\" onmouseover=\"alert('XSS')\"",
                "' onfocus='alert(1)' autofocus='",
                "\" onfocus=\"alert(1)\" autofocus=\"",
            ],
            "javascript": [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "</script><script>alert('XSS')</script>",
            ],
            "url": [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
            ]
        }

    def _load_payloads(self) -> list[str]:
        """Load XSS payloads from file"""
        payload_file = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'xss.txt')
        payloads = []
        try:
            with open(payload_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
            ]
        return payloads

    def _make_request(self, url: str, method: str = "GET",
                      data: dict = None, params: dict = None) -> requests.Response | None:
        """Make HTTP request with error handling"""
        try:
            headers = {"User-Agent": self.user_agent}
            if method.upper() == "GET":
                return requests.get(url, params=params, headers=headers,
                                  timeout=self.timeout, verify=False)
            else:
                return requests.post(url, data=data, headers=headers,
                                   timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _detect_context(self, response_text: str, payload: str) -> str:
        """Detect the context where payload is reflected"""
        # Check if payload appears unencoded
        if payload in response_text:
            # Check context
            soup = BeautifulSoup(response_text, 'html.parser')

            # Check in script tags
            for script in soup.find_all('script'):
                if payload in str(script):
                    return "javascript"

            # Check in attributes
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and payload in value:
                        if attr.startswith('on'):
                            return "event_handler"
                        elif attr in ['href', 'src', 'action']:
                            return "url"
                        else:
                            return "attribute"

            return "html"

        # Check if payload is encoded
        if html.escape(payload) in response_text:
            return "encoded"

        return "none"

    def _check_reflection(self, response: requests.Response, payload: str) -> dict | None:
        """Check if payload is reflected and potentially exploitable"""
        if not response:
            return None

        content = response.text
        context = self._detect_context(content, payload)

        if context == "none" or context == "encoded":
            return None

        # Check if dangerous patterns are present
        for pattern in self.reflection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    "type": "REFLECTED_XSS",
                    "payload": payload,
                    "context": context,
                    "evidence": f"Payload reflected in {context} context",
                    "confidence": "HIGH" if context in ["javascript", "event_handler"] else "MEDIUM"
                }

        # Payload reflected but possibly sanitized
        if payload in content:
            return {
                "type": "REFLECTED_XSS",
                "payload": payload,
                "context": context,
                "evidence": "Payload reflected, may be exploitable",
                "confidence": "LOW"
            }

        return None

    def _check_dom_xss(self, response: requests.Response, url: str) -> list[dict]:
        """Check for potential DOM-based XSS sinks"""
        findings = []
        if not response:
            return findings

        content = response.text

        # DOM XSS sinks
        dom_sinks = [
            (r"document\.write\s*\(", "document.write()"),
            (r"document\.writeln\s*\(", "document.writeln()"),
            (r"\.innerHTML\s*=", "innerHTML assignment"),
            (r"\.outerHTML\s*=", "outerHTML assignment"),
            (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
            (r"eval\s*\(", "eval()"),
            (r"setTimeout\s*\([^,]*,", "setTimeout() with string"),
            (r"setInterval\s*\([^,]*,", "setInterval() with string"),
            (r"new\s+Function\s*\(", "new Function()"),
            (r"location\s*=", "location assignment"),
            (r"location\.href\s*=", "location.href assignment"),
            (r"location\.replace\s*\(", "location.replace()"),
            (r"location\.assign\s*\(", "location.assign()"),
        ]

        # DOM XSS sources
        dom_sources = [
            "location.hash",
            "location.search",
            "location.href",
            "document.URL",
            "document.referrer",
            "window.name",
            "document.cookie",
        ]

        # Check for sinks
        for pattern, sink_name in dom_sinks:
            if re.search(pattern, content, re.IGNORECASE):
                # Check if any source flows to sink
                for source in dom_sources:
                    if source in content:
                        findings.append({
                            "type": "DOM_XSS_POTENTIAL",
                            "url": url,
                            "sink": sink_name,
                            "source": source,
                            "evidence": f"Found {sink_name} with {source} in page",
                            "confidence": "MEDIUM"
                        })

        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan a URL for XSS vulnerabilities"""
        findings = []

        # Get original response
        original_response = self._make_request(url)
        if not original_response:
            return findings

        # Check for DOM XSS
        dom_findings = self._check_dom_xss(original_response, url)
        findings.extend(dom_findings)

        # Parse URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Test each parameter
        for param in params:
            for payload in self.payloads[:15]:  # Limit for speed
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                response = self._make_request(test_url)
                result = self._check_reflection(response, payload)

                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)
                    break  # Found XSS in this param

        return findings

    def scan_form(self, url: str, form: dict) -> list[dict[str, Any]]:
        """Scan a form for XSS vulnerabilities"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})

        if not inputs:
            return findings

        for field_name in inputs:
            for payload in self.payloads[:10]:
                test_data = inputs.copy()
                test_data[field_name] = payload

                if method == "GET":
                    response = self._make_request(action, params=test_data)
                else:
                    response = self._make_request(action, method="POST", data=test_data)

                result = self._check_reflection(response, payload)
                if result:
                    result["parameter"] = field_name
                    result["url"] = action
                    result["method"] = method
                    findings.append(result)
                    break

        return findings

    def get_stored_xss_indicators(self, response: requests.Response) -> list[dict]:
        """Check for indicators of stored XSS"""
        findings = []
        if not response:
            return findings

        content = response.text

        # Check for common XSS payloads in page content
        stored_patterns = [
            r"<script>alert\(",
            r"onerror\s*=\s*['\"]?alert",
            r"onload\s*=\s*['\"]?alert",
            r"javascript:alert",
        ]

        for pattern in stored_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "STORED_XSS_INDICATOR",
                    "evidence": f"Found pattern: {matches[0]}",
                    "confidence": "MEDIUM"
                })

        return findings
