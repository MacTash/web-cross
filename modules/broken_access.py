"""
Broken Access Control Scanner Module
Detects IDOR and privilege escalation vulnerabilities.
"""

import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests


class BrokenAccessScanner:
    """
    Broken Access Control vulnerability scanner.

    Detects:
    - Insecure Direct Object References (IDOR)
    - Horizontal privilege escalation
    - Vertical privilege escalation indicators
    - Missing function-level access control
    - Path-based access bypass
    - HTTP method tampering
    """

    # Patterns for identifying resource IDs
    ID_PATTERNS = [
        r'/(\d+)(?:/|$|\?)',           # Numeric IDs in path
        r'/([a-f0-9]{24})(?:/|$|\?)',  # MongoDB ObjectIDs
        r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:/|$|\?)',  # UUIDs
        r'[?&]id=(\d+)',               # id parameter
        r'[?&]user_id=(\d+)',          # user_id parameter
        r'[?&]userId=(\d+)',           # userId parameter
        r'[?&]account[_]?id=(\d+)',    # accountId parameter
        r'[?&]order[_]?id=(\d+)',      # orderId parameter
        r'[?&]file[_]?id=(\d+)',       # fileId parameter
        r'[?&]doc[_]?id=(\d+)',        # docId parameter
    ]

    # Common parameter names that might contain object references
    IDOR_PARAMS = [
        "id", "Id", "ID",
        "user_id", "userId", "user",
        "account_id", "accountId", "account",
        "profile_id", "profileId", "profile",
        "order_id", "orderId", "order",
        "file_id", "fileId", "file",
        "doc_id", "docId", "document",
        "record_id", "recordId", "record",
        "item_id", "itemId", "item",
        "message_id", "messageId", "message",
        "uid", "uuid", "guid",
        "ref", "reference",
    ]

    # Sensitive admin/internal endpoints
    ADMIN_ENDPOINTS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/manage",
        "/management",
        "/console",
        "/dashboard/admin",
        "/api/admin",
        "/api/internal",
        "/api/private",
        "/internal",
        "/private",
        "/config",
        "/settings/admin",
        "/users/all",
        "/api/users",
        "/debug",
        "/phpinfo",
        "/.git",
        "/.env",
    ]

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: dict = None,
        headers: dict = None,
    ) -> requests.Response | None:
        """Make HTTP request with error handling"""
        try:
            req_headers = dict(self.session.headers)
            if headers:
                req_headers.update(headers)

            return self.session.request(
                method.upper(),
                url,
                data=data,
                timeout=self.timeout,
                headers=req_headers,
                verify=False,
                allow_redirects=True,
            )
        except requests.RequestException:
            return None

    def _extract_ids_from_url(self, url: str) -> list[dict[str, Any]]:
        """Extract potential object IDs from URL"""
        ids = []

        for pattern in self.ID_PATTERNS:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                id_info = {
                    "value": match,
                    "type": "numeric" if match.isdigit() else "string",
                    "pattern": pattern,
                }
                ids.append(id_info)

        # Also check query parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in self.IDOR_PARAMS:
            if param_name in params:
                for value in params[param_name]:
                    ids.append({
                        "value": value,
                        "type": "numeric" if value.isdigit() else "string",
                        "param": param_name,
                    })

        return ids

    def _generate_test_ids(self, original_id: str) -> list[str]:
        """Generate test IDs to check for IDOR"""
        test_ids = []

        if original_id.isdigit():
            # Numeric ID - try adjacent values
            id_int = int(original_id)
            test_ids.extend([
                str(id_int - 1),
                str(id_int + 1),
                str(id_int - 100),
                str(id_int + 100),
                "1",
                "0",
                "2",
                "999999",
            ])
        elif len(original_id) == 24 and all(c in '0123456789abcdef' for c in original_id.lower()):
            # MongoDB ObjectID - modify last few characters
            test_ids.extend([
                original_id[:-4] + "0000",
                original_id[:-4] + "ffff",
                "000000000000000000000001",
            ])
        elif "-" in original_id and len(original_id) == 36:
            # UUID - try variations
            test_ids.extend([
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000000",
            ])
        else:
            # Generic string ID
            test_ids.extend([
                "admin",
                "root",
                "test",
                "1",
            ])

        return test_ids

    def _compare_responses(
        self,
        original: requests.Response,
        test: requests.Response,
    ) -> tuple[bool, str]:
        """Compare two responses to detect IDOR"""
        # If status codes differ significantly, might not be IDOR
        if original.status_code != test.status_code:
            if test.status_code in (401, 403):
                return False, "Access denied"
            if test.status_code == 404:
                return False, "Not found"

        # If test request got data that original didn't, that's suspicious
        if test.status_code == 200 and original.status_code != 200:
            return True, "Different status codes suggest unauthorized access"

        # Compare content length differences
        orig_len = len(original.content)
        test_len = len(test.content)

        if orig_len > 0 and test_len > 0:
            len_diff = abs(orig_len - test_len)
            # If content differs significantly, data might be different
            if len_diff > 100 and test.status_code == 200:
                return True, f"Content length differs by {len_diff} bytes"

        # Check for sensitive data indicators in response
        sensitive_patterns = [
            r'"email"\s*:\s*"[^"]+@[^"]+"',
            r'"password"\s*:',
            r'"ssn"\s*:',
            r'"credit_card"\s*:',
            r'"phone"\s*:\s*"[^"]+"',
            r'"address"\s*:',
            r'"token"\s*:',
            r'"api_key"\s*:',
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, test.text, re.IGNORECASE):
                if not re.search(pattern, original.text, re.IGNORECASE):
                    return True, f"Sensitive data pattern found: {pattern}"

        return False, "No significant difference"

    def _test_idor_url(self, url: str) -> list[dict[str, Any]]:
        """Test a URL for IDOR vulnerabilities"""
        findings = []

        # Get original response
        original_response = self._make_request(url)
        if not original_response:
            return findings

        # Extract IDs from URL
        ids = self._extract_ids_from_url(url)

        for id_info in ids:
            original_id = id_info["value"]
            test_ids = self._generate_test_ids(original_id)

            for test_id in test_ids:
                if test_id == original_id:
                    continue

                # Build test URL
                if "param" in id_info:
                    # It's a query parameter
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[id_info["param"]] = [test_id]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                else:
                    # It's in the path
                    test_url = url.replace(original_id, test_id)

                test_response = self._make_request(test_url)
                if not test_response:
                    continue

                is_vulnerable, reason = self._compare_responses(
                    original_response,
                    test_response,
                )

                if is_vulnerable:
                    findings.append({
                        "type": "BROKEN_ACCESS_CONTROL",
                        "subtype": "IDOR",
                        "url": url,
                        "test_url": test_url,
                        "original_id": original_id,
                        "test_id": test_id,
                        "parameter": id_info.get("param", "path"),
                        "evidence": reason,
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "description": (
                            f"Insecure Direct Object Reference (IDOR) detected. "
                            f"Changing {id_info.get('param', 'resource ID')} from "
                            f"'{original_id}' to '{test_id}' returns different data. "
                            f"This may allow access to other users' resources."
                        ),
                        "remediation": (
                            "Implement proper authorization checks. "
                            "Verify the requesting user owns/has access to the resource. "
                            "Use indirect references (e.g., session-based mapping)."
                        ),
                        "owasp": "A01:2021",
                        "cwe": "CWE-639",
                    })
                    break  # One finding per ID is enough

        return findings

    def _test_admin_endpoints(self, base_url: str) -> list[dict[str, Any]]:
        """Test for accessible admin endpoints"""
        findings = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in self.ADMIN_ENDPOINTS:
            url = urljoin(base, endpoint)
            response = self._make_request(url)

            if not response:
                continue

            if response.status_code == 200:
                # Check if it's actually admin content
                content_lower = response.text.lower()
                admin_indicators = [
                    "admin", "dashboard", "control panel", "management",
                    "configuration", "settings", "users", "system",
                ]

                is_admin_page = any(ind in content_lower for ind in admin_indicators)

                if is_admin_page:
                    findings.append({
                        "type": "BROKEN_ACCESS_CONTROL",
                        "subtype": "MISSING_FUNCTION_LEVEL_ACCESS_CONTROL",
                        "url": url,
                        "endpoint": endpoint,
                        "evidence": f"Admin endpoint accessible: {response.status_code}",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "description": (
                            f"Administrative endpoint {endpoint} is accessible "
                            f"without authentication. This may expose sensitive "
                            f"functionality or data."
                        ),
                        "remediation": (
                            "Implement authentication and authorization on all admin endpoints. "
                            "Use role-based access control (RBAC). "
                            "Consider network-level restrictions for admin panels."
                        ),
                        "owasp": "A01:2021",
                        "cwe": "CWE-306",
                    })

        return findings

    def _test_method_tampering(self, url: str) -> list[dict[str, Any]]:
        """Test for HTTP method tampering bypasses"""
        findings = []

        # First, check if resource is protected
        get_response = self._make_request(url, method="GET")
        if not get_response:
            return findings

        # If GET is forbidden, try other methods
        if get_response.status_code in (401, 403):
            methods = ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

            for method in methods:
                response = self._make_request(url, method=method)
                if response and response.status_code == 200:
                    findings.append({
                        "type": "BROKEN_ACCESS_CONTROL",
                        "subtype": "HTTP_METHOD_BYPASS",
                        "url": url,
                        "method": method,
                        "evidence": (
                            f"GET returned {get_response.status_code}, "
                            f"but {method} returned 200"
                        ),
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "description": (
                            f"Access control bypass via HTTP method tampering. "
                            f"While GET is blocked, {method} method is allowed."
                        ),
                        "remediation": (
                            "Ensure access control applies to all HTTP methods. "
                            "Use framework-level access control that covers all methods."
                        ),
                        "owasp": "A01:2021",
                        "cwe": "CWE-650",
                    })
                    break

        return findings

    def _test_path_traversal_bypass(self, url: str) -> list[dict[str, Any]]:
        """Test for path-based access control bypass"""
        findings = []

        parsed = urlparse(url)

        # Try path manipulation bypasses
        bypasses = [
            ("/..", "parent_directory"),
            ("/./", "current_directory"),
            ("//", "double_slash"),
            ("/;/", "semicolon"),
            ("/%2e%2e/", "encoded_parent"),
            ("/.;/", "dot_semicolon"),
        ]

        for bypass, technique in bypasses:
            # Insert bypass in path
            if parsed.path and len(parsed.path) > 1:
                test_path = bypass + parsed.path
                test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

                if parsed.query:
                    test_url += f"?{parsed.query}"

                response = self._make_request(test_url)
                if response and response.status_code == 200:
                    # Compare with original
                    original = self._make_request(url)
                    if original and original.status_code in (401, 403):
                        findings.append({
                            "type": "BROKEN_ACCESS_CONTROL",
                            "subtype": "PATH_TRAVERSAL_BYPASS",
                            "url": url,
                            "test_url": test_url,
                            "technique": technique,
                            "evidence": f"Path manipulation bypass: {bypass}",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "description": (
                                f"Access control bypass via path manipulation. "
                                f"Using '{bypass}' in the path bypasses authorization."
                            ),
                            "remediation": (
                                "Normalize and canonicalize paths before authorization checks. "
                                "Use path-agnostic access control mechanisms."
                            ),
                            "owasp": "A01:2021",
                            "cwe": "CWE-22",
                        })
                        break

        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """
        Scan a URL for broken access control vulnerabilities.

        Args:
            url: Target URL to scan

        Returns:
            List of vulnerability findings
        """
        findings = []

        # Test for IDOR
        findings.extend(self._test_idor_url(url))

        # Test for method tampering
        findings.extend(self._test_method_tampering(url))

        # Test for path bypass
        findings.extend(self._test_path_traversal_bypass(url))

        return findings

    def scan_all(self, base_url: str) -> list[dict[str, Any]]:
        """
        Comprehensive broken access control scan.

        Args:
            base_url: Base URL to scan

        Returns:
            List of vulnerability findings
        """
        findings = []

        # Scan base URL for IDOR
        findings.extend(self.scan_url(base_url))

        # Test admin endpoints
        findings.extend(self._test_admin_endpoints(base_url))

        return findings

    def test_idor_api(
        self,
        url: str,
        parameter: str,
        test_values: list[str] = None,
        method: str = "GET",
    ) -> list[dict[str, Any]]:
        """
        Test specific API endpoint for IDOR.

        Args:
            url: API endpoint URL
            parameter: Parameter containing the object reference
            test_values: List of IDs to test
            method: HTTP method

        Returns:
            List of vulnerability findings
        """
        findings = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if parameter not in params:
            return findings

        original_id = params[parameter][0]
        original_response = self._make_request(url, method=method)

        if not original_response:
            return findings

        test_ids = test_values or self._generate_test_ids(original_id)

        for test_id in test_ids:
            if test_id == original_id:
                continue

            test_params = dict(params)
            test_params[parameter] = [test_id]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

            test_response = self._make_request(test_url, method=method)
            if not test_response:
                continue

            is_vulnerable, reason = self._compare_responses(
                original_response,
                test_response,
            )

            if is_vulnerable:
                findings.append({
                    "type": "BROKEN_ACCESS_CONTROL",
                    "subtype": "API_IDOR",
                    "url": url,
                    "test_url": test_url,
                    "method": method,
                    "parameter": parameter,
                    "original_id": original_id,
                    "test_id": test_id,
                    "evidence": reason,
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "description": (
                        f"API IDOR vulnerability found. "
                        f"Parameter '{parameter}' allows access to other "
                        f"users' resources by changing the ID value."
                    ),
                    "remediation": (
                        "Implement proper authorization in API endpoints. "
                        "Verify resource ownership before returning data."
                    ),
                    "owasp": "A01:2021",
                    "cwe": "CWE-639",
                })

        return findings


def get_scanner(timeout: int = 10, user_agent: str = None) -> BrokenAccessScanner:
    """Get a Broken Access Control scanner instance"""
    return BrokenAccessScanner(timeout=timeout, user_agent=user_agent)
