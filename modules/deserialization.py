"""
Insecure Deserialization Scanner Module
Detects deserialization vulnerabilities in Java, PHP, Python, and .NET applications.
"""

import re
import os
import base64
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
import requests


class DeserializationScanner:
    """
    Insecure Deserialization vulnerability scanner.
    
    Detects:
    - Java serialization (AC ED 00 05 magic bytes)
    - PHP serialization (O:, a:, s:, i:, b:, N; patterns)
    - Python pickle detection
    - .NET ViewState analysis
    - JSON deserialization issues
    - Cookie-based deserialization
    """
    
    # Java serialization magic bytes (base64 encoded starts with rO0)
    JAVA_SERIAL_PATTERNS = [
        (b'\xac\xed\x00\x05', "raw_bytes"),
        (b'rO0', "base64_start"),
        (b'H4sIA', "gzip_base64"),  # GZIPed Java object
    ]
    
    # PHP serialization patterns
    PHP_PATTERNS = [
        r'O:\d+:"[^"]+":',  # Object
        r'a:\d+:{',         # Array
        r's:\d+:"[^"]*";',  # String
        r'i:\d+;',          # Integer
        r'b:[01];',         # Boolean
        r'N;',              # Null
        r'd:\d+\.?\d*;',    # Double/Float
    ]
    
    # Python pickle signatures
    PICKLE_PATTERNS = [
        b'\x80\x03',  # Protocol 3
        b'\x80\x04',  # Protocol 4
        b'\x80\x05',  # Protocol 5
        b'cos\n',     # Module import
        b'cposix\n',  # POSIX module
        b'c__builtin__\n',  # Builtins
    ]
    
    # .NET ViewState patterns
    VIEWSTATE_PATTERNS = [
        r'__VIEWSTATE',
        r'__VIEWSTATEGENERATOR',
        r'__EVENTVALIDATION',
    ]
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })
        
        # Load payloads
        self.payloads = self._load_payloads()
    
    def _load_payloads(self) -> Dict[str, List[Dict]]:
        """Load deserialization payloads by type"""
        payloads = {
            "java": [],
            "php": [],
            "python": [],
            "dotnet": [],
        }
        
        # Java ysoserial-style payloads (detection patterns, not actual exploits)
        payloads["java"] = [
            {
                "name": "CommonsCollections",
                "pattern": b"CommonsCollections",
                "description": "Apache Commons Collections gadget chain"
            },
            {
                "name": "Spring",
                "pattern": b"springframework",
                "description": "Spring Framework gadget chain"
            },
        ]
        
        # PHP payloads for detection
        payloads["php"] = [
            {
                # Serialized object that would trigger __wakeup or __destruct
                "payload": 'O:8:"stdClass":0:{}',
                "technique": "basic_object",
            },
            {
                "payload": 'a:1:{s:4:"test";s:4:"data";}',
                "technique": "array_injection",
            },
        ]
        
        # Load from file if exists
        payloads_file = os.path.join(
            os.path.dirname(__file__), "..", "payloads", "deserialization.txt"
        )
        if os.path.exists(payloads_file):
            with open(payloads_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Format: type|payload|technique
                        parts = line.split("|")
                        if len(parts) >= 2:
                            ptype = parts[0].lower()
                            if ptype in payloads:
                                payloads[ptype].append({
                                    "payload": parts[1],
                                    "technique": parts[2] if len(parts) > 2 else "file"
                                })
        
        return payloads
    
    def _make_request(
        self, 
        url: str, 
        method: str = "GET",
        data: Dict = None,
        headers: Dict = None,
    ) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            req_headers = dict(self.session.headers)
            if headers:
                req_headers.update(headers)
            
            if method.upper() == "GET":
                return self.session.get(
                    url, 
                    timeout=self.timeout,
                    headers=req_headers,
                    verify=False,
                )
            else:
                return self.session.post(
                    url, 
                    data=data, 
                    timeout=self.timeout,
                    headers=req_headers,
                    verify=False,
                )
        except requests.RequestException:
            return None
    
    def _detect_java_serialization(
        self, 
        content: bytes,
        source: str = "response",
    ) -> Optional[Dict[str, Any]]:
        """Detect Java serialized objects"""
        # Check raw bytes
        if content.startswith(b'\xac\xed\x00\x05'):
            return {
                "type": "JAVA_SERIALIZATION",
                "format": "raw",
                "source": source,
                "evidence": "Java serialization magic bytes (AC ED 00 05) detected",
            }
        
        # Check base64 encoded
        try:
            content_str = content.decode('utf-8', errors='ignore')
            # Look for base64 encoded serialized objects
            base64_pattern = r'rO0[A-Za-z0-9+/=]+'
            matches = re.findall(base64_pattern, content_str)
            for match in matches:
                try:
                    decoded = base64.b64decode(match + "=" * (4 - len(match) % 4))
                    if decoded.startswith(b'\xac\xed\x00\x05'):
                        return {
                            "type": "JAVA_SERIALIZATION",
                            "format": "base64",
                            "source": source,
                            "evidence": f"Base64 encoded Java object: {match[:50]}...",
                        }
                except:
                    pass
        except:
            pass
        
        return None
    
    def _detect_php_serialization(
        self, 
        content: str,
        source: str = "response",
    ) -> Optional[Dict[str, Any]]:
        """Detect PHP serialized data"""
        for pattern in self.PHP_PATTERNS:
            if re.search(pattern, content):
                match = re.search(pattern, content)
                return {
                    "type": "PHP_SERIALIZATION",
                    "format": "php_serialize",
                    "source": source,
                    "evidence": f"PHP serialization pattern found: {match.group()[:100]}",
                    "pattern": pattern,
                }
        
        # Check for base64 encoded PHP serialization
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        for match in re.finditer(base64_pattern, content):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                for pattern in self.PHP_PATTERNS:
                    if re.search(pattern, decoded):
                        return {
                            "type": "PHP_SERIALIZATION",
                            "format": "base64",
                            "source": source,
                            "evidence": f"Base64 encoded PHP serialization: {decoded[:100]}",
                        }
            except:
                pass
        
        return None
    
    def _detect_python_pickle(
        self, 
        content: bytes,
        source: str = "response",
    ) -> Optional[Dict[str, Any]]:
        """Detect Python pickle data"""
        for pattern in self.PICKLE_PATTERNS:
            if pattern in content:
                return {
                    "type": "PYTHON_PICKLE",
                    "format": "pickle",
                    "source": source,
                    "evidence": f"Python pickle signature detected",
                }
        
        return None
    
    def _detect_viewstate(
        self, 
        response: requests.Response,
    ) -> List[Dict[str, Any]]:
        """Detect and analyze .NET ViewState"""
        findings = []
        content = response.text
        
        for pattern in self.VIEWSTATE_PATTERNS:
            match = re.search(
                rf'<input[^>]*name="{pattern}"[^>]*value="([^"]+)"',
                content,
                re.IGNORECASE,
            )
            if match:
                value = match.group(1)
                
                finding = {
                    "type": "VIEWSTATE_DETECTED",
                    "field": pattern,
                    "value_length": len(value),
                }
                
                # Check if ViewState is encrypted/MAC protected
                try:
                    decoded = base64.b64decode(value)
                    
                    # Check for unprotected ViewState
                    if not self._viewstate_has_mac(decoded):
                        findings.append({
                            "type": "INSECURE_DESERIALIZATION",
                            "subtype": "UNPROTECTED_VIEWSTATE",
                            "url": response.url,
                            "parameter": pattern,
                            "evidence": f"ViewState appears unprotected (no MAC)",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "description": (
                                ".NET ViewState without MAC protection detected. "
                                "This may allow ViewState tampering and deserialization attacks."
                            ),
                            "remediation": (
                                "Enable ViewState MAC validation in web.config: "
                                "<pages enableViewStateMac=\"true\" />. "
                                "Consider upgrading to ASP.NET 4.5+ with stronger protections."
                            ),
                            "owasp": "A08:2021",
                            "cwe": "CWE-502",
                        })
                except:
                    pass
        
        return findings
    
    def _viewstate_has_mac(self, decoded: bytes) -> bool:
        """Check if ViewState has MAC protection"""
        # ViewState with MAC typically has 20-byte HMAC at the end
        # This is a heuristic check
        if len(decoded) < 20:
            return False
        
        # Check for common .NET serialization headers
        # Unprotected ViewState typically starts with specific bytes
        if decoded[:2] == b'\xff\x01':
            return False
        
        return True
    
    def _check_header_serialization(
        self, 
        response: requests.Response,
    ) -> List[Dict[str, Any]]:
        """Check headers for serialized data"""
        findings = []
        
        # Check cookies for serialized data
        for cookie in response.cookies:
            value = cookie.value
            
            # Check for Java serialization in cookie
            try:
                decoded = base64.b64decode(value + "=" * (4 - len(value) % 4))
                java_result = self._detect_java_serialization(decoded, f"cookie:{cookie.name}")
                if java_result:
                    findings.append({
                        "type": "INSECURE_DESERIALIZATION",
                        "subtype": "JAVA_COOKIE",
                        "url": response.url,
                        "parameter": f"Cookie: {cookie.name}",
                        "evidence": java_result["evidence"],
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "description": (
                            f"Java serialized object found in cookie '{cookie.name}'. "
                            "This can lead to Remote Code Execution if the application "
                            "deserializes the cookie value."
                        ),
                        "remediation": (
                            "Avoid using Java serialization for cookies. "
                            "Use JSON or other safe serialization formats. "
                            "Implement integrity checks (HMAC) on serialized data."
                        ),
                        "owasp": "A08:2021",
                        "cwe": "CWE-502",
                    })
            except:
                pass
            
            # Check for PHP serialization in cookie
            php_result = self._detect_php_serialization(value, f"cookie:{cookie.name}")
            if php_result:
                findings.append({
                    "type": "INSECURE_DESERIALIZATION",
                    "subtype": "PHP_COOKIE",
                    "url": response.url,
                    "parameter": f"Cookie: {cookie.name}",
                    "evidence": php_result["evidence"],
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "description": (
                        f"PHP serialized data found in cookie '{cookie.name}'. "
                        "This may be vulnerable to object injection attacks."
                    ),
                    "remediation": (
                        "Use JSON instead of PHP serialize for session data. "
                        "Implement HMAC validation on serialized data."
                    ),
                    "owasp": "A08:2021",
                    "cwe": "CWE-502",
                })
        
        return findings
    
    def _check_content_type_vulnerabilities(
        self,
        response: requests.Response,
    ) -> List[Dict[str, Any]]:
        """Check for Content-Type based deserialization issues"""
        findings = []
        
        content_type = response.headers.get("Content-Type", "")
        
        # Check for Java serialization Content-Type
        if "application/x-java-serialized-object" in content_type:
            findings.append({
                "type": "INSECURE_DESERIALIZATION",
                "subtype": "JAVA_CONTENT_TYPE",
                "url": response.url,
                "evidence": f"Content-Type indicates Java serialization: {content_type}",
                "severity": "HIGH",
                "confidence": "HIGH",
                "description": (
                    "Application accepts or returns Java serialized objects. "
                    "This is a strong indicator of deserialization vulnerability."
                ),
                "remediation": (
                    "Replace Java serialization with JSON or other safe formats. "
                    "If serialization is required, use a secure library like Kryo with class whitelisting."
                ),
                "owasp": "A08:2021",
                "cwe": "CWE-502",
            })
        
        return findings
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for deserialization vulnerabilities.
        
        Args:
            url: Target URL to scan
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        response = self._make_request(url)
        if not response:
            return findings
        
        content = response.content
        content_str = response.text
        
        # Check for Java serialization in response
        java_result = self._detect_java_serialization(content, "response_body")
        if java_result:
            findings.append({
                "type": "INSECURE_DESERIALIZATION",
                "subtype": "JAVA_RESPONSE",
                "url": url,
                "evidence": java_result["evidence"],
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "description": "Java serialized data detected in response body.",
                "remediation": "Avoid exposing serialized Java objects. Use JSON for data exchange.",
                "owasp": "A08:2021",
                "cwe": "CWE-502",
            })
        
        # Check for PHP serialization
        php_result = self._detect_php_serialization(content_str, "response_body")
        if php_result:
            findings.append({
                "type": "INSECURE_DESERIALIZATION",
                "subtype": "PHP_RESPONSE",
                "url": url,
                "evidence": php_result["evidence"],
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "description": "PHP serialized data detected in response.",
                "remediation": "Use JSON instead of PHP serialize for data exchange.",
                "owasp": "A08:2021",
                "cwe": "CWE-502",
            })
        
        # Check for Python pickle
        pickle_result = self._detect_python_pickle(content, "response_body")
        if pickle_result:
            findings.append({
                "type": "INSECURE_DESERIALIZATION",
                "subtype": "PYTHON_PICKLE",
                "url": url,
                "evidence": pickle_result["evidence"],
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "description": "Python pickle data detected. Pickle is inherently unsafe.",
                "remediation": "Never use pickle for untrusted data. Use JSON or other safe formats.",
                "owasp": "A08:2021",
                "cwe": "CWE-502",
            })
        
        # Check ViewState
        findings.extend(self._detect_viewstate(response))
        
        # Check headers/cookies
        findings.extend(self._check_header_serialization(response))
        
        # Check Content-Type
        findings.extend(self._check_content_type_vulnerabilities(response))
        
        return findings
    
    def scan_endpoint_with_payloads(
        self, 
        url: str, 
        parameter: str,
        method: str = "POST",
    ) -> List[Dict[str, Any]]:
        """
        Test an endpoint with deserialization payloads.
        
        Args:
            url: Target endpoint
            parameter: Parameter to inject
            method: HTTP method
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Test with PHP payloads
        for payload_info in self.payloads.get("php", []):
            payload = payload_info.get("payload", "")
            technique = payload_info.get("technique", "unknown")
            
            data = {parameter: payload}
            response = self._make_request(url, method=method, data=data)
            
            if response:
                # Check for error indicators
                error_patterns = [
                    r"unserialize\(\)",
                    r"__wakeup",
                    r"__destruct",
                    r"Object of class",
                    r"cannot be converted to string",
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append({
                            "type": "INSECURE_DESERIALIZATION",
                            "subtype": "PHP_INJECTION",
                            "url": url,
                            "method": method,
                            "parameter": parameter,
                            "payload": payload,
                            "technique": technique,
                            "evidence": f"PHP deserialization error pattern: {pattern}",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "description": (
                                "PHP object injection vulnerability detected. "
                                "The application deserializes user-controlled data."
                            ),
                            "remediation": (
                                "Avoid unserialize() on user input. "
                                "Use json_decode() instead. "
                                "If serialization is needed, implement strict class allowlisting."
                            ),
                            "owasp": "A08:2021",
                            "cwe": "CWE-502",
                        })
                        return findings  # One finding is enough
        
        return findings


def get_scanner(timeout: int = 10, user_agent: str = None) -> DeserializationScanner:
    """Get a Deserialization scanner instance"""
    return DeserializationScanner(timeout=timeout, user_agent=user_agent)
