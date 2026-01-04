"""
Open Redirect Scanner Module
Detects URL redirection vulnerabilities that can be exploited for phishing.
"""

import re
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, quote
import requests
from bs4 import BeautifulSoup


class OpenRedirectScanner:
    """
    Open Redirect vulnerability scanner.
    
    Detects:
    - Parameter-based redirects (url, redirect, next, return, etc.)
    - JavaScript-based redirects
    - Meta refresh redirects
    - Header Location manipulation
    - Various encoding bypass techniques
    """
    
    # Common redirect parameters
    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri",
        "next", "next_url", "return", "return_url", "returnUrl",
        "goto", "go", "dest", "destination", "target",
        "redir", "redirect_to", "redirectTo", "returnTo",
        "continue", "forward", "forward_url", "out", "outurl",
        "view", "link", "linkurl", "site", "callback",
        "checkout_url", "success_url", "failure_url",
        "login_url", "logout_url", "back", "backurl", "ref",
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
        
        # Canary domain for detection
        self.canary_domain = "evil.com"
        self.canary_patterns = [
            f"https://{self.canary_domain}",
            f"http://{self.canary_domain}",
            f"//{self.canary_domain}",
            self.canary_domain,
        ]
    
    def _load_payloads(self) -> List[Dict[str, str]]:
        """Load open redirect payloads"""
        payloads = []
        
        # Basic payloads
        basic = [
            {"payload": "https://evil.com", "technique": "direct_url"},
            {"payload": "//evil.com", "technique": "protocol_relative"},
            {"payload": "http://evil.com", "technique": "http_url"},
            {"payload": "/\\evil.com", "technique": "backslash_bypass"},
            {"payload": "////evil.com", "technique": "multiple_slash"},
            {"payload": "https:evil.com", "technique": "missing_slash"},
            {"payload": "https:/evil.com", "technique": "single_slash"},
        ]
        payloads.extend(basic)
        
        # Encoding bypasses
        encoding = [
            {"payload": "https:%2F%2Fevil.com", "technique": "url_encode"},
            {"payload": "https:%252F%252Fevil.com", "technique": "double_encode"},
            {"payload": "%2F%2Fevil.com", "technique": "encoded_protocol_relative"},
            {"payload": "//evil%2Ecom", "technique": "encoded_dot"},
            {"payload": "https://evil。com", "technique": "unicode_dot"},
            {"payload": "https://evil%E3%80%82com", "technique": "encoded_unicode_dot"},
        ]
        payloads.extend(encoding)
        
        # Subdomain/path confusion
        confusion = [
            {"payload": "https://legitimate.com@evil.com", "technique": "at_sign_bypass"},
            {"payload": "https://legitimate.com%40evil.com", "technique": "encoded_at_bypass"},
            {"payload": "https://evil.com#legitimate.com", "technique": "fragment_bypass"},
            {"payload": "https://evil.com?legitimate.com", "technique": "query_bypass"},
            {"payload": "https://evil.com/legitimate.com", "technique": "path_bypass"},
            {"payload": "https://evil.com\\.legitimate.com", "technique": "backslash_domain"},
        ]
        payloads.extend(confusion)
        
        # JavaScript-based
        javascript = [
            {"payload": "javascript://evil.com/%0Aalert(1)", "technique": "javascript_protocol"},
            {"payload": "data:text/html,<script>location='https://evil.com'</script>", "technique": "data_uri"},
        ]
        payloads.extend(javascript)
        
        # Domain mimic
        mimic = [
            {"payload": "https://evil.com/legitimate.com/../", "technique": "path_traversal"},
            {"payload": "https://legitimate.com.evil.com", "technique": "subdomain_mimic"},
        ]
        payloads.extend(mimic)
        
        # Load from file if exists
        payloads_file = os.path.join(
            os.path.dirname(__file__), "..", "payloads", "open_redirect.txt"
        )
        if os.path.exists(payloads_file):
            with open(payloads_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append({
                            "payload": line,
                            "technique": "file_payload"
                        })
        
        return payloads
    
    def _make_request(
        self, 
        url: str, 
        method: str = "GET",
        data: Dict = None,
        params: Dict = None,
        allow_redirects: bool = False,
    ) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            if method.upper() == "GET":
                return self.session.get(
                    url, 
                    params=params, 
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False,
                )
            else:
                return self.session.post(
                    url, 
                    data=data, 
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False,
                )
        except requests.RequestException:
            return None
    
    def _check_redirect_response(
        self, 
        response: requests.Response, 
        payload: str,
    ) -> Dict[str, Any]:
        """Check if response indicates successful redirect"""
        result = {
            "vulnerable": False,
            "type": None,
            "evidence": None,
        }
        
        # Check for redirect status codes
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            
            # Check if Location contains our canary domain
            for pattern in self.canary_patterns:
                if pattern in location.lower():
                    result["vulnerable"] = True
                    result["type"] = "HEADER_REDIRECT"
                    result["evidence"] = f"Location header redirects to: {location}"
                    return result
            
            # Check for @ bypass in Location
            if "@" in location and self.canary_domain in location:
                result["vulnerable"] = True
                result["type"] = "AT_BYPASS_REDIRECT"
                result["evidence"] = f"Location header with @ bypass: {location}"
                return result
        
        # Check response body for JS redirects
        if response.status_code == 200:
            body = response.text.lower()
            
            # Check for meta refresh
            meta_pattern = r'<meta[^>]*refresh[^>]*content=["\'][^"\']*url=([^"\'>]+)'
            meta_matches = re.findall(meta_pattern, body, re.IGNORECASE)
            for match in meta_matches:
                if self.canary_domain in match:
                    result["vulnerable"] = True
                    result["type"] = "META_REFRESH_REDIRECT"
                    result["evidence"] = f"Meta refresh redirects to: {match}"
                    return result
            
            # Check for JavaScript redirects
            js_patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)',
                r'location\.href\s*=\s*["\']([^"\']+)',
                r'location\.replace\s*\(\s*["\']([^"\']+)',
                r'location\.assign\s*\(\s*["\']([^"\']+)',
            ]
            for pattern in js_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    if self.canary_domain in match:
                        result["vulnerable"] = True
                        result["type"] = "JAVASCRIPT_REDIRECT"
                        result["evidence"] = f"JavaScript redirect to: {match}"
                        return result
        
        return result
    
    def _detect_redirect_params(self, url: str) -> List[str]:
        """Detect potential redirect parameters in URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        detected = []
        for param in params:
            param_lower = param.lower()
            # Check if param name suggests redirect
            if any(rp in param_lower for rp in self.REDIRECT_PARAMS):
                detected.append(param)
            # Check if param value looks like a URL
            for value in params[param]:
                if value.startswith(("http://", "https://", "/", "//")):
                    if param not in detected:
                        detected.append(param)
        
        return detected
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for open redirect vulnerabilities.
        
        Args:
            url: Target URL to scan
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Get original parameters
        original_params = parse_qs(parsed.query)
        
        # Detect redirect parameters
        detected_params = self._detect_redirect_params(url)
        
        # Also test common redirect params even if not in URL
        test_params = list(set(detected_params + self.REDIRECT_PARAMS[:15]))
        
        for param in test_params:
            for payload_info in self.payloads:
                payload = payload_info["payload"]
                technique = payload_info["technique"]
                
                # Build test URL
                test_params_dict = dict(original_params)
                test_params_dict[param] = [payload]
                test_url = f"{base_url}?{urlencode(test_params_dict, doseq=True)}"
                
                response = self._make_request(test_url, allow_redirects=False)
                if not response:
                    continue
                
                result = self._check_redirect_response(response, payload)
                
                if result["vulnerable"]:
                    findings.append({
                        "type": "OPEN_REDIRECT",
                        "subtype": result["type"],
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "technique": technique,
                        "evidence": result["evidence"],
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "description": (
                            f"Open redirect vulnerability found via {param} parameter. "
                            f"The application redirects to attacker-controlled URLs, "
                            f"which can be used for phishing attacks."
                        ),
                        "remediation": (
                            "Validate redirect URLs against a whitelist of allowed domains. "
                            "Use relative URLs for redirects when possible. "
                            "Implement proper URL parsing to prevent bypass techniques."
                        ),
                        "owasp": "A01:2021",
                        "cwe": "CWE-601",
                    })
                    # Move to next parameter after finding vulnerability
                    break
        
        return findings
    
    def scan_form(self, url: str, form: Dict) -> List[Dict[str, Any]]:
        """
        Scan a form for open redirect vulnerabilities.
        
        Args:
            url: Base URL
            form: Form dictionary with action, method, and inputs
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        action = form.get("action", url)
        if not action.startswith(("http://", "https://")):
            action = urljoin(url, action)
        
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        
        # Find redirect-like input fields
        redirect_inputs = []
        for inp in inputs:
            name = inp.get("name", "").lower()
            if any(rp in name for rp in self.REDIRECT_PARAMS):
                redirect_inputs.append(inp)
        
        for inp in redirect_inputs:
            param_name = inp.get("name")
            
            for payload_info in self.payloads[:10]:  # Test top payloads
                payload = payload_info["payload"]
                technique = payload_info["technique"]
                
                # Build form data
                form_data = {}
                for input_field in inputs:
                    name = input_field.get("name")
                    if name:
                        if name == param_name:
                            form_data[name] = payload
                        else:
                            form_data[name] = input_field.get("value", "test")
                
                if method == "GET":
                    response = self._make_request(
                        action, 
                        method="GET", 
                        params=form_data,
                        allow_redirects=False,
                    )
                else:
                    response = self._make_request(
                        action, 
                        method="POST", 
                        data=form_data,
                        allow_redirects=False,
                    )
                
                if not response:
                    continue
                
                result = self._check_redirect_response(response, payload)
                
                if result["vulnerable"]:
                    findings.append({
                        "type": "OPEN_REDIRECT",
                        "subtype": result["type"],
                        "url": action,
                        "method": method,
                        "parameter": param_name,
                        "payload": payload,
                        "technique": technique,
                        "evidence": result["evidence"],
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "description": (
                            f"Open redirect vulnerability found in form via {param_name} field. "
                            f"Form submission can be manipulated to redirect users to malicious sites."
                        ),
                        "remediation": (
                            "Validate redirect destinations against an allowlist. "
                            "Use server-side redirect mapping instead of user-controlled URLs."
                        ),
                        "owasp": "A01:2021",
                        "cwe": "CWE-601",
                    })
                    break
        
        return findings
    
    def check_known_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Check known redirect endpoints.
        
        Args:
            base_url: Base URL of the target
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Common redirect endpoints
        endpoints = [
            "/redirect?url={payload}",
            "/redirect?redirect_url={payload}",
            "/login?next={payload}",
            "/login?return={payload}",
            "/logout?redirect={payload}",
            "/oauth/authorize?redirect_uri={payload}",
            "/auth/callback?return_to={payload}",
            "/link?url={payload}",
            "/out?url={payload}",
            "/go?to={payload}",
        ]
        
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in endpoints:
            test_url = base + endpoint.format(payload=quote("https://evil.com"))
            response = self._make_request(test_url, allow_redirects=False)
            
            if response:
                result = self._check_redirect_response(response, "https://evil.com")
                if result["vulnerable"]:
                    findings.append({
                        "type": "OPEN_REDIRECT",
                        "subtype": result["type"],
                        "url": test_url,
                        "endpoint": endpoint,
                        "evidence": result["evidence"],
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "description": (
                            f"Open redirect found at common endpoint. "
                            f"This endpoint allows redirecting users to arbitrary URLs."
                        ),
                        "remediation": (
                            "Remove or restrict access to redirect endpoints. "
                            "Implement strict URL validation."
                        ),
                        "owasp": "A01:2021",
                        "cwe": "CWE-601",
                    })
        
        return findings


def get_scanner(timeout: int = 10, user_agent: str = None) -> OpenRedirectScanner:
    """Get an Open Redirect scanner instance"""
    return OpenRedirectScanner(timeout=timeout, user_agent=user_agent)
