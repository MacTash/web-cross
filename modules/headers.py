"""Security Headers Scanner Module"""

import requests
from typing import List, Dict, Any, Optional


class HeaderScanner:
    """Security headers vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        
        # Security headers and their expected values
        self.security_headers = {
            "Strict-Transport-Security": {
                "required": True,
                "check": self._check_hsts,
                "severity": "HIGH"
            },
            "Content-Security-Policy": {
                "required": True,
                "check": self._check_csp,
                "severity": "HIGH"
            },
            "X-Content-Type-Options": {
                "required": True,
                "expected": "nosniff",
                "severity": "MEDIUM"
            },
            "X-Frame-Options": {
                "required": True,
                "expected": ["DENY", "SAMEORIGIN"],
                "severity": "MEDIUM"
            },
            "X-XSS-Protection": {
                "required": False,  # Deprecated but still useful
                "expected": "1; mode=block",
                "severity": "LOW"
            },
            "Referrer-Policy": {
                "required": True,
                "expected": [
                    "no-referrer",
                    "no-referrer-when-downgrade",
                    "strict-origin",
                    "strict-origin-when-cross-origin"
                ],
                "severity": "LOW"
            },
            "Permissions-Policy": {
                "required": False,
                "check": self._check_permissions_policy,
                "severity": "LOW"
            },
            "Cross-Origin-Embedder-Policy": {
                "required": False,
                "expected": ["require-corp", "credentialless"],
                "severity": "LOW"
            },
            "Cross-Origin-Opener-Policy": {
                "required": False,
                "expected": ["same-origin", "same-origin-allow-popups"],
                "severity": "LOW"
            },
            "Cross-Origin-Resource-Policy": {
                "required": False,
                "expected": ["same-origin", "same-site", "cross-origin"],
                "severity": "LOW"
            }
        }
        
        # Dangerous headers that shouldn't be exposed
        self.dangerous_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
        ]
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make HTTP request"""
        try:
            headers = {"User-Agent": self.user_agent}
            return requests.get(url, headers=headers, timeout=self.timeout, 
                              verify=False, allow_redirects=True)
        except Exception:
            return None
    
    def _check_hsts(self, value: str) -> Dict:
        """Check HSTS header configuration"""
        result = {"valid": True, "issues": []}
        
        if not value:
            result["valid"] = False
            result["issues"].append("HSTS header missing")
            return result
        
        value_lower = value.lower()
        
        # Check max-age
        if "max-age=" not in value_lower:
            result["valid"] = False
            result["issues"].append("Missing max-age directive")
        else:
            try:
                max_age = int(value_lower.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:  # Less than 1 year
                    result["issues"].append(f"max-age too short ({max_age}s, recommended: 31536000)")
            except ValueError:
                result["issues"].append("Invalid max-age value")
        
        # Check for includeSubDomains
        if "includesubdomains" not in value_lower:
            result["issues"].append("Missing includeSubDomains directive")
        
        # Check for preload
        if "preload" not in value_lower:
            result["issues"].append("Missing preload directive (recommended)")
        
        return result
    
    def _check_csp(self, value: str) -> Dict:
        """Check CSP header configuration"""
        result = {"valid": True, "issues": []}
        
        if not value:
            result["valid"] = False
            result["issues"].append("CSP header missing")
            return result
        
        value_lower = value.lower()
        
        # Check for dangerous directives
        if "'unsafe-inline'" in value_lower:
            result["issues"].append("Contains 'unsafe-inline' (XSS risk)")
        
        if "'unsafe-eval'" in value_lower:
            result["issues"].append("Contains 'unsafe-eval' (XSS risk)")
        
        if "data:" in value_lower and "script-src" in value_lower:
            result["issues"].append("Allows data: URIs in scripts (XSS risk)")
        
        # Check for default-src
        if "default-src" not in value_lower:
            result["issues"].append("Missing default-src directive")
        
        # Check for script-src
        if "script-src" not in value_lower and "default-src" not in value_lower:
            result["issues"].append("No script-src or default-src defined")
        
        # Check for wildcard
        if "script-src *" in value_lower or "default-src *" in value_lower:
            result["valid"] = False
            result["issues"].append("Wildcard (*) in script sources is dangerous")
        
        return result
    
    def _check_permissions_policy(self, value: str) -> Dict:
        """Check Permissions-Policy header"""
        result = {"valid": True, "issues": []}
        
        if not value:
            result["issues"].append("Permissions-Policy not set (recommended)")
            return result
        
        # Check for dangerous permissions enabled
        dangerous_features = ["camera", "microphone", "geolocation", "payment"]
        value_lower = value.lower()
        
        for feature in dangerous_features:
            if f"{feature}=*" in value_lower or f"{feature}=()" not in value_lower:
                if f"{feature}=self" not in value_lower and f"{feature}=(self)" not in value_lower:
                    result["issues"].append(f"{feature} permission may be too permissive")
        
        return result
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Scan a URL for security header issues"""
        findings = []
        
        response = self._make_request(url)
        if not response:
            return findings
        
        headers = response.headers
        
        # Check required security headers
        for header_name, config in self.security_headers.items():
            header_value = headers.get(header_name, "")
            
            if config.get("check"):
                # Custom check function
                check_result = config["check"](header_value)
                if not check_result["valid"] or check_result["issues"]:
                    # Build explicit evidence
                    issues_str = "; ".join(check_result["issues"]) if check_result["issues"] else "Configuration issue"
                    evidence = f"{header_name}: {issues_str}"
                    if header_value:
                        evidence += f" (Current: '{header_value[:80]}')"
                    findings.append({
                        "type": "HEADER_MISCONFIGURATION" if header_value else "MISSING_HEADER",
                        "url": url,
                        "header": header_name,
                        "current_value": header_value[:100] if header_value else None,
                        "evidence": evidence,
                        "confidence": "HIGH" if not check_result["valid"] else "MEDIUM",
                        "severity": config["severity"]
                    })
            elif config.get("required"):
                if not header_value:
                    findings.append({
                        "type": "MISSING_HEADER",
                        "url": url,
                        "header": header_name,
                        "expected": config.get("expected"),
                        "evidence": f"Missing {header_name} header",
                        "confidence": "HIGH",
                        "severity": config["severity"]
                    })
                elif config.get("expected"):
                    expected = config["expected"]
                    if isinstance(expected, list):
                        if header_value.upper() not in [e.upper() for e in expected]:
                            findings.append({
                                "type": "HEADER_MISCONFIGURATION",
                                "url": url,
                                "header": header_name,
                                "current_value": header_value,
                                "expected": expected,
                                "evidence": f"Unexpected value for {header_name}",
                                "confidence": "MEDIUM",
                                "severity": config["severity"]
                            })
                    elif header_value.lower() != expected.lower():
                        findings.append({
                            "type": "HEADER_MISCONFIGURATION",
                            "url": url,
                            "header": header_name,
                            "current_value": header_value,
                            "expected": expected,
                            "evidence": f"Unexpected value for {header_name}",
                            "confidence": "MEDIUM",
                            "severity": config["severity"]
                        })
        
        # Check for information disclosure headers
        for header_name in self.dangerous_headers:
            if header_name in headers:
                header_val = headers[header_name]
                findings.append({
                    "type": "INFORMATION_DISCLOSURE",
                    "url": url,
                    "header": header_name,
                    "current_value": header_val,
                    "evidence": f"{header_name}: '{header_val}' - Reveals server/technology info",
                    "confidence": "MEDIUM",
                    "severity": "LOW"
                })
        
        # Check for missing cache control on sensitive pages
        cache_control = headers.get("Cache-Control", "")
        if not cache_control or "no-store" not in cache_control.lower():
            # Check if this looks like a sensitive page
            if any(s in url.lower() for s in ["/login", "/admin", "/account", "/profile", "/dashboard"]):
                findings.append({
                    "type": "INSECURE_CACHING",
                    "url": url,
                    "header": "Cache-Control",
                    "current_value": cache_control or None,
                    "evidence": "Sensitive page may be cached",
                    "confidence": "MEDIUM",
                    "severity": "MEDIUM"
                })
        
        return findings
