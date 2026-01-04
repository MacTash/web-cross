"""
API Rate Limiting Scanner Module
Tests for missing or weak rate limiting protections.
"""

import time
import threading
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests


class RateLimitingScanner:
    """
    API Rate Limiting vulnerability scanner.
    
    Detects:
    - Missing rate limiting on sensitive endpoints
    - Weak rate limiting thresholds
    - Rate limit bypass techniques
    - Brute-force susceptibility
    - Resource exhaustion vulnerabilities
    """
    
    # Sensitive endpoints that should have rate limiting
    SENSITIVE_ENDPOINTS = [
        # Authentication
        "/login",
        "/signin",
        "/auth",
        "/authenticate",
        "/api/login",
        "/api/auth",
        "/oauth/token",
        # Password reset
        "/password/reset",
        "/forgot-password",
        "/api/password/reset",
        "/reset-password",
        # Registration
        "/register",
        "/signup",
        "/api/register",
        "/api/users",
        # OTP/2FA
        "/verify",
        "/otp",
        "/2fa",
        "/verify-otp",
        "/api/verify",
        # API endpoints
        "/api/v1/",
        "/api/v2/",
        "/graphql",
        # Sensitive actions
        "/transfer",
        "/payment",
        "/checkout",
        "/api/transfer",
    ]
    
    # Headers that indicate rate limiting
    RATE_LIMIT_HEADERS = [
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "X-Rate-Limit-Limit",
        "X-Rate-Limit-Remaining",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        "Retry-After",
        "X-Retry-After",
    ]
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })
        
        # Rate limit testing parameters
        self.test_requests_count = 20
        self.concurrent_threads = 5
        self.request_delay = 0.1  # 100ms between requests
    
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
            elif method.upper() == "POST":
                return self.session.post(
                    url, 
                    data=data or {},
                    timeout=self.timeout,
                    headers=req_headers,
                    verify=False,
                )
            else:
                return self.session.request(
                    method.upper(),
                    url,
                    data=data,
                    timeout=self.timeout,
                    headers=req_headers,
                    verify=False,
                )
        except requests.RequestException:
            return None
    
    def _detect_rate_limit_headers(
        self, 
        response: requests.Response,
    ) -> Dict[str, Any]:
        """Detect rate limiting headers in response"""
        detected = {}
        
        for header in self.RATE_LIMIT_HEADERS:
            value = response.headers.get(header)
            if value:
                detected[header] = value
        
        return detected
    
    def _is_rate_limited_response(
        self, 
        response: requests.Response,
    ) -> bool:
        """Check if response indicates rate limiting"""
        # Check status code
        if response.status_code == 429:
            return True
        
        # Check for rate limit in response body
        rate_limit_indicators = [
            "rate limit",
            "too many requests",
            "slow down",
            "exceeded",
            "throttl",
            "quota",
        ]
        
        body_lower = response.text.lower()
        for indicator in rate_limit_indicators:
            if indicator in body_lower:
                return True
        
        return False
    
    def _test_rapid_requests(
        self, 
        url: str, 
        method: str = "POST",
        data: Dict = None,
    ) -> Dict[str, Any]:
        """Send rapid requests to test rate limiting"""
        results = {
            "total_requests": 0,
            "successful": 0,
            "rate_limited": 0,
            "errors": 0,
            "response_times": [],
            "rate_limit_headers": {},
            "first_rate_limit_at": None,
        }
        
        def send_request(i: int) -> Dict:
            start_time = time.time()
            response = self._make_request(url, method=method, data=data)
            elapsed = time.time() - start_time
            
            if response is None:
                return {"success": False, "rate_limited": False, "time": elapsed}
            
            rate_limited = self._is_rate_limited_response(response)
            headers = self._detect_rate_limit_headers(response)
            
            return {
                "success": response.status_code < 400 or response.status_code == 429,
                "rate_limited": rate_limited,
                "status_code": response.status_code,
                "time": elapsed,
                "headers": headers,
                "request_num": i,
            }
        
        # Send requests with some concurrency
        with ThreadPoolExecutor(max_workers=self.concurrent_threads) as executor:
            futures = []
            for i in range(self.test_requests_count):
                futures.append(executor.submit(send_request, i))
                time.sleep(self.request_delay)  # Small delay between submissions
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results["total_requests"] += 1
                    results["response_times"].append(result["time"])
                    
                    if result.get("rate_limited"):
                        results["rate_limited"] += 1
                        if results["first_rate_limit_at"] is None:
                            results["first_rate_limit_at"] = result.get("request_num")
                    elif result.get("success"):
                        results["successful"] += 1
                    else:
                        results["errors"] += 1
                    
                    if result.get("headers"):
                        results["rate_limit_headers"].update(result["headers"])
                        
                except Exception:
                    results["errors"] += 1
        
        return results
    
    def _analyze_rate_limit_results(
        self, 
        url: str,
        results: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Analyze rate limiting test results"""
        findings = []
        
        has_rate_limiting = results["rate_limited"] > 0
        has_rate_limit_headers = bool(results["rate_limit_headers"])
        
        if not has_rate_limiting and not has_rate_limit_headers:
            # No rate limiting detected
            findings.append({
                "type": "MISSING_RATE_LIMITING",
                "url": url,
                "evidence": (
                    f"Sent {results['total_requests']} requests with "
                    f"{results['successful']} successful responses. "
                    f"No rate limiting detected."
                ),
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "description": (
                    "No rate limiting detected on this endpoint. "
                    "This may allow brute-force attacks, credential stuffing, "
                    "or API abuse."
                ),
                "remediation": (
                    "Implement rate limiting on all sensitive endpoints. "
                    "Use sliding window or token bucket algorithms. "
                    "Return 429 Too Many Requests with Retry-After header."
                ),
                "owasp": "A07:2021",
                "cwe": "CWE-770",
            })
        
        elif has_rate_limiting:
            # Rate limiting exists but check threshold
            threshold = results["first_rate_limit_at"]
            
            if threshold and threshold > 10:
                # High threshold - might be weak
                findings.append({
                    "type": "WEAK_RATE_LIMITING",
                    "url": url,
                    "evidence": (
                        f"Rate limiting triggered after {threshold} requests. "
                        f"This threshold may be too high for sensitive endpoints."
                    ),
                    "severity": "LOW",
                    "confidence": "MEDIUM",
                    "description": (
                        f"Rate limiting is present but allows {threshold} requests "
                        f"before triggering. For authentication endpoints, this "
                        f"may still allow brute-force attempts."
                    ),
                    "remediation": (
                        "Consider lower rate limits for authentication endpoints "
                        "(e.g., 5-10 attempts per minute). "
                        "Implement progressive delays or account lockout."
                    ),
                    "owasp": "A07:2021",
                    "cwe": "CWE-307",
                })
        
        return findings
    
    def _check_rate_limit_bypass(
        self, 
        url: str,
        method: str = "POST",
    ) -> List[Dict[str, Any]]:
        """Test for rate limit bypass techniques"""
        findings = []
        
        # First, verify rate limiting exists
        initial_test = self._test_rapid_requests(url, method)
        if initial_test["rate_limited"] == 0:
            return findings  # No rate limiting to bypass
        
        # Bypass techniques to test
        bypass_techniques = [
            {
                "name": "X-Forwarded-For",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
            },
            {
                "name": "X-Real-IP",
                "headers": {"X-Real-IP": "10.0.0.1"},
            },
            {
                "name": "X-Originating-IP",
                "headers": {"X-Originating-IP": "192.168.1.1"},
            },
            {
                "name": "Client-IP",
                "headers": {"Client-IP": "172.16.0.1"},
            },
            {
                "name": "X-Client-IP",
                "headers": {"X-Client-IP": "8.8.8.8"},
            },
        ]
        
        for technique in bypass_techniques:
            # Test with bypass headers
            bypass_response = self._make_request(
                url, 
                method=method, 
                headers=technique["headers"],
            )
            
            if bypass_response and not self._is_rate_limited_response(bypass_response):
                # Potential bypass - test with rapid requests
                time.sleep(1)  # Wait before testing
                
                # Make several requests with bypass header
                bypass_count = 0
                for _ in range(5):
                    resp = self._make_request(
                        url, 
                        method=method, 
                        headers=technique["headers"],
                    )
                    if resp and not self._is_rate_limited_response(resp):
                        bypass_count += 1
                
                if bypass_count >= 4:
                    findings.append({
                        "type": "RATE_LIMIT_BYPASS",
                        "url": url,
                        "technique": technique["name"],
                        "headers": technique["headers"],
                        "evidence": (
                            f"Rate limiting bypassed using {technique['name']} header. "
                            f"{bypass_count}/5 requests succeeded after rate limit."
                        ),
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "description": (
                            f"Rate limiting can be bypassed using the {technique['name']} header. "
                            f"Attackers can reset their rate limit by spoofing IP addresses."
                        ),
                        "remediation": (
                            "Do not trust client-supplied IP headers for rate limiting. "
                            "Use the actual connection IP address. "
                            "If behind a proxy, only trust headers from known proxy IPs."
                        ),
                        "owasp": "A07:2021",
                        "cwe": "CWE-770",
                    })
        
        return findings
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a URL for rate limiting vulnerabilities.
        
        Args:
            url: Target URL to scan
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        # Initial request to check if endpoint exists
        response = self._make_request(url)
        if not response:
            return findings
        
        # Check for rate limit headers on single request
        headers = self._detect_rate_limit_headers(response)
        if not headers:
            # No rate limit headers - might be missing rate limiting
            pass
        
        # Test with rapid requests
        test_results = self._test_rapid_requests(url)
        findings.extend(self._analyze_rate_limit_results(url, test_results))
        
        return findings
    
    def scan_sensitive_endpoints(
        self, 
        base_url: str,
    ) -> List[Dict[str, Any]]:
        """
        Scan known sensitive endpoints for rate limiting.
        
        Args:
            base_url: Base URL of the target
        
        Returns:
            List of vulnerability findings
        """
        findings = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in self.SENSITIVE_ENDPOINTS:
            url = urljoin(base, endpoint)
            
            # Check if endpoint exists
            response = self._make_request(url)
            if not response:
                continue
            
            # Skip 404s
            if response.status_code == 404:
                continue
            
            # Determine method (POST for auth endpoints, GET for others)
            method = "POST" if any(
                auth in endpoint.lower() 
                for auth in ["login", "auth", "register", "password", "otp", "verify"]
            ) else "GET"
            
            # Test rate limiting
            test_results = self._test_rapid_requests(url, method=method)
            endpoint_findings = self._analyze_rate_limit_results(url, test_results)
            
            for finding in endpoint_findings:
                finding["endpoint"] = endpoint
                finding["method"] = method
                findings.append(finding)
            
            # Check for bypass on rate-limited endpoints
            if test_results["rate_limited"] > 0:
                bypass_findings = self._check_rate_limit_bypass(url, method)
                findings.extend(bypass_findings)
        
        return findings


def get_scanner(timeout: int = 10, user_agent: str = None) -> RateLimitingScanner:
    """Get a Rate Limiting scanner instance"""
    return RateLimitingScanner(timeout=timeout, user_agent=user_agent)
