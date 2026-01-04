"""CSRF (Cross-Site Request Forgery) Scanner Module"""

from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class CSRFScanner:
    """Cross-Site Request Forgery vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # Common CSRF token field names
        self.token_names = [
            'csrf', 'csrf_token', 'csrftoken', 'csrf-token',
            '_csrf', '_token', 'token', 'authenticity_token',
            '__RequestVerificationToken', 'anti-csrf-token',
            'formToken', 'form_token', 'xsrf', 'xsrf_token',
            '_xsrf', 'anticsrf', 'security_token', 'sec_token',
            'nonce', '_wpnonce', 'verify', 'verification'
        ]

        # Sensitive actions that should have CSRF protection
        self.sensitive_actions = [
            'login', 'logout', 'signin', 'signout', 'register',
            'password', 'change', 'update', 'delete', 'remove',
            'transfer', 'payment', 'pay', 'checkout', 'order',
            'submit', 'post', 'create', 'new', 'add', 'edit',
            'profile', 'settings', 'account', 'admin', 'config'
        ]

    def _make_request(self, url: str) -> requests.Response | None:
        """Make HTTP request"""
        try:
            headers = {"User-Agent": self.user_agent}
            return requests.get(url, headers=headers, timeout=self.timeout, verify=False)
        except Exception:
            return None

    def _is_sensitive_form(self, form: BeautifulSoup, action: str) -> bool:
        """Check if form performs sensitive action"""
        # Check action URL
        action_lower = action.lower()
        for sensitive in self.sensitive_actions:
            if sensitive in action_lower:
                return True

        # Check form fields
        form_text = str(form).lower()
        sensitive_fields = ['password', 'email', 'credit', 'card', 'amount', 'transfer']
        for field in sensitive_fields:
            if field in form_text:
                return True

        # Check for POST method (more likely to be state-changing)
        method = form.get('method', 'get').lower()
        if method == 'post':
            return True

        return False

    def _has_csrf_token(self, form: BeautifulSoup) -> dict[str, Any]:
        """Check if form has CSRF token"""
        result = {
            "has_token": False,
            "token_name": None,
            "token_type": None
        }

        # Check hidden inputs
        for inp in form.find_all('input', type='hidden'):
            name = inp.get('name', '').lower()
            for token_name in self.token_names:
                if token_name in name:
                    result["has_token"] = True
                    result["token_name"] = inp.get('name')
                    result["token_type"] = "hidden_input"
                    return result

        # Check meta tags in parent document (common for SPA)
        # This would need the full page context

        return result

    def _check_samesite_cookie(self, response: requests.Response) -> list[dict]:
        """Check for SameSite cookie attribute"""
        findings = []

        cookies = response.headers.get('Set-Cookie', '')
        if not cookies:
            return findings

        # Check each cookie
        cookie_parts = cookies.split(',')
        for cookie in cookie_parts:
            cookie_lower = cookie.lower()

            # Check if session/auth cookie
            is_session = any(s in cookie_lower for s in ['session', 'auth', 'token', 'login'])

            if is_session:
                if 'samesite=strict' not in cookie_lower and 'samesite=lax' not in cookie_lower:
                    findings.append({
                        "type": "MISSING_SAMESITE",
                        "evidence": "Session cookie missing SameSite attribute",
                        "cookie": cookie.split(';')[0] if ';' in cookie else cookie[:50],
                        "confidence": "MEDIUM"
                    })

                if 'httponly' not in cookie_lower:
                    findings.append({
                        "type": "MISSING_HTTPONLY",
                        "evidence": "Session cookie missing HttpOnly flag",
                        "cookie": cookie.split(';')[0] if ';' in cookie else cookie[:50],
                        "confidence": "MEDIUM"
                    })

                if 'secure' not in cookie_lower:
                    findings.append({
                        "type": "MISSING_SECURE",
                        "evidence": "Session cookie missing Secure flag",
                        "cookie": cookie.split(';')[0] if ';' in cookie else cookie[:50],
                        "confidence": "LOW"
                    })

        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan a URL for CSRF vulnerabilities"""
        findings = []

        response = self._make_request(url)
        if not response:
            return findings

        # Check cookies
        cookie_findings = self._check_samesite_cookie(response)
        for finding in cookie_findings:
            finding["url"] = url
        findings.extend(cookie_findings)

        # Parse HTML for forms
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            action = form.get('action', '')
            if not action:
                action = url
            elif not action.startswith(('http://', 'https://')):
                action = urljoin(url, action)

            method = form.get('method', 'get').lower()

            # Only check POST forms or sensitive GET forms
            if method != 'post' and not self._is_sensitive_form(form, action):
                continue

            # Check for CSRF token
            token_info = self._has_csrf_token(form)

            if not token_info["has_token"] and self._is_sensitive_form(form, action):
                findings.append({
                    "type": "CSRF_NO_TOKEN",
                    "url": url,
                    "form_action": action,
                    "method": method.upper(),
                    "evidence": "Sensitive form without CSRF token",
                    "confidence": "HIGH"
                })

        # Check for anti-CSRF headers
        if 'X-CSRF-Token' not in response.headers and 'X-XSRF-TOKEN' not in response.headers:
            # Not necessarily a vulnerability, just noting
            pass

        return findings

    def scan_form(self, url: str, form: dict) -> list[dict[str, Any]]:
        """Scan a specific form for CSRF vulnerabilities"""
        findings = []

        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})

        # Check if any input looks like a CSRF token
        has_token = False
        for field_name in inputs:
            for token_name in self.token_names:
                if token_name in field_name.lower():
                    has_token = True
                    break

        if not has_token and method == 'POST':
            # Check if this is a sensitive action
            action_lower = action.lower()
            for sensitive in self.sensitive_actions:
                if sensitive in action_lower:
                    findings.append({
                        "type": "CSRF_NO_TOKEN",
                        "url": url,
                        "form_action": action,
                        "method": method,
                        "evidence": f"Sensitive form ({sensitive}) without CSRF token",
                        "confidence": "HIGH"
                    })
                    break

        return findings
