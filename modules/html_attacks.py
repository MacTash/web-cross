"""HTML Attack Scanner Module"""

import re
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


class HTMLAttackScanner:
    """HTML-based attack vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # HTML injection payloads
        self.html_payloads = [
            "<h1>INJECTED</h1>",
            "<div style='color:red'>INJECTED</div>",
            "<marquee>INJECTED</marquee>",
            "<u>INJECTED</u>",
            "<b>INJECTED</b>",
            "<!--INJECTED-->",
            "<form action='http://evil.com'><input type='submit'></form>",
            "<base href='http://evil.com'>",
            "<meta http-equiv='refresh' content='0;url=http://evil.com'>",
        ]

        # Clickjacking indicators
        self.frame_headers = ['X-Frame-Options', 'Content-Security-Policy']

    def _make_request(self, url: str, method: str = "GET",
                      data: dict = None, params: dict = None) -> requests.Response | None:
        """Make HTTP request"""
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

    def _check_html_injection(self, response: requests.Response, payload: str) -> dict | None:
        """Check if HTML payload is reflected"""
        if not response:
            return None

        content = response.text

        # Check if payload appears unencoded
        if payload in content:
            return {
                "type": "HTML_INJECTION",
                "payload": payload,
                "evidence": "HTML payload reflected without encoding",
                "confidence": "HIGH"
            }

        return None

    def _check_clickjacking(self, response: requests.Response, url: str) -> list[dict]:
        """Check for clickjacking vulnerabilities"""
        findings = []

        if not response:
            return findings

        headers = response.headers

        # Check X-Frame-Options
        xfo = headers.get('X-Frame-Options', '').upper()
        if not xfo:
            findings.append({
                "type": "CLICKJACKING",
                "url": url,
                "evidence": "Missing X-Frame-Options header",
                "confidence": "MEDIUM"
            })
        elif xfo not in ['DENY', 'SAMEORIGIN']:
            findings.append({
                "type": "CLICKJACKING",
                "url": url,
                "evidence": f"Weak X-Frame-Options: {xfo}",
                "confidence": "LOW"
            })

        # Check CSP frame-ancestors
        csp = headers.get('Content-Security-Policy', '')
        if csp and 'frame-ancestors' not in csp.lower():
            findings.append({
                "type": "CLICKJACKING",
                "url": url,
                "evidence": "CSP present but missing frame-ancestors directive",
                "confidence": "LOW"
            })

        return findings

    def _check_form_hijacking(self, soup: BeautifulSoup, url: str) -> list[dict]:
        """Check for form hijacking vulnerabilities"""
        findings = []

        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')

            # Check for external form actions
            if action:
                parsed_action = urlparse(action)
                parsed_url = urlparse(url)

                if parsed_action.netloc and parsed_action.netloc != parsed_url.netloc:
                    findings.append({
                        "type": "EXTERNAL_FORM_ACTION",
                        "url": url,
                        "form_action": action,
                        "evidence": "Form submits to external domain",
                        "confidence": "MEDIUM"
                    })

            # Check for forms without action (submits to current page)
            if not action:
                # Not necessarily a vulnerability, but worth noting
                pass

            # Check for autocomplete on sensitive fields
            for inp in form.find_all('input'):
                inp_type = inp.get('type', '').lower()
                inp_name = inp.get('name', '').lower()
                autocomplete = inp.get('autocomplete', '')

                if inp_type == 'password' and autocomplete != 'off':
                    findings.append({
                        "type": "AUTOCOMPLETE_PASSWORD",
                        "url": url,
                        "field": inp.get('name', 'unknown'),
                        "evidence": "Password field allows autocomplete",
                        "confidence": "LOW"
                    })

                if any(s in inp_name for s in ['credit', 'card', 'cvv', 'ssn']):
                    if autocomplete != 'off':
                        findings.append({
                            "type": "AUTOCOMPLETE_SENSITIVE",
                            "url": url,
                            "field": inp.get('name', 'unknown'),
                            "evidence": "Sensitive field allows autocomplete",
                            "confidence": "LOW"
                        })

        return findings

    def _check_base_tag_injection(self, response: requests.Response, url: str) -> list[dict]:
        """Check for base tag that could be exploited"""
        findings = []

        if not response:
            return findings

        soup = BeautifulSoup(response.text, 'html.parser')
        base_tags = soup.find_all('base')

        for base in base_tags:
            href = base.get('href', '')
            if href:
                parsed_base = urlparse(href)
                parsed_url = urlparse(url)

                if parsed_base.netloc and parsed_base.netloc != parsed_url.netloc:
                    findings.append({
                        "type": "SUSPICIOUS_BASE_TAG",
                        "url": url,
                        "base_href": href,
                        "evidence": "Base tag points to external domain",
                        "confidence": "HIGH"
                    })

        return findings

    def _check_open_redirect(self, soup: BeautifulSoup, url: str) -> list[dict]:
        """Check for potential open redirect vulnerabilities"""
        findings = []

        # Check meta refresh tags
        for meta in soup.find_all('meta', attrs={'http-equiv': re.compile('refresh', re.I)}):
            content = meta.get('content', '')
            if 'url=' in content.lower():
                redirect_url = content.split('url=')[-1].strip()
                if redirect_url.startswith(('http://', 'https://', '//')):
                    parsed_redirect = urlparse(redirect_url)
                    parsed_url = urlparse(url)
                    if parsed_redirect.netloc and parsed_redirect.netloc != parsed_url.netloc:
                        findings.append({
                            "type": "META_REDIRECT_EXTERNAL",
                            "url": url,
                            "redirect_to": redirect_url,
                            "evidence": "Meta refresh redirects to external domain",
                            "confidence": "MEDIUM"
                        })

        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan a URL for HTML-based attack vulnerabilities"""
        findings = []

        response = self._make_request(url)
        if not response:
            return findings

        soup = BeautifulSoup(response.text, 'html.parser')

        # Check clickjacking
        findings.extend(self._check_clickjacking(response, url))

        # Check form hijacking
        findings.extend(self._check_form_hijacking(soup, url))

        # Check base tag
        findings.extend(self._check_base_tag_injection(response, url))

        # Check open redirect
        findings.extend(self._check_open_redirect(soup, url))

        return findings

    def scan_form(self, url: str, form: dict) -> list[dict[str, Any]]:
        """Scan a form for HTML injection"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})

        if not inputs:
            return findings

        for field_name in inputs:
            for payload in self.html_payloads[:5]:
                test_data = inputs.copy()
                test_data[field_name] = payload

                if method == "GET":
                    response = self._make_request(action, params=test_data)
                else:
                    response = self._make_request(action, method="POST", data=test_data)

                result = self._check_html_injection(response, payload)
                if result:
                    result["parameter"] = field_name
                    result["url"] = action
                    result["method"] = method
                    findings.append(result)
                    break

        return findings
