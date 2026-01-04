"""Web-Cross Test Package"""

import pytest


@pytest.fixture
def sample_findings():
    """Sample vulnerability findings for testing"""
    return [
        {
            "type": "SQL_INJECTION",
            "url": "http://example.com/api/users?id=1",
            "parameter": "id",
            "severity": "HIGH",
            "severity_label": "HIGH",
            "confidence": "HIGH",
            "evidence": "SQL syntax error in query",
            "description": "SQL injection vulnerability detected",
            "remediation": "Use parameterized queries",
        },
        {
            "type": "XSS",
            "url": "http://example.com/search?q=test",
            "parameter": "q",
            "severity": "MEDIUM",
            "severity_label": "MEDIUM",
            "confidence": "MEDIUM",
            "evidence": "<script>alert(1)</script>",
            "description": "Reflected XSS vulnerability",
            "remediation": "Encode output and use CSP",
        },
        {
            "type": "OPEN_REDIRECT",
            "url": "http://example.com/redirect?url=http://evil.com",
            "parameter": "url",
            "severity": "MEDIUM",
            "severity_label": "MEDIUM",
            "confidence": "HIGH",
            "evidence": "Redirects to external domain",
            "description": "Open redirect vulnerability",
            "remediation": "Validate redirect URLs",
        },
    ]


@pytest.fixture
def sample_target():
    """Sample target URL"""
    return "http://testphp.vulnweb.com"


@pytest.fixture
def sample_scan_info():
    """Sample scan information"""
    return {
        "mode": "full",
        "ai_enabled": True,
        "threads": 10,
        "duration": "00:05:30",
    }
