"""
Tests for new v3.0 scanner modules
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

# Import the new modules
import sys
sys.path.insert(0, '/home/anomaly/Extra1/aiprojects/web-cross')


class TestOpenRedirectScanner:
    """Tests for Open Redirect Scanner"""
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        from modules.open_redirect import OpenRedirectScanner
        scanner = OpenRedirectScanner(timeout=5)
        assert scanner.timeout == 5
        assert scanner.canary_domain == "evil.com"
    
    def test_payload_loading(self):
        """Test payloads are loaded"""
        from modules.open_redirect import OpenRedirectScanner
        scanner = OpenRedirectScanner()
        # The scanner uses 'payloads' not 'BASE_PAYLOADS'
        assert len(scanner.payloads) > 0
    
    def test_redirect_params_defined(self):
        """Test redirect params are defined"""
        from modules.open_redirect import OpenRedirectScanner
        scanner = OpenRedirectScanner()
        assert len(scanner.REDIRECT_PARAMS) > 0
        assert "url" in scanner.REDIRECT_PARAMS
        assert "redirect" in scanner.REDIRECT_PARAMS
    
    @patch('requests.Session.get')
    def test_check_redirect_response(self, mock_get):
        """Test redirect response checking"""
        from modules.open_redirect import OpenRedirectScanner
        
        # Mock redirect response
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.headers = {'Location': 'https://evil.com/redirect'}
        mock_response.text = ""
        
        scanner = OpenRedirectScanner()
        result = scanner._check_redirect_response(mock_response, "https://evil.com")
        
        assert result["vulnerable"] == True
        assert result["type"] == "HEADER_REDIRECT"


class TestDeserializationScanner:
    """Tests for Deserialization Scanner"""
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        from modules.deserialization import DeserializationScanner
        scanner = DeserializationScanner()
        assert scanner.timeout == 10
    
    def test_php_serialization_detection(self):
        """Test PHP serialization detection"""
        from modules.deserialization import DeserializationScanner
        scanner = DeserializationScanner()
        
        result = scanner._detect_php_serialization('O:8:"stdClass":0:{}')
        assert result is not None
    
    def test_viewstate_detection(self):
        """Test .NET ViewState detection"""
        from modules.deserialization import DeserializationScanner
        scanner = DeserializationScanner()
        
        # Use correct method name: _detect_viewstate
        result = scanner._detect_viewstate(
            '<input name="__VIEWSTATE" value="abc123" />'
        )
        assert result is not None
    
    def test_signatures_defined(self):
        """Test serialization signatures are defined"""
        from modules.deserialization import DeserializationScanner
        scanner = DeserializationScanner()
        
        assert len(scanner.PHP_SIGNATURES) > 0
        assert len(scanner.JAVA_SIGNATURES) > 0


class TestRateLimitingScanner:
    """Tests for Rate Limiting Scanner"""
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        from modules.rate_limiting import RateLimitingScanner
        scanner = RateLimitingScanner()
        assert scanner.test_requests_count == 20
    
    def test_rate_limit_headers_detection(self):
        """Test rate limit header detection"""
        from modules.rate_limiting import RateLimitingScanner
        scanner = RateLimitingScanner()
        
        mock_response = Mock()
        mock_response.headers = {
            'X-RateLimit-Limit': '100',
            'X-RateLimit-Remaining': '95',
        }
        
        headers = scanner._detect_rate_limit_headers(mock_response)
        assert 'X-RateLimit-Limit' in headers
        assert headers['X-RateLimit-Limit'] == '100'
    
    def test_is_rate_limited_response(self):
        """Test rate limited response detection"""
        from modules.rate_limiting import RateLimitingScanner
        scanner = RateLimitingScanner()
        
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.text = ""
        
        assert scanner._is_rate_limited_response(mock_response) == True
    
    def test_sensitive_endpoints_defined(self):
        """Test sensitive endpoints are defined"""
        from modules.rate_limiting import RateLimitingScanner
        scanner = RateLimitingScanner()
        
        assert len(scanner.SENSITIVE_ENDPOINTS) > 0
        assert "/login" in scanner.SENSITIVE_ENDPOINTS


class TestSubdomainTakeoverScanner:
    """Tests for Subdomain Takeover Scanner"""
    
    def test_vulnerable_services_defined(self):
        """Test vulnerable services are defined"""
        from modules.subdomain_takeover import SubdomainTakeoverScanner
        scanner = SubdomainTakeoverScanner()
        
        assert len(scanner.VULNERABLE_SERVICES) > 20
        
        # Check AWS S3 is included
        s3_service = None
        for service in scanner.VULNERABLE_SERVICES:
            if service['name'] == 'AWS S3':
                s3_service = service
                break
        
        assert s3_service is not None
        assert 'NoSuchBucket' in s3_service['fingerprints']
    
    def test_subdomain_discovery(self):
        """Test subdomain discovery"""
        from modules.subdomain_takeover import SubdomainTakeoverScanner
        scanner = SubdomainTakeoverScanner()
        
        subdomains = scanner._discover_subdomains("example.com")
        assert "www.example.com" in subdomains
        assert "api.example.com" in subdomains
    
    def test_github_service_defined(self):
        """Test GitHub Pages is in services"""
        from modules.subdomain_takeover import SubdomainTakeoverScanner
        scanner = SubdomainTakeoverScanner()
        
        github_service = None
        for service in scanner.VULNERABLE_SERVICES:
            if 'GitHub' in service['name']:
                github_service = service
                break
        
        assert github_service is not None


class TestBrokenAccessScanner:
    """Tests for Broken Access Control Scanner"""
    
    def test_id_patterns_defined(self):
        """Test ID patterns are defined"""
        from modules.broken_access import BrokenAccessScanner
        scanner = BrokenAccessScanner()
        
        assert len(scanner.ID_PATTERNS) > 0
        assert len(scanner.IDOR_PARAMS) > 0
    
    def test_extract_ids_from_url(self):
        """Test ID extraction from URL"""
        from modules.broken_access import BrokenAccessScanner
        scanner = BrokenAccessScanner()
        
        ids = scanner._extract_ids_from_url(
            "http://example.com/users/123/profile?account_id=456"
        )
        
        # Should find numeric IDs
        values = [i['value'] for i in ids]
        assert '123' in values or '456' in values
    
    def test_generate_test_ids(self):
        """Test test ID generation"""
        from modules.broken_access import BrokenAccessScanner
        scanner = BrokenAccessScanner()
        
        # Numeric ID
        test_ids = scanner._generate_test_ids("100")
        assert "99" in test_ids
        assert "101" in test_ids
        assert "1" in test_ids
    
    def test_admin_endpoints_defined(self):
        """Test admin endpoints are defined"""
        from modules.broken_access import BrokenAccessScanner
        scanner = BrokenAccessScanner()
        
        assert len(scanner.ADMIN_ENDPOINTS) > 0
        assert "/admin" in scanner.ADMIN_ENDPOINTS


class TestWebSocketScanner:
    """Tests for WebSocket Scanner"""
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        from modules.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner()
        assert scanner.timeout == 10
    
    def test_test_origins_defined(self):
        """Test origins for CSWSH testing are defined"""
        from modules.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner()
        
        # Uses test_origins not MALICIOUS_ORIGINS
        assert 'null' in scanner.test_origins
        assert 'https://evil.com' in scanner.test_origins
    
    def test_xss_payloads_defined(self):
        """Test XSS payloads for message injection are defined"""
        from modules.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner()
        
        # Uses xss_payloads not XSS_PAYLOADS
        assert len(scanner.xss_payloads) > 0
        assert any('<script>' in p for p in scanner.xss_payloads)
    
    def test_sqli_payloads_defined(self):
        """Test SQLi payloads are defined"""
        from modules.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner()
        
        assert len(scanner.sqli_payloads) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
