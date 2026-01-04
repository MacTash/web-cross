"""
Tests for core performance modules
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, '/home/anomaly/Extra1/aiprojects/web-cross')


class TestRateLimiter:
    """Tests for Rate Limiter"""

    def test_initialization(self):
        """Test rate limiter initializes correctly"""
        from core.rate_limiter import RateLimiter
        limiter = RateLimiter(requests_per_second=10, burst_size=20)

        assert limiter.rate == 10
        assert limiter.burst == 20
        assert limiter.enabled

    def test_try_acquire(self):
        """Test non-blocking token acquisition"""
        from core.rate_limiter import RateLimiter
        limiter = RateLimiter(requests_per_second=100, burst_size=10)

        # Should succeed for first few requests
        for _ in range(5):
            assert limiter.try_acquire()

    def test_disabled_limiter(self):
        """Test disabled rate limiter always allows"""
        from core.rate_limiter import RateLimiter
        limiter = RateLimiter(enabled=False)

        # Should always succeed when disabled
        for _ in range(100):
            assert limiter.try_acquire()

    def test_available_tokens(self):
        """Test token count tracking"""
        from core.rate_limiter import RateLimiter
        limiter = RateLimiter(requests_per_second=100, burst_size=10)

        initial = limiter.available_tokens
        limiter.try_acquire()
        after = limiter.available_tokens

        assert after < initial


class TestResponseCache:
    """Tests for Response Cache"""

    def test_initialization(self):
        """Test cache initializes correctly"""
        from core.cache import ResponseCache
        cache = ResponseCache(ttl=3600, max_memory_items=1000)

        assert cache.default_ttl == 3600
        assert cache.max_memory_items == 1000

    def test_set_and_get(self):
        """Test setting and getting cached responses"""
        from core.cache import ResponseCache
        cache = ResponseCache()

        cache.set(
            url="http://example.com",
            method="GET",
            status_code=200,
            headers={"Content-Type": "text/html"},
            content="<html>test</html>",
        )

        entry = cache.get("http://example.com", "GET")
        assert entry is not None
        assert entry.status_code == 200
        assert entry.content == "<html>test</html>"

    def test_cache_miss(self):
        """Test cache miss returns None"""
        from core.cache import ResponseCache
        cache = ResponseCache()

        entry = cache.get("http://notcached.com", "GET")
        assert entry is None

    def test_cache_disabled(self):
        """Test disabled cache doesn't store"""
        from core.cache import ResponseCache
        cache = ResponseCache(enabled=False)

        cache.set(
            url="http://example.com",
            method="GET",
            status_code=200,
            headers={},
            content="test",
        )

        entry = cache.get("http://example.com", "GET")
        assert entry is None

    def test_clear(self):
        """Test cache clearing"""
        from core.cache import ResponseCache
        cache = ResponseCache()

        cache.set("http://example.com", "GET", 200, {}, "test")
        cache.clear()

        entry = cache.get("http://example.com", "GET")
        assert entry is None


class TestScanStateManager:
    """Tests for Scan State Manager"""

    def test_create_scan(self):
        """Test creating a new scan state"""
        from core.state_manager import ScanStateManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScanStateManager(state_dir=Path(tmpdir))

            state = manager.create_scan(
                scan_id="test-scan-1",
                target_url="http://example.com",
                scan_mode="full",
            )

            assert state.scan_id == "test-scan-1"
            assert state.target_url == "http://example.com"
            assert state.phase == "pending"

    def test_update_phase(self):
        """Test updating scan phase"""
        from core.state_manager import ScanStateManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScanStateManager(state_dir=Path(tmpdir))
            manager.create_scan("test-scan", "http://example.com")

            state = manager.update_phase("test-scan", "scanning", progress=50.0)

            assert state.phase == "scanning"
            assert state.progress_percent == 50.0

    def test_add_finding(self):
        """Test adding a finding"""
        from core.state_manager import ScanStateManager

        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ScanStateManager(state_dir=Path(tmpdir))
            manager.create_scan("test-scan", "http://example.com")

            finding = {"type": "XSS", "url": "http://example.com/test"}
            state = manager.add_finding("test-scan", finding)

            assert len(state.findings) == 1
            assert state.findings[0]["type"] == "XSS"


class TestHTTPClient:
    """Tests for Async HTTP Client"""

    def test_initialization(self):
        """Test HTTP client initializes correctly"""
        from core.http_client import AsyncHTTPClient
        client = AsyncHTTPClient(timeout=15, max_connections=50)

        assert client.timeout == 15
        assert client.max_connections == 50

    def test_default_headers(self):
        """Test default headers are set"""
        from core.http_client import AsyncHTTPClient
        client = AsyncHTTPClient(user_agent="TestAgent/1.0")

        headers = client._get_default_headers()
        assert headers["User-Agent"] == "TestAgent/1.0"


class TestHTTPResponse:
    """Tests for HTTP Response wrapper"""

    def test_ok_property(self):
        """Test ok property"""
        from core.http_client import HTTPResponse

        ok_response = HTTPResponse(
            url="http://example.com",
            status_code=200,
            headers={},
            text="OK",
            content=b"OK",
            elapsed=0.1,
        )
        assert ok_response.ok

        error_response = HTTPResponse(
            url="http://example.com",
            status_code=500,
            headers={},
            text="Error",
            content=b"Error",
            elapsed=0.1,
        )
        assert not error_response.ok


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
