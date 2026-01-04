"""
Async HTTP Client
High-performance HTTP client using httpx for concurrent scanning.
"""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

import requests


@dataclass
class HTTPResponse:
    """Unified HTTP response wrapper"""
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    content: bytes
    elapsed: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


class AsyncHTTPClient:
    """
    High-performance async HTTP client for vulnerability scanning.

    Features:
    - Concurrent requests with httpx
    - Rate limiting integration
    - Retry logic with tenacity
    - Fallback to synchronous requests
    """

    def __init__(
        self,
        timeout: int = 10,
        max_connections: int = 100,
        user_agent: str = None,
        verify_ssl: bool = False,
        follow_redirects: bool = True,
        retries: int = 2,
    ):
        self.timeout = timeout
        self.max_connections = max_connections
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.retries = retries

        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None
        self._requests_session: requests.Session | None = None

    def _get_default_headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    async def _get_async_client(self) -> "httpx.AsyncClient":
        """Get or create async client"""
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx not available")

        if self._async_client is None:
            limits = httpx.Limits(
                max_connections=self.max_connections,
                max_keepalive_connections=20,
            )
            self._async_client = httpx.AsyncClient(
                timeout=self.timeout,
                limits=limits,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                headers=self._get_default_headers(),
            )
        return self._async_client

    def _get_requests_session(self) -> requests.Session:
        """Get or create requests session for fallback"""
        if self._requests_session is None:
            self._requests_session = requests.Session()
            self._requests_session.headers.update(self._get_default_headers())
            self._requests_session.verify = self.verify_ssl
        return self._requests_session

    async def get(
        self,
        url: str,
        headers: dict[str, str] = None,
        params: dict[str, str] = None,
    ) -> HTTPResponse:
        """Async GET request"""
        return await self._request("GET", url, headers=headers, params=params)

    async def post(
        self,
        url: str,
        data: dict[str, Any] = None,
        json: dict[str, Any] = None,
        headers: dict[str, str] = None,
    ) -> HTTPResponse:
        """Async POST request"""
        return await self._request("POST", url, headers=headers, data=data, json=json)

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] = None,
        params: dict[str, str] = None,
        data: dict[str, Any] = None,
        json: dict[str, Any] = None,
    ) -> HTTPResponse:
        """Make async HTTP request with retry logic"""
        if not HTTPX_AVAILABLE:
            return self._sync_request(method, url, headers, params, data)

        client = await self._get_async_client()
        last_error = None

        for attempt in range(self.retries + 1):
            try:
                start = time.time()
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                )
                elapsed = time.time() - start

                return HTTPResponse(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    text=response.text,
                    content=response.content,
                    elapsed=elapsed,
                )
            except Exception as e:
                last_error = str(e)
                if attempt < self.retries:
                    await asyncio.sleep(0.5 * (attempt + 1))

        return HTTPResponse(
            url=url,
            status_code=0,
            headers={},
            text="",
            content=b"",
            elapsed=0,
            error=last_error,
        )

    def _sync_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] = None,
        params: dict[str, str] = None,
        data: dict[str, Any] = None,
    ) -> HTTPResponse:
        """Synchronous fallback request"""
        session = self._get_requests_session()

        try:
            start = time.time()
            response = session.request(
                method,
                url,
                headers=headers,
                params=params,
                data=data,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
            )
            elapsed = time.time() - start

            return HTTPResponse(
                url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                content=response.content,
                elapsed=elapsed,
            )
        except Exception as e:
            return HTTPResponse(
                url=url,
                status_code=0,
                headers={},
                text="",
                content=b"",
                elapsed=0,
                error=str(e),
            )

    async def batch_get(
        self,
        urls: list[str],
        concurrency: int = 10,
        callback: Callable[[HTTPResponse], None] = None,
    ) -> list[HTTPResponse]:
        """
        Fetch multiple URLs concurrently.

        Args:
            urls: List of URLs to fetch
            concurrency: Maximum concurrent requests
            callback: Optional callback for each response

        Returns:
            List of responses in order
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def fetch_with_semaphore(url: str) -> HTTPResponse:
            async with semaphore:
                response = await self.get(url)
                if callback:
                    callback(response)
                return response

        tasks = [fetch_with_semaphore(url) for url in urls]
        return await asyncio.gather(*tasks)

    async def close(self):
        """Close the client connections"""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None
        if self._requests_session:
            self._requests_session.close()
            self._requests_session = None

    def sync_get(self, url: str, **kwargs) -> HTTPResponse:
        """Synchronous GET request"""
        return self._sync_request("GET", url, **kwargs)

    def sync_post(self, url: str, **kwargs) -> HTTPResponse:
        """Synchronous POST request"""
        return self._sync_request("POST", url, **kwargs)


# Singleton instance
_client: AsyncHTTPClient | None = None


def get_http_client(**kwargs) -> AsyncHTTPClient:
    """Get singleton HTTP client"""
    global _client
    if _client is None:
        _client = AsyncHTTPClient(**kwargs)
    return _client
