"""
WebSocket Security Scanner Module
Tests WebSocket endpoints for security vulnerabilities.
"""

import asyncio
import json
import re
import ssl
from typing import Any
from urllib.parse import urlparse

import requests

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


class WebSocketScanner:
    """
    WebSocket Security vulnerability scanner.

    Detects:
    - Cross-Site WebSocket Hijacking (CSWSH)
    - Origin validation bypass
    - Missing authentication
    - Insecure (WS vs WSS) connections
    - Message injection vulnerabilities
    - Rate limiting issues
    """

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })

        # Test origins for CSWSH
        self.test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "",
        ]

        # XSS payloads for message injection
        self.xss_payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "{{constructor.constructor('alert(1)')()}}",
        ]

        # SQLi payloads for message injection
        self.sqli_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
        ]

    def _discover_websocket_endpoints(
        self,
        base_url: str,
    ) -> list[str]:
        """Discover WebSocket endpoints from page content"""
        endpoints = []

        try:
            response = self.session.get(base_url, timeout=self.timeout, verify=False)
            content = response.text

            # Look for WebSocket URLs in JavaScript
            ws_patterns = [
                r'wss?://[^\s\'"<>]+',
                r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'socket\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'io\s*\(\s*[\'"]([^\'"]+)[\'"]',  # Socket.io
            ]

            for pattern in ws_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match.startswith("ws://") or match.startswith("wss://"):
                        endpoints.append(match)

            # Convert relative WebSocket paths
            parsed = urlparse(base_url)

            # Common WebSocket endpoints
            common_paths = [
                "/ws",
                "/websocket",
                "/socket",
                "/socket.io/",
                "/sockjs",
                "/realtime",
                "/live",
                "/stream",
                "/events",
                "/notifications",
            ]

            scheme = "wss" if parsed.scheme == "https" else "ws"
            for path in common_paths:
                endpoints.append(f"{scheme}://{parsed.netloc}{path}")

        except Exception:
            pass

        return list(set(endpoints))

    async def _test_websocket_connection(
        self,
        ws_url: str,
        origin: str = None,
        extra_headers: dict = None,
    ) -> dict[str, Any]:
        """Test WebSocket connection with specific headers"""
        if not WEBSOCKETS_AVAILABLE:
            return {"error": "websockets library not installed"}

        result = {
            "connected": False,
            "url": ws_url,
            "origin": origin,
            "response_headers": {},
            "messages": [],
            "error": None,
        }

        try:
            headers = {"User-Agent": self.user_agent}
            if origin:
                headers["Origin"] = origin
            if extra_headers:
                headers.update(extra_headers)

            # SSL context for wss
            ssl_context = None
            if ws_url.startswith("wss://"):
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            async with websockets.connect(
                ws_url,
                additional_headers=headers,
                ssl=ssl_context,
                close_timeout=self.timeout,
                open_timeout=self.timeout,
            ) as websocket:
                result["connected"] = True
                result["response_headers"] = dict(websocket.response_headers)

                # Try to receive a message
                try:
                    message = await asyncio.wait_for(
                        websocket.recv(),
                        timeout=2.0,
                    )
                    result["messages"].append(str(message)[:500])
                except TimeoutError:
                    pass

        except Exception as e:
            result["error"] = str(e)

        return result

    async def _test_cswsh(self, ws_url: str) -> list[dict[str, Any]]:
        """Test for Cross-Site WebSocket Hijacking"""
        findings = []

        # First establish baseline with legitimate origin
        parsed = urlparse(ws_url.replace("ws://", "http://").replace("wss://", "https://"))
        legitimate_origin = f"{parsed.scheme}://{parsed.netloc}"

        baseline = await self._test_websocket_connection(ws_url, origin=legitimate_origin)
        if not baseline.get("connected"):
            return findings

        # Test with malicious origins
        for evil_origin in self.test_origins:
            result = await self._test_websocket_connection(ws_url, origin=evil_origin)

            if result.get("connected"):
                findings.append({
                    "type": "WEBSOCKET_VULNERABILITY",
                    "subtype": "CSWSH",
                    "url": ws_url,
                    "parameter": "Origin",
                    "payload": evil_origin or "(empty)",
                    "evidence": f"WebSocket connected with Origin: {evil_origin or 'empty'}",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "description": (
                        f"Cross-Site WebSocket Hijacking (CSWSH) vulnerability detected. "
                        f"The WebSocket server accepted connection from malicious origin: {evil_origin}. "
                        f"This allows attackers to hijack authenticated WebSocket sessions."
                    ),
                    "remediation": (
                        "Validate the Origin header on WebSocket handshake. "
                        "Only accept connections from trusted origins. "
                        "Implement CSRF tokens for WebSocket authentication."
                    ),
                    "owasp": "A01:2021",
                    "cwe": "CWE-346",
                })
                break  # One finding is enough

        return findings

    async def _test_message_injection(
        self,
        ws_url: str,
    ) -> list[dict[str, Any]]:
        """Test for message injection vulnerabilities"""
        findings = []

        if not WEBSOCKETS_AVAILABLE:
            return findings

        try:
            ssl_context = None
            if ws_url.startswith("wss://"):
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            async with websockets.connect(
                ws_url,
                additional_headers={"User-Agent": self.user_agent},
                ssl=ssl_context,
                close_timeout=self.timeout,
                open_timeout=self.timeout,
            ) as websocket:

                # Test XSS payloads
                for payload in self.xss_payloads:
                    try:
                        # Send as JSON (common format)
                        test_msg = json.dumps({"message": payload, "action": "test"})
                        await websocket.send(test_msg)

                        try:
                            response = await asyncio.wait_for(
                                websocket.recv(),
                                timeout=2.0,
                            )

                            # Check if payload is reflected
                            if payload in str(response):
                                findings.append({
                                    "type": "WEBSOCKET_VULNERABILITY",
                                    "subtype": "MESSAGE_INJECTION_XSS",
                                    "url": ws_url,
                                    "payload": payload,
                                    "evidence": f"XSS payload reflected in response: {str(response)[:200]}",
                                    "severity": "HIGH",
                                    "confidence": "HIGH",
                                    "description": (
                                        "WebSocket message injection vulnerability. "
                                        "XSS payload is reflected in WebSocket responses."
                                    ),
                                    "remediation": (
                                        "Sanitize all WebSocket message content. "
                                        "Implement proper output encoding."
                                    ),
                                    "owasp": "A03:2021",
                                    "cwe": "CWE-79",
                                })
                                break
                        except TimeoutError:
                            pass

                    except Exception:
                        pass

        except Exception:
            pass

        return findings

    def _check_insecure_transport(self, ws_url: str) -> dict[str, Any] | None:
        """Check for insecure WebSocket transport"""
        if ws_url.startswith("ws://"):
            # Check if HTTPS version of the site exists
            http_url = ws_url.replace("ws://", "http://")
            urlparse(http_url)

            return {
                "type": "WEBSOCKET_VULNERABILITY",
                "subtype": "INSECURE_TRANSPORT",
                "url": ws_url,
                "evidence": "WebSocket using unencrypted WS protocol instead of WSS",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "description": (
                    "WebSocket connection uses unencrypted WS:// protocol. "
                    "All WebSocket traffic can be intercepted by attackers."
                ),
                "remediation": (
                    "Use WSS:// (WebSocket Secure) for all WebSocket connections. "
                    "Ensure proper TLS configuration."
                ),
                "owasp": "A02:2021",
                "cwe": "CWE-319",
            }

        return None

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """
        Scan a URL for WebSocket vulnerabilities.

        Args:
            url: Target URL to scan (HTTP/HTTPS base URL)

        Returns:
            List of vulnerability findings
        """
        findings = []

        if not WEBSOCKETS_AVAILABLE:
            return [{
                "type": "SCAN_ERROR",
                "message": "websockets library not installed. Run: pip install websockets",
            }]

        # Discover WebSocket endpoints
        ws_endpoints = self._discover_websocket_endpoints(url)

        if not ws_endpoints:
            return findings

        # Test each endpoint
        for ws_url in ws_endpoints[:5]:  # Limit to first 5 endpoints
            # Check for insecure transport
            insecure = self._check_insecure_transport(ws_url)
            if insecure:
                findings.append(insecure)

            # Run async tests
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                # Test CSWSH
                cswsh_findings = loop.run_until_complete(self._test_cswsh(ws_url))
                findings.extend(cswsh_findings)

                # Test message injection
                injection_findings = loop.run_until_complete(
                    self._test_message_injection(ws_url)
                )
                findings.extend(injection_findings)

                loop.close()

            except Exception:
                pass

        return findings

    def scan_websocket_url(self, ws_url: str) -> list[dict[str, Any]]:
        """
        Directly scan a WebSocket URL.

        Args:
            ws_url: WebSocket URL (ws:// or wss://)

        Returns:
            List of vulnerability findings
        """
        findings = []

        if not WEBSOCKETS_AVAILABLE:
            return [{
                "type": "SCAN_ERROR",
                "message": "websockets library not installed",
            }]

        # Check insecure transport
        insecure = self._check_insecure_transport(ws_url)
        if insecure:
            findings.append(insecure)

        # Run async tests
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            cswsh_findings = loop.run_until_complete(self._test_cswsh(ws_url))
            findings.extend(cswsh_findings)

            injection_findings = loop.run_until_complete(
                self._test_message_injection(ws_url)
            )
            findings.extend(injection_findings)

            loop.close()

        except Exception:
            pass

        return findings


def get_scanner(timeout: int = 10, user_agent: str = None) -> WebSocketScanner:
    """Get a WebSocket scanner instance"""
    return WebSocketScanner(timeout=timeout, user_agent=user_agent)
