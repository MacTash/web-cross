"""JWT Vulnerability Scanner Module"""

import base64
import json
import re
from typing import Any

import requests


class JWTScanner:
    """JWT (JSON Web Token) vulnerability scanner"""

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"

        # Common JWT header/cookie names
        self.jwt_locations = [
            'Authorization',
            'X-Auth-Token',
            'X-Access-Token',
            'access_token',
            'token',
            'jwt',
            'auth',
            'id_token',
        ]

        # Weak secrets to test
        self.weak_secrets = [
            'secret',
            'password',
            '123456',
            'key',
            'private',
            'jwt_secret',
            'secretkey',
        ]

    def _decode_jwt(self, token: str) -> dict | None:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header
            header = parts[0]
            header += '=' * (4 - len(header) % 4)  # Pad
            header_data = json.loads(base64.urlsafe_b64decode(header))

            # Decode payload
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)  # Pad
            payload_data = json.loads(base64.urlsafe_b64decode(payload))

            return {
                "header": header_data,
                "payload": payload_data,
                "signature": parts[2]
            }
        except Exception:
            return None

    def _check_alg_none(self, decoded: dict, token: str) -> dict | None:
        """Check for algorithm none bypass"""
        header = decoded.get("header", {})
        alg = header.get("alg", "")

        # Already using none
        if alg.lower() in ['none', '']:
            return {
                "type": "JWT_ALG_NONE",
                "evidence": f"Token uses algorithm: {alg}",
                "confidence": "HIGH"
            }
        return None

    def _check_weak_alg(self, decoded: dict) -> dict | None:
        """Check for weak algorithms"""
        header = decoded.get("header", {})
        alg = header.get("alg", "")

        weak_algs = ['HS256', 'HS384', 'HS512']  # Symmetric, vulnerable to brute force
        if alg in weak_algs:
            return {
                "type": "JWT_WEAK_ALGORITHM",
                "algorithm": alg,
                "evidence": f"Symmetric algorithm {alg} may be vulnerable to key brute force",
                "confidence": "LOW"
            }
        return None

    def _check_exp_claim(self, decoded: dict) -> dict | None:
        """Check for missing or distant expiration"""
        import time

        payload = decoded.get("payload", {})
        exp = payload.get("exp")

        if exp is None:
            return {
                "type": "JWT_NO_EXPIRATION",
                "evidence": "Token has no expiration claim",
                "confidence": "MEDIUM"
            }

        # Check if expired but still being used
        current_time = int(time.time())
        if exp < current_time:
            return {
                "type": "JWT_EXPIRED",
                "evidence": f"Token expired at {exp}",
                "confidence": "MEDIUM"
            }

        # Very long expiration (> 30 days)
        if exp - current_time > 30 * 24 * 60 * 60:
            return {
                "type": "JWT_LONG_EXPIRATION",
                "evidence": "Token expires in more than 30 days",
                "confidence": "LOW"
            }

        return None

    def _check_sensitive_claims(self, decoded: dict) -> list[dict]:
        """Check for sensitive info in JWT"""
        findings = []
        payload = decoded.get("payload", {})

        sensitive_keys = ['password', 'secret', 'key', 'credit', 'ssn', 'card']

        for key, _value in payload.items():
            key_lower = key.lower()
            for sensitive in sensitive_keys:
                if sensitive in key_lower:
                    findings.append({
                        "type": "JWT_SENSITIVE_DATA",
                        "claim": key,
                        "evidence": f"Potentially sensitive claim: {key}",
                        "confidence": "MEDIUM"
                    })

        return findings

    def _check_jku_jwk(self, decoded: dict) -> dict | None:
        """Check for JKU/JWK injection"""
        header = decoded.get("header", {})

        if "jku" in header:
            return {
                "type": "JWT_JKU_INJECTION",
                "jku_url": header["jku"],
                "evidence": "JKU header present - potential key injection",
                "confidence": "MEDIUM"
            }

        if "jwk" in header:
            return {
                "type": "JWT_JWK_INJECTION",
                "evidence": "Embedded JWK in header - potential key injection",
                "confidence": "MEDIUM"
            }

        if "kid" in header:
            kid = header["kid"]
            # Check for SQL injection in kid
            if any(c in kid for c in ["'", '"', ';', '--']):
                return {
                    "type": "JWT_KID_INJECTION",
                    "kid": kid,
                    "evidence": "Kid contains suspicious characters",
                    "confidence": "MEDIUM"
                }

        return None

    def scan_token(self, token: str) -> list[dict[str, Any]]:
        """Scan a JWT token for vulnerabilities"""
        findings = []

        decoded = self._decode_jwt(token)
        if not decoded:
            return findings

        # Check algorithm
        alg_none = self._check_alg_none(decoded, token)
        if alg_none:
            findings.append(alg_none)

        weak_alg = self._check_weak_alg(decoded)
        if weak_alg:
            findings.append(weak_alg)

        # Check expiration
        exp_check = self._check_exp_claim(decoded)
        if exp_check:
            findings.append(exp_check)

        # Check sensitive claims
        sensitive = self._check_sensitive_claims(decoded)
        findings.extend(sensitive)

        # Check for injection
        injection = self._check_jku_jwk(decoded)
        if injection:
            findings.append(injection)

        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Scan URL response for JWTs"""
        findings = []

        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.get(url, headers=headers,
                                  timeout=self.timeout, verify=False)

            # Check response headers
            for header_name in self.jwt_locations:
                value = response.headers.get(header_name, '')
                if value and '.' in value:
                    # Remove Bearer prefix if present
                    token = value.replace('Bearer ', '').strip()
                    token_findings = self.scan_token(token)
                    for f in token_findings:
                        f["url"] = url
                        f["location"] = f"Header: {header_name}"
                    findings.extend(token_findings)

            # Check cookies
            for cookie in response.cookies:
                if '.' in cookie.value:
                    token_findings = self.scan_token(cookie.value)
                    for f in token_findings:
                        f["url"] = url
                        f["location"] = f"Cookie: {cookie.name}"
                    findings.extend(token_findings)

            # Check response body for JWT patterns
            jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
            body_tokens = re.findall(jwt_pattern, response.text)

            for token in body_tokens[:5]:  # Limit
                token_findings = self.scan_token(token)
                for f in token_findings:
                    f["url"] = url
                    f["location"] = "Response body"
                findings.extend(token_findings)

        except Exception:
            pass

        return findings
