"""
Supabase Scanner - Detect exposed Supabase API keys in JavaScript.
Ported from sif's Supabase scanning functionality.
"""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

import requests


# JWT regex pattern (matches tokens in quotes or backticks)
JWT_REGEX = re.compile(r'["\'\x60](ey[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2})["\'\x60]')


@dataclass
class SupabaseCollection:
    """Represents a Supabase collection/table"""
    name: str
    sample: list[Any] = field(default_factory=list)
    count: int = 0


@dataclass
class SupabaseResult:
    """Result from Supabase scan"""
    project_id: str
    api_key: str
    role: str
    collections: list[SupabaseCollection] = field(default_factory=list)
    vulnerable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "api_key": self.api_key[:20] + "..." if len(self.api_key) > 20 else self.api_key,
            "role": self.role,
            "collections": [
                {"name": c.name, "count": c.count}
                for c in self.collections
            ],
            "vulnerable": self.vulnerable,
        }


class SupabaseScanner:
    """
    Supabase API Key Scanner.
    
    Detects:
    - Exposed Supabase API keys in JavaScript
    - Public table access
    - Misconfigured RLS policies
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = None,
    ):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })

    def _decode_jwt_body(self, token: str) -> dict | None:
        """Decode JWT body without verification"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            
            # Add padding if needed
            body = parts[1]
            padding = 4 - len(body) % 4
            if padding != 4:
                body += "=" * padding
            
            decoded = base64.urlsafe_b64decode(body)
            return json.loads(decoded)
        except Exception:
            return None

    def _is_supabase_token(self, jwt_body: dict) -> bool:
        """Check if JWT is a Supabase token"""
        return "ref" in jwt_body or "role" in jwt_body

    def _check_supabase_access(
        self,
        project_id: str,
        api_key: str,
    ) -> SupabaseResult:
        """Check Supabase project accessibility"""
        result = SupabaseResult(
            project_id=project_id,
            api_key=api_key,
            role="unknown",
        )
        
        try:
            # Get OpenAPI spec to discover tables
            url = f"https://{project_id}.supabase.co/rest/v1/"
            headers = {
                "apikey": api_key,
                "Prefer": "count=exact",
            }
            
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if resp.status_code != 200:
                return result
            
            spec = resp.json()
            paths = spec.get("paths", {})
            
            # Try to access each table
            for path in paths:
                if path == "/" or path.startswith("/rpc/"):
                    continue
                
                table_name = path.lstrip("/")
                table_url = f"https://{project_id}.supabase.co/rest/v1{path}?limit=10"
                
                try:
                    table_resp = self.session.get(
                        table_url,
                        headers=headers,
                        timeout=self.timeout,
                    )
                    
                    if table_resp.status_code == 200:
                        data = table_resp.json()
                        
                        # Get count from Content-Range header
                        content_range = table_resp.headers.get("Content-Range", "")
                        count = 0
                        if "/" in content_range:
                            try:
                                count = int(content_range.split("/")[1])
                            except (ValueError, IndexError):
                                count = len(data) if isinstance(data, list) else 0
                        
                        if count > 0:
                            result.vulnerable = True
                            result.collections.append(SupabaseCollection(
                                name=table_name,
                                sample=data[:3] if isinstance(data, list) else [],
                                count=count,
                            ))
                except Exception:
                    continue
            
            return result
            
        except Exception:
            return result

    def scan_content(self, content: str, source_url: str = "") -> list[dict[str, Any]]:
        """
        Scan JavaScript content for Supabase API keys.
        
        Args:
            content: JavaScript or HTML content
            source_url: Source URL for context
            
        Returns:
            List of findings
        """
        findings = []
        
        # Find all JWTs in content
        jwt_matches = JWT_REGEX.findall(content)
        
        # Deduplicate
        unique_tokens = list(set(jwt_matches))
        
        for token in unique_tokens:
            jwt_body = self._decode_jwt_body(token)
            
            if not jwt_body:
                continue
            
            if not self._is_supabase_token(jwt_body):
                continue
            
            project_id = jwt_body.get("ref")
            role = jwt_body.get("role", "unknown")
            
            if not project_id:
                continue
            
            # Check access
            result = self._check_supabase_access(project_id, token)
            result.role = role
            
            severity = "HIGH" if result.vulnerable else "MEDIUM"
            
            if result.vulnerable:
                findings.append({
                    "type": "supabase",
                    "name": "Exposed Supabase API Key with Data Access",
                    "severity": severity,
                    "description": (
                        f"Supabase API key found with access to "
                        f"{len(result.collections)} tables"
                    ),
                    "evidence": f"Project: {project_id}, Role: {role}",
                    "details": result.to_dict(),
                    "source": source_url,
                })
            else:
                # Still report the exposed key
                if role != "anon":
                    findings.append({
                        "type": "supabase",
                        "name": "Exposed Supabase API Key",
                        "severity": "MEDIUM",
                        "description": (
                            f"Supabase API key found with role: {role}"
                        ),
                        "evidence": f"Project: {project_id}, Role: {role}",
                        "details": result.to_dict(),
                        "source": source_url,
                    })
        
        return findings

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """
        Fetch URL and scan for Supabase keys.
        
        Args:
            url: URL to fetch and scan
            
        Returns:
            List of findings
        """
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                return self.scan_content(resp.text, url)
        except Exception:
            pass
        
        return []


def get_scanner(timeout: int = 10, user_agent: str = None) -> SupabaseScanner:
    """Get a Supabase scanner instance"""
    return SupabaseScanner(timeout=timeout, user_agent=user_agent)
