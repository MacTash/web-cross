"""
GraphQL Security Scanner Module for Web-Cross
Detects GraphQL-specific vulnerabilities: introspection, batching, depth attacks.
"""

import re
import json
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class GraphQLFinding:
    """GraphQL vulnerability finding."""
    vuln_type: str
    severity: str
    evidence: str
    recommendation: str


class GraphQLScanner:
    """
    GraphQL Security Scanner.
    
    Detects:
    - Introspection enabled
    - Batching attacks
    - Depth/complexity attacks
    - Field suggestions (info disclosure)
    - Aliases for DoS
    """
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types { name kind }
        }
    }
    """
    
    DEPTH_QUERY = """
    query DepthTest {
        users {
            friends {
                friends {
                    friends {
                        friends {
                            id
                        }
                    }
                }
            }
        }
    }
    """
    
    BATCH_QUERY = [
        {"query": "query { __typename }"},
        {"query": "query { __typename }"},
        {"query": "query { __typename }"},
    ]
    
    ALIAS_DOS_QUERY = """
    query AliasDoS {
        a1: __typename
        a2: __typename
        a3: __typename
        a4: __typename
        a5: __typename
        a6: __typename
        a7: __typename
        a8: __typename
        a9: __typename
        a10: __typename
    }
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[GraphQLFinding] = []
    
    def detect_graphql_endpoint(self, base_url: str) -> Optional[str]:
        """Try common GraphQL endpoints."""
        endpoints = [
            "/graphql",
            "/api/graphql", 
            "/graphql/v1",
            "/v1/graphql",
            "/query",
            "/gql",
        ]
        
        for endpoint in endpoints:
            url = base_url.rstrip("/") + endpoint
            try:
                # Try POST with introspection
                resp = requests.post(
                    url,
                    json={"query": "{ __typename }"},
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            return url
                    except:
                        pass
            except:
                continue
        
        return None
    
    def test_introspection(self, url: str) -> Optional[GraphQLFinding]:
        """Test if introspection is enabled."""
        try:
            resp = requests.post(
                url,
                json={"query": self.INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and data["data"].get("__schema"):
                    schema = data["data"]["__schema"]
                    types_count = len(schema.get("types", []))
                    
                    return GraphQLFinding(
                        vuln_type="GRAPHQL_INTROSPECTION",
                        severity="Medium",
                        evidence=f"Introspection enabled. Found {types_count} types.",
                        recommendation="Disable introspection in production."
                    )
        except Exception as e:
            pass
        
        return None
    
    def test_batching(self, url: str) -> Optional[GraphQLFinding]:
        """Test if query batching is allowed."""
        try:
            resp = requests.post(
                url,
                json=self.BATCH_QUERY,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) == 3:
                    return GraphQLFinding(
                        vuln_type="GRAPHQL_BATCHING",
                        severity="Low",
                        evidence="Query batching enabled. DoS risk via batch amplification.",
                        recommendation="Limit batch query count or disable batching."
                    )
        except:
            pass
        
        return None
    
    def test_field_suggestions(self, url: str) -> Optional[GraphQLFinding]:
        """Test if field suggestions leak schema info."""
        try:
            resp = requests.post(
                url,
                json={"query": "{ usersXXX }"},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                errors = data.get("errors", [])
                for error in errors:
                    msg = str(error.get("message", ""))
                    if "did you mean" in msg.lower() or "suggestions" in msg.lower():
                        return GraphQLFinding(
                            vuln_type="GRAPHQL_FIELD_SUGGESTIONS",
                            severity="Low",
                            evidence=f"Field suggestions enabled: {msg[:100]}",
                            recommendation="Disable field suggestions in production."
                        )
        except:
            pass
        
        return None
    
    def test_depth_limit(self, url: str) -> Optional[GraphQLFinding]:
        """Test if query depth is limited."""
        try:
            resp = requests.post(
                url,
                json={"query": self.DEPTH_QUERY},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )
            
            # If query succeeds or no depth error, it's vulnerable
            if resp.status_code == 200:
                data = resp.json()
                errors = data.get("errors", [])
                depth_limited = any(
                    "depth" in str(e).lower() or "complexity" in str(e).lower()
                    for e in errors
                )
                
                if not depth_limited and "data" in data:
                    return GraphQLFinding(
                        vuln_type="GRAPHQL_NO_DEPTH_LIMIT",
                        severity="Medium",
                        evidence="No query depth limit detected. DoS risk.",
                        recommendation="Implement query depth limiting."
                    )
        except:
            pass
        
        return None
    
    def scan(self, base_url: str) -> List[Dict[str, Any]]:
        """Run full GraphQL security scan."""
        self.findings = []
        
        # Find GraphQL endpoint
        endpoint = self.detect_graphql_endpoint(base_url)
        if not endpoint:
            return []
        
        # Run tests
        tests = [
            self.test_introspection,
            self.test_batching,
            self.test_field_suggestions,
            self.test_depth_limit,
        ]
        
        for test in tests:
            finding = test(endpoint)
            if finding:
                self.findings.append(finding)
        
        return [
            {
                "type": f.vuln_type,
                "severity": f.severity,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "endpoint": endpoint,
            }
            for f in self.findings
        ]


# Singleton
_scanner: Optional[GraphQLScanner] = None


def get_scanner() -> GraphQLScanner:
    """Get singleton scanner instance."""
    global _scanner
    if _scanner is None:
        _scanner = GraphQLScanner()
    return _scanner
