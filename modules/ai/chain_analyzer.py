"""
Vulnerability Chain Analyzer
AI-powered detection of vulnerability chains and attack paths.
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from .providers.groq_provider import get_groq_provider
from .providers.ollama_provider import get_ollama_provider


@dataclass
class AttackChain:
    """Represents a chain of vulnerabilities forming an attack path"""
    name: str
    steps: List[Dict[str, Any]]
    impact: str
    likelihood: str
    severity: str
    description: str
    mitigation: str


class VulnerabilityChainAnalyzer:
    """
    Analyzes vulnerability findings to identify attack chains.
    
    Uses AI to:
    - Identify related vulnerabilities
    - Construct exploitation paths
    - Assess combined impact
    - Prioritize remediation
    """
    
    CHAIN_ANALYSIS_PROMPT = """You are an expert red team operator analyzing vulnerability findings.

Identify potential attack chains by:
1. Finding vulnerabilities that can be combined
2. Mapping exploitation sequences
3. Assessing combined impact
4. Identifying prerequisites for each step

Common chains:
- XSS + CSRF = Account takeover
- SSRF + Cloud metadata = Credential theft
- SQL injection + Path traversal = Code execution
- IDOR + Information disclosure = Data breach
- Open redirect + Phishing = Credential harvesting

Respond with JSON:
{
    "chains": [
        {
            "name": "Chain name",
            "steps": [
                {"vulnerability": "type", "action": "what attacker does", "outcome": "result"}
            ],
            "impact": "What attacker achieves",
            "likelihood": "HIGH/MEDIUM/LOW",
            "severity": "CRITICAL/HIGH/MEDIUM/LOW",
            "description": "Detailed explanation",
            "mitigation": "How to break the chain"
        }
    ],
    "priority_order": ["Chain names in order of risk"]
}"""

    # Known vulnerability chain patterns
    KNOWN_CHAINS = [
        {
            "vulns": ["XSS", "CSRF"],
            "name": "XSS to Account Takeover",
            "impact": "Account compromise via JavaScript session hijacking",
        },
        {
            "vulns": ["SSRF", "INFORMATION_DISCLOSURE"],
            "name": "SSRF to Cloud Credential Theft",
            "impact": "AWS/GCP/Azure credential exposure via metadata endpoint",
        },
        {
            "vulns": ["SQL_INJECTION", "FILE_UPLOAD"],
            "name": "SQLi to RCE",
            "impact": "Remote code execution via SQL file write",
        },
        {
            "vulns": ["IDOR", "SQL_INJECTION"],
            "name": "IDOR to Full Database Access",
            "impact": "Complete database compromise",
        },
        {
            "vulns": ["OPEN_REDIRECT", "XSS"],
            "name": "Redirect to Phishing",
            "impact": "Credential theft via trusted domain redirect",
        },
        {
            "vulns": ["PATH_TRAVERSAL", "FILE_INCLUSION"],
            "name": "LFI to RCE",
            "impact": "Code execution via log poisoning or PHP wrappers",
        },
        {
            "vulns": ["INSECURE_DESERIALIZATION", "COMMAND_INJECTION"],
            "name": "Deserialization to Shell",
            "impact": "Remote shell access via gadget chains",
        },
    ]
    
    def __init__(
        self,
        provider: str = "auto",
        groq_api_key: str = None,
        ollama_host: str = None,
    ):
        self.provider_preference = provider
        
        self.groq = get_groq_provider(api_key=groq_api_key)
        self.ollama = get_ollama_provider(host=ollama_host)
        
        self._active_provider = None
        if provider == "groq" and self.groq.is_available():
            self._active_provider = self.groq
        elif provider == "ollama" and self.ollama.is_available():
            self._active_provider = self.ollama
        elif provider == "auto":
            if self.groq.is_available():
                self._active_provider = self.groq
            elif self.ollama.is_available():
                self._active_provider = self.ollama
    
    def analyze_chains(
        self,
        findings: List[Dict[str, Any]],
        target: str = "",
    ) -> List[AttackChain]:
        """
        Analyze findings to identify vulnerability chains.
        
        Args:
            findings: List of vulnerability findings
            target: Target URL/application
        
        Returns:
            List of identified attack chains
        """
        if not findings:
            return []
        
        # Try AI-based analysis first
        if self._active_provider:
            chains = self._ai_analyze(findings, target)
            if chains:
                return chains
        
        # Fall back to pattern matching
        return self._fallback_analyze(findings)
    
    def _ai_analyze(
        self,
        findings: List[Dict[str, Any]],
        target: str,
    ) -> List[AttackChain]:
        """AI-based chain analysis"""
        findings_summary = json.dumps(
            [
                {
                    "type": f.get("type"),
                    "severity": f.get("severity_label", f.get("severity")),
                    "url": f.get("url"),
                    "parameter": f.get("parameter"),
                }
                for f in findings[:15]  # Limit for token size
            ],
            indent=2,
        )
        
        prompt = f"""Analyze these vulnerability findings for attack chains.

Target: {target}

Findings:
{findings_summary}

Identify exploitation chains and attack paths."""

        result = self._active_provider.generate(
            prompt=prompt,
            system_prompt=self.CHAIN_ANALYSIS_PROMPT,
            temperature=0.4,
            max_tokens=2000,
            json_mode=True,
        )
        
        if not result.success:
            return []
        
        try:
            data = json.loads(result.text)
            chains = data.get("chains", [])
            
            return [
                AttackChain(
                    name=c.get("name", "Unknown Chain"),
                    steps=c.get("steps", []),
                    impact=c.get("impact", "Unknown"),
                    likelihood=c.get("likelihood", "MEDIUM"),
                    severity=c.get("severity", "HIGH"),
                    description=c.get("description", ""),
                    mitigation=c.get("mitigation", ""),
                )
                for c in chains
            ]
        except (json.JSONDecodeError, KeyError):
            return []
    
    def _fallback_analyze(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[AttackChain]:
        """Pattern-based fallback chain analysis"""
        chains = []
        
        # Extract vulnerability types
        vuln_types = set()
        for f in findings:
            vuln_type = f.get("type", "")
            # Normalize type names
            normalized = vuln_type.upper().replace("-", "_").replace(" ", "_")
            vuln_types.add(normalized)
            
            # Also add common aliases
            if "XSS" in normalized or "CROSS_SITE" in normalized:
                vuln_types.add("XSS")
            if "SQL" in normalized:
                vuln_types.add("SQL_INJECTION")
            if "REDIRECT" in normalized:
                vuln_types.add("OPEN_REDIRECT")
            if "SSRF" in normalized or "SERVER_SIDE" in normalized:
                vuln_types.add("SSRF")
        
        # Check for known chains
        for known in self.KNOWN_CHAINS:
            required_vulns = set(known["vulns"])
            if required_vulns.issubset(vuln_types):
                chains.append(AttackChain(
                    name=known["name"],
                    steps=[
                        {"vulnerability": v, "action": f"Exploit {v}"}
                        for v in known["vulns"]
                    ],
                    impact=known["impact"],
                    likelihood="MEDIUM",
                    severity="HIGH",
                    description=f"Chain of {', '.join(known['vulns'])} vulnerabilities",
                    mitigation=f"Fix any of: {', '.join(known['vulns'])}",
                ))
        
        return chains
    
    def get_attack_graph(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Generate an attack graph representation.
        
        Args:
            findings: List of vulnerability findings
        
        Returns:
            Graph data structure for visualization
        """
        chains = self.analyze_chains(findings)
        
        nodes = []
        edges = []
        
        # Add entry point
        nodes.append({
            "id": "entry",
            "label": "Attacker Entry",
            "type": "entry",
        })
        
        # Add vulnerability nodes
        for i, finding in enumerate(findings[:20]):
            node_id = f"vuln_{i}"
            nodes.append({
                "id": node_id,
                "label": finding.get("type", "Unknown"),
                "type": "vulnerability",
                "severity": finding.get("severity_label", "MEDIUM"),
                "url": finding.get("url", ""),
            })
            
            # Connect from entry
            edges.append({
                "from": "entry",
                "to": node_id,
                "label": "exploit",
            })
        
        # Add chain connections
        for chain in chains:
            for i, step in enumerate(chain.steps[:-1]):
                next_step = chain.steps[i + 1]
                edges.append({
                    "from": f"chain_{chain.name}_{i}",
                    "to": f"chain_{chain.name}_{i+1}",
                    "label": "leads to",
                })
        
        # Add impact nodes
        impacts = set()
        for chain in chains:
            if chain.impact not in impacts:
                impacts.add(chain.impact)
                nodes.append({
                    "id": f"impact_{len(impacts)}",
                    "label": chain.impact[:50],
                    "type": "impact",
                })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "chains": [
                {
                    "name": c.name,
                    "severity": c.severity,
		    "steps": len(c.steps),
                }
                for c in chains
            ],
        }


# Singleton
_chain_analyzer: Optional[VulnerabilityChainAnalyzer] = None


def get_chain_analyzer(**kwargs) -> VulnerabilityChainAnalyzer:
    """Get singleton chain analyzer"""
    global _chain_analyzer
    if _chain_analyzer is None:
        _chain_analyzer = VulnerabilityChainAnalyzer(**kwargs)
    return _chain_analyzer
