"""
LLM Analyzer Module for Web-Cross Scanner
Uses Ollama with Llama 3.2:3b for AI-powered vulnerability detection.
"""

import os
import re
import json
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


# Configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
MODEL_NAME = os.getenv("WEBCROSS_MODEL", "llama3.2:3b")


@dataclass
class AnalysisResult:
    """Result from LLM analysis."""
    vulnerabilities: List[Dict[str, Any]]
    confidence: float
    reasoning: str
    recommendations: List[str]


class LLMAnalyzer:
    """
    AI-powered vulnerability analyzer using Ollama + Llama 3.2.
    
    Provides intelligent analysis beyond pattern matching:
    - Context-aware vulnerability detection
    - Smart payload generation
    - Response interpretation
    - Risk prioritization
    """
    
    def __init__(
        self,
        host: str = None,
        model: str = None,
        timeout: int = 60,
    ):
        self.host = host or OLLAMA_HOST
        self.model = model or MODEL_NAME
        self.timeout = timeout
        self._available = None
    
    def is_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        if self._available is not None:
            return self._available
        
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                # Check if our model exists (exact match or with :latest)
                self._available = any(
                    self.model in name or name.startswith(self.model.split(":")[0])
                    for name in model_names
                )
                if not self._available:
                    print(f"⚠️ Model '{self.model}' not found. Available: {model_names[:5]}")
                    print(f"   Run: ollama pull {self.model}")
                return self._available
        except Exception as e:
            print(f"⚠️ Ollama not reachable at {self.host}: {e}")
            self._available = False
        
        return False
    
    def _generate(self, prompt: str, json_format: bool = False) -> str:
        """Generate text from Ollama."""
        url = f"{self.host}/api/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Lower for more focused analysis
                "num_predict": 1024,
            }
        }
        
        if json_format:
            payload["format"] = "json"
        
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception as e:
            print(f"⚠️ LLM generation failed: {e}")
            return ""
    
    def analyze_response(
        self,
        response_text: str,
        url: str = "",
        context: Dict = None,
    ) -> AnalysisResult:
        """
        Analyze an HTTP response for vulnerabilities.
        
        Args:
            response_text: The HTTP response body
            url: Target URL
            context: Additional context (headers, method, etc.)
        
        Returns:
            AnalysisResult with detected vulnerabilities
        """
        if not self.is_available():
            return self._fallback_analyze(response_text)
        
        context = context or {}
        
        # Truncate response to fit context
        truncated = response_text[:4000]
        
        prompt = f"""You are an expert web security analyst. Analyze this HTTP response for vulnerabilities.

TARGET: {url}
RESPONSE HEADERS:
{json.dumps(context.get('headers', {}), indent=2)[:500]}

RESPONSE BODY:
{truncated}

═══════════════════════════════════════════
DETECT THESE 2025 VULNERABILITY PATTERNS:
═══════════════════════════════════════════

1. XSS (Reflected/DOM/Stored)
   - Unescaped user input in HTML/JS
   - Event handlers, script tags, javascript: URIs

2. SQL Injection
   - Database errors (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
   - Syntax errors, stack traces with SQL

3. SSRF Indicators
   - Internal IPs (127.0.0.1, 10.x, 192.168.x, 169.254.x)
   - Cloud metadata URLs (169.254.169.254)

4. Information Disclosure
   - Stack traces, debug info, version numbers
   - API keys, tokens, credentials in response
   - Internal paths, server configuration

5. Injection Points
   - Template syntax (double-braces, Jinja, EL)
   - Command output patterns
   - LDAP/XML/Path errors

6. Authentication Issues
   - Session tokens in URL
   - Weak JWT (alg:none, weak secret)
   - Missing security headers

═══════════════════════════════════════════
STRICT RULES:
═══════════════════════════════════════════

- ONLY report vulnerabilities with SPECIFIC evidence
- Quote the EXACT text/code from the response as proof
- Do NOT guess or hallucinate
- If unsure, do not include it

═══════════════════════════════════════════
OUTPUT FORMAT (JSON):
═══════════════════════════════════════════

{{
  "vulnerabilities": [
    {{
      "type": "XSS",
      "evidence": "<exact quote from response>",
      "severity": "High",
      "line": "approximate line if visible"
    }}
  ],
  "recommendations": ["specific fix suggestion"]
}}

Return ONLY valid JSON."""

        result = self._generate(prompt, json_format=True)
        
        try:
            data = json.loads(result)
            vulns = data.get("vulnerabilities", [])
            recs = data.get("recommendations", [])
            
            return AnalysisResult(
                vulnerabilities=vulns,
                confidence=0.8 if vulns else 0.5,
                reasoning=result,
                recommendations=recs,
            )
        except json.JSONDecodeError:
            return self._parse_text_response(result)
    
    def _parse_text_response(self, text: str) -> AnalysisResult:
        """Parse non-JSON response into structured format."""
        vulnerabilities = []
        recommendations = []
        
        # Simple extraction for common patterns
        if "XSS" in text.upper() or "CROSS-SITE" in text.upper():
            vulnerabilities.append({
                "type": "XSS",
                "evidence": "Detected in LLM analysis",
                "severity": "High"
            })
        if "SQL" in text.upper() and ("INJECTION" in text.upper() or "SQLI" in text.upper()):
            vulnerabilities.append({
                "type": "SQL_INJECTION", 
                "evidence": "Detected in LLM analysis",
                "severity": "Critical"
            })
        if "CSRF" in text.upper():
            vulnerabilities.append({
                "type": "CSRF",
                "evidence": "Detected in LLM analysis", 
                "severity": "Medium"
            })
        
        return AnalysisResult(
            vulnerabilities=vulnerabilities,
            confidence=0.6,
            reasoning=text,
            recommendations=recommendations,
        )
    
    def generate_payloads(
        self,
        vuln_type: str,
        context: str = "",
        waf_info: str = "None detected",
    ) -> List[Dict[str, str]]:
        """
        Generate context-aware payloads using LLM.
        
        Args:
            vuln_type: Type of vulnerability (XSS, SQLi, etc.)
            context: Target context information
            waf_info: Detected WAF information
        
        Returns:
            List of payloads with techniques
        """
        if not self.is_available():
            return self._fallback_payloads(vuln_type)
        
        prompt = f"""You are an expert penetration tester. Generate 7 sophisticated {vuln_type} payloads.

TARGET CONTEXT: {context or 'Modern web application'}
WAF DETECTED: {waf_info}

═══════════════════════════════════════════
2025 BYPASS TECHNIQUES TO USE:
═══════════════════════════════════════════

For XSS:
- DOM clobbering, mutation XSS, prototype pollution chains
- SVG/MathML payloads, template literal injection
- WebSocket/postMessage exploitation

For SQLi:
- JSON/XML injection in APIs
- Unicode normalization bypasses
- Comment-based WAF evasion (/*!50000*/, --)
- Time-based with CASE/IF variations

For SSRF:
- DNS rebinding, IPv6 bypasses
- URL parser differentials
- Cloud metadata endpoints (AWS, GCP, Azure)

For Command Injection:
- Environment variable injection
- Wildcard abuse, IFS manipulation
- Backtick/$()/heredoc variations

General WAF Bypass:
- Double URL encoding, Unicode escapes
- Chunked transfer, multipart boundaries
- Case mixing, comment insertion
- Null byte injection, parameter pollution

═══════════════════════════════════════════
OUTPUT FORMAT (JSON array):
═══════════════════════════════════════════

[
  {{"payload": "<actual payload>", "technique": "<bypass method>", "risk": "high/medium/low"}}
]

Return ONLY the JSON array, no explanation."""

        result = self._generate(prompt, json_format=True)
        
        try:
            payloads = json.loads(result)
            if isinstance(payloads, list):
                return payloads
        except json.JSONDecodeError:
            pass
        
        return self._fallback_payloads(vuln_type)
    
    def _fallback_payloads(self, vuln_type: str) -> List[Dict[str, str]]:
        """Return basic payloads when LLM unavailable."""
        if vuln_type.upper() == "XSS":
            return [
                {"payload": "<script>alert(1)</script>", "technique": "basic"},
                {"payload": "<img src=x onerror=alert(1)>", "technique": "event_handler"},
                {"payload": "<svg/onload=alert(1)>", "technique": "svg"},
            ]
        elif vuln_type.upper() in ["SQLI", "SQL"]:
            return [
                {"payload": "' OR '1'='1", "technique": "basic"},
                {"payload": "' UNION SELECT NULL--", "technique": "union"},
                {"payload": "' AND SLEEP(5)--", "technique": "time_based"},
            ]
        return []
    
    def assess_risk(
        self,
        findings: List[Dict],
        target: str,
    ) -> Dict[str, Any]:
        """
        Provide risk assessment for all findings.
        
        Args:
            findings: List of vulnerability findings
            target: Target URL/application
        
        Returns:
            Risk assessment dictionary
        """
        if not self.is_available() or not findings:
            return self._fallback_risk(findings)
        
        # Format findings for prompt
        findings_str = json.dumps(findings[:20], indent=2)[:3000]
        
        prompt = f"""Analyze these security scan findings for {target}:

{findings_str}

Return a JSON object with:
- "risk_level": "Critical" | "High" | "Medium" | "Low"
- "summary": one-line overall assessment
- "priority_fixes": array of top 3 things to fix first
- "attack_chain": possible attack chain if vulnerabilities are chained

Return ONLY valid JSON."""

        result = self._generate(prompt, json_format=True)
        
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return self._fallback_risk(findings)
    
    def _fallback_risk(self, findings: List[Dict]) -> Dict[str, Any]:
        """Fallback risk assessment."""
        if not findings:
            return {"risk_level": "Low", "summary": "No vulnerabilities detected"}
        
        # Calculate based on findings
        critical = sum(1 for f in findings if f.get("severity") == "Critical" or f.get("risk_score", 0) >= 9)
        high = sum(1 for f in findings if f.get("severity") == "High" or 7 <= f.get("risk_score", 0) < 9)
        
        if critical > 0:
            level = "Critical"
        elif high > 0:
            level = "High"
        elif len(findings) > 5:
            level = "Medium"
        else:
            level = "Low"
        
        return {
            "risk_level": level,
            "summary": f"Found {len(findings)} issues ({critical} critical, {high} high)",
            "priority_fixes": ["Address critical vulnerabilities first"],
        }
    
    def _fallback_analyze(self, response_text: str) -> AnalysisResult:
        """
        Fallback pattern-based analysis when Ollama unavailable.
        """
        findings = []
        
        # XSS patterns
        xss_patterns = [
            (r"<script[^>]*>", "Script tag in response"),
            (r"javascript:", "JavaScript URL scheme"),
            (r"on\w+\s*=", "Event handler attribute"),
        ]
        
        # SQLi patterns
        sqli_patterns = [
            (r"(mysql|sql|ora|postgres).*error", "Database error exposed"),
            (r"syntax.*error", "SQL syntax error"),
            (r"warning.*mysql", "MySQL warning"),
        ]
        
        for pattern, desc in xss_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                findings.append({
                    "type": "XSS_INDICATOR",
                    "evidence": desc,
                    "severity": "Medium",
                })
        
        for pattern, desc in sqli_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                findings.append({
                    "type": "SQLI_INDICATOR",
                    "evidence": desc,
                    "severity": "High",
                })
        
        return AnalysisResult(
            vulnerabilities=findings,
            confidence=0.5,
            reasoning="Pattern-based analysis (Ollama unavailable)",
            recommendations=[],
        )


# Singleton instance
_analyzer: Optional[LLMAnalyzer] = None


def get_analyzer() -> LLMAnalyzer:
    """Get the singleton LLM analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = LLMAnalyzer()
    return _analyzer
