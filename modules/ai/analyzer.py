"""
Web-Cross AI Analyzer
Multi-provider AI analyzer for vulnerability detection.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .providers import GenerationResult
from .providers.groq_provider import get_groq_provider
from .providers.ollama_provider import get_ollama_provider


@dataclass
class AnalysisResult:
    """Result from AI vulnerability analysis"""
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""
    recommendations: list[str] = field(default_factory=list)
    provider: str = ""
    model: str = ""


class AIAnalyzer:
    """
    Multi-provider AI analyzer for intelligent vulnerability detection.

    Supports:
    - Groq (cloud, fast inference)
    - Ollama (local)
    - Automatic fallback between providers
    """

    # System prompts for different analysis types
    VULN_ANALYSIS_PROMPT = """You are an expert security analyst specializing in web application security.
Analyze the provided HTTP response for security vulnerabilities.

Focus on:
1. Sensitive data exposure
2. Security misconfigurations
3. Injection vulnerabilities (reflected payloads)
4. Authentication/authorization issues
5. Information disclosure

Respond with JSON containing:
{
    "vulnerabilities": [
        {
            "type": "VULNERABILITY_TYPE",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
            "confidence": "HIGH|MEDIUM|LOW",
            "evidence": "specific evidence from response",
            "description": "brief description",
            "remediation": "how to fix"
        }
    ],
    "confidence": 0.0-1.0,
    "reasoning": "your analysis reasoning"
}"""

    PAYLOAD_ANALYSIS_PROMPT = """You are a security researcher analyzing potential vulnerability indicators.
Given the payload and response, determine if the vulnerability was successfully exploited.

Consider:
1. Payload reflection (exact or modified)
2. Error messages indicating vulnerability
3. Behavioral changes
4. Time-based indicators

Respond with JSON:
{
    "exploited": true/false,
    "confidence": 0.0-1.0,
    "evidence": "what indicates success/failure",
    "technique": "exploitation technique used"
}"""

    def __init__(
        self,
        provider: str = "auto",
        groq_api_key: str = None,
        groq_model: str = None,
        ollama_host: str = None,
        ollama_model: str = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        timeout: int = 60,
    ):
        """
        Initialize AI analyzer.

        Args:
            provider: "groq", "ollama", or "auto" (try groq first)
            groq_api_key: Groq API key
            groq_model: Groq model name
            ollama_host: Ollama server URL
            ollama_model: Ollama model name
            temperature: LLM temperature
            max_tokens: Maximum tokens for generation
            timeout: Request timeout
        """
        self.provider_preference = provider
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

        # Initialize providers
        self.groq = get_groq_provider(api_key=groq_api_key, model=groq_model)
        self.ollama = get_ollama_provider(host=ollama_host, model=ollama_model)

        # Determine active provider
        self._active_provider = None
        self._initialize_provider()

    def _initialize_provider(self):
        """Initialize the active provider based on availability"""
        if self.provider_preference == "groq":
            if self.groq.is_available():
                self._active_provider = self.groq
        elif self.provider_preference == "ollama":
            if self.ollama.is_available():
                self._active_provider = self.ollama
        else:  # auto
            if self.groq.is_available():
                self._active_provider = self.groq
            elif self.ollama.is_available():
                self._active_provider = self.ollama

    def is_available(self) -> bool:
        """Check if any AI provider is available"""
        return self._active_provider is not None

    @property
    def active_provider_name(self) -> str:
        """Get name of active provider"""
        return self._active_provider.name if self._active_provider else "none"

    def _generate(
        self,
        prompt: str,
        system_prompt: str = None,
        json_mode: bool = False,
    ) -> GenerationResult:
        """Generate using active provider with fallback"""
        if not self._active_provider:
            return GenerationResult(
                text="",
                model="none",
                provider="none",
                success=False,
                error="No AI provider available",
            )

        result = self._active_provider.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            json_mode=json_mode,
        )

        # If primary fails and in auto mode, try fallback
        if not result.success and self.provider_preference == "auto":
            fallback = self.ollama if self._active_provider == self.groq else self.groq
            if fallback.is_available():
                result = fallback.generate(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    json_mode=json_mode,
                )

        return result

    def _parse_json_response(self, text: str) -> dict[str, Any]:
        """Parse JSON from response text"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            return {}

    def analyze_response(
        self,
        response_text: str,
        url: str = "",
        context: dict = None,
    ) -> AnalysisResult:
        """
        Analyze an HTTP response for vulnerabilities.

        Args:
            response_text: HTTP response body
            url: Target URL
            context: Additional context (headers, method, etc.)

        Returns:
            AnalysisResult with detected vulnerabilities
        """
        # Truncate response if too long
        max_response_len = 4000
        if len(response_text) > max_response_len:
            response_text = response_text[:max_response_len] + "\n... [truncated]"

        prompt = f"""Analyze this HTTP response for security vulnerabilities.

URL: {url}
Context: {json.dumps(context or {})}

Response:
{response_text}

Provide your analysis as JSON."""

        result = self._generate(
            prompt=prompt,
            system_prompt=self.VULN_ANALYSIS_PROMPT,
            json_mode=True,
        )

        if not result.success:
            return self._fallback_analysis(response_text)

        data = self._parse_json_response(result.text)

        return AnalysisResult(
            vulnerabilities=data.get("vulnerabilities", []),
            confidence=data.get("confidence", 0.0),
            reasoning=data.get("reasoning", ""),
            recommendations=data.get("recommendations", []),
            provider=result.provider,
            model=result.model,
        )

    def verify_exploit(
        self,
        payload: str,
        response_text: str,
        vuln_type: str,
    ) -> dict[str, Any]:
        """
        Verify if an exploitation attempt was successful.

        Args:
            payload: The payload that was sent
            response_text: The response received
            vuln_type: Type of vulnerability tested

        Returns:
            Dict with verification result
        """
        max_response_len = 3000
        if len(response_text) > max_response_len:
            response_text = response_text[:max_response_len] + "\n... [truncated]"

        prompt = f"""Verify if this {vuln_type} exploit was successful.

Payload: {payload}

Response:
{response_text}

Analyze and respond with JSON."""

        result = self._generate(
            prompt=prompt,
            system_prompt=self.PAYLOAD_ANALYSIS_PROMPT,
            json_mode=True,
        )

        if not result.success:
            return {"exploited": False, "confidence": 0.0, "error": result.error}

        return self._parse_json_response(result.text)

    def assess_risk(
        self,
        findings: list[dict],
        target: str,
    ) -> dict[str, Any]:
        """
        Provide overall risk assessment for findings.

        Args:
            findings: List of vulnerability findings
            target: Target URL/application

        Returns:
            Risk assessment dictionary
        """
        if not findings:
            return {
                "risk_level": "LOW",
                "score": 0.0,
                "summary": "No vulnerabilities detected.",
            }

        findings_summary = json.dumps(findings[:10], indent=2)  # Limit for token size

        prompt = f"""Assess the overall security risk for this target.

Target: {target}

Findings:
{findings_summary}

Provide risk assessment as JSON with:
- risk_level: CRITICAL/HIGH/MEDIUM/LOW
- score: 0.0-10.0
- summary: brief risk summary
- priority_actions: list of immediate actions needed
- attack_scenarios: potential attack paths"""

        result = self._generate(
            prompt=prompt,
            system_prompt="You are a security risk analyst. Provide actionable risk assessments.",
            json_mode=True,
        )

        if not result.success:
            return self._fallback_risk(findings)

        return self._parse_json_response(result.text)

    def _fallback_analysis(self, response_text: str) -> AnalysisResult:
        """Pattern-based fallback analysis when AI unavailable"""
        vulnerabilities = []

        # Check for common vulnerability patterns
        patterns = [
            (r"SQL syntax.*MySQL", "SQL_INJECTION", "HIGH"),
            (r"ORA-\d{5}", "SQL_INJECTION", "HIGH"),
            (r"postgresql.*error", "SQL_INJECTION", "HIGH"),
            (r"<script>.*</script>", "XSS", "MEDIUM"),
            (r"on\w+\s*=", "XSS", "LOW"),
            (r"root:.*:0:0:", "PATH_TRAVERSAL", "CRITICAL"),
            (r"\[boot loader\]", "PATH_TRAVERSAL", "CRITICAL"),
            (r"stack trace|exception|error", "INFORMATION_DISCLOSURE", "LOW"),
        ]

        for pattern, vuln_type, severity in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                vulnerabilities.append({
                    "type": vuln_type,
                    "severity": severity,
                    "confidence": "MEDIUM",
                    "evidence": f"Pattern match: {pattern}",
                })

        return AnalysisResult(
            vulnerabilities=vulnerabilities,
            confidence=0.5 if vulnerabilities else 0.0,
            reasoning="Fallback pattern-based analysis",
            provider="fallback",
            model="pattern",
        )

    def _fallback_risk(self, findings: list[dict]) -> dict[str, Any]:
        """Fallback risk assessment"""
        if not findings:
            return {"risk_level": "LOW", "score": 0.0}

        severity_scores = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}

        scores = []
        for f in findings:
            sev = f.get("severity", f.get("severity_label", "MEDIUM"))
            scores.append(severity_scores.get(sev, 5))

        max_score = max(scores) if scores else 0

        if max_score >= 9:
            level = "CRITICAL"
        elif max_score >= 7:
            level = "HIGH"
        elif max_score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "risk_level": level,
            "score": max_score,
            "summary": f"Found {len(findings)} vulnerabilities, highest severity: {level}",
        }


# Singleton instance
_analyzer: AIAnalyzer | None = None


def get_ai_analyzer(**kwargs) -> AIAnalyzer:
    """Get singleton AI analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = AIAnalyzer(**kwargs)
    return _analyzer


def reset_ai_analyzer():
    """Reset analyzer for testing"""
    global _analyzer
    _analyzer = None
