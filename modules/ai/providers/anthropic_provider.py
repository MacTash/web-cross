"""
Anthropic Claude AI Provider
High-quality security analysis using Claude models.
"""

import json
import os
from typing import Any

from . import AIProvider, GenerationResult

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class AnthropicProvider(AIProvider):
    """
    Anthropic Claude AI Provider for security analysis.

    Supports Claude 3.5 Sonnet, Claude 3 Opus, etc.
    Requires ANTHROPIC_API_KEY environment variable or explicit key.
    """

    # Available models on Anthropic
    MODELS = {
        "claude-sonnet-4-20250514": "Claude Sonnet 4 - Latest, balanced",
        "claude-3-5-sonnet-20241022": "Claude 3.5 Sonnet - Fast and capable",
        "claude-3-opus-20240229": "Claude 3 Opus - Most capable",
        "claude-3-haiku-20240307": "Claude 3 Haiku - Fastest",
    }

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(
        self,
        api_key: str = None,
        model: str = None,
        timeout: int = 60,
    ):
        self.api_key = (
            api_key
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("WEBCROSS_AI__ANTHROPIC_API_KEY")
        )
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout
        self._client = None

        if ANTHROPIC_AVAILABLE and self.api_key:
            self._client = anthropic.Anthropic(api_key=self.api_key)

    @property
    def name(self) -> str:
        return "anthropic"

    def is_available(self) -> bool:
        """Check if Anthropic is available"""
        if not ANTHROPIC_AVAILABLE:
            return False
        if not self.api_key:
            return False

        # Validate key format (basic check)
        if not self.api_key.startswith("sk-ant-"):
            return False

        # We don't make a test call to save tokens
        # The actual availability will be confirmed on first use
        return True

    def generate(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> GenerationResult:
        """Generate text using Anthropic Claude"""
        if not self._client:
            return GenerationResult(
                text="",
                model=self.model,
                provider=self.name,
                success=False,
                error="Anthropic client not initialized",
            )

        try:
            # Build system prompt
            system = system_prompt or ""
            if json_mode:
                system += "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanation, just the JSON object."

            # Create message
            message = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system if system else None,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=temperature,
            )

            # Extract text from response
            text = ""
            for block in message.content:
                if hasattr(block, "text"):
                    text += block.text

            tokens = message.usage.input_tokens + message.usage.output_tokens

            return GenerationResult(
                text=text,
                model=self.model,
                provider=self.name,
                tokens_used=tokens,
                success=True,
            )

        except anthropic.APIConnectionError as e:
            return GenerationResult(
                text="",
                model=self.model,
                provider=self.name,
                success=False,
                error=f"Connection error: {e}",
            )
        except anthropic.RateLimitError as e:
            return GenerationResult(
                text="",
                model=self.model,
                provider=self.name,
                success=False,
                error=f"Rate limit exceeded: {e}",
            )
        except anthropic.APIStatusError as e:
            return GenerationResult(
                text="",
                model=self.model,
                provider=self.name,
                success=False,
                error=f"API error: {e.status_code} - {e.message}",
            )
        except Exception as e:
            return GenerationResult(
                text="",
                model=self.model,
                provider=self.name,
                success=False,
                error=str(e),
            )

    def generate_json(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> dict[str, Any]:
        """Generate JSON response"""
        result = self.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
        )

        if not result.success:
            return {"error": result.error}

        try:
            return json.loads(result.text)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            text = result.text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            return {"error": "Invalid JSON response", "raw": result.text}


# Singleton instance
_anthropic_provider: AnthropicProvider | None = None


def get_anthropic_provider(
    api_key: str = None,
    model: str = None,
) -> AnthropicProvider:
    """Get Anthropic provider instance"""
    global _anthropic_provider
    if _anthropic_provider is None or api_key:
        _anthropic_provider = AnthropicProvider(api_key=api_key, model=model)
    return _anthropic_provider
