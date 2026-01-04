"""
Groq AI Provider
Fast inference using Groq Cloud API.
"""

import os
import json
from typing import Dict, List, Any, Optional

from . import AIProvider, GenerationResult

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


class GroqProvider(AIProvider):
    """
    Groq AI Provider for fast LLM inference.
    
    Supports models like Llama 3.3, Mixtral, etc.
    Requires GROQ_API_KEY environment variable or explicit key.
    """
    
    # Available models on Groq
    MODELS = {
        "llama-3.3-70b-versatile": "Latest Llama 3.3 70B - Best quality",
        "llama-3.1-70b-versatile": "Llama 3.1 70B",
        "llama-3.1-8b-instant": "Llama 3.1 8B - Fast",
        "mixtral-8x7b-32768": "Mixtral 8x7B",
        "gemma2-9b-it": "Gemma 2 9B",
    }
    
    DEFAULT_MODEL = "llama-3.3-70b-versatile"
    
    def __init__(
        self,
        api_key: str = None,
        model: str = None,
        timeout: int = 60,
    ):
        self.api_key = api_key or os.getenv("GROQ_API_KEY") or os.getenv("WEBCROSS_AI__GROQ_API_KEY")
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout
        self._client = None
        
        if GROQ_AVAILABLE and self.api_key:
            self._client = Groq(api_key=self.api_key)
    
    @property
    def name(self) -> str:
        return "groq"
    
    def is_available(self) -> bool:
        """Check if Groq is available"""
        if not GROQ_AVAILABLE:
            return False
        if not self.api_key:
            return False
        
        # Test the connection
        try:
            # Make a minimal test call
            self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5,
            )
            return True
        except Exception:
            return False
    
    def generate(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> GenerationResult:
        """Generate text using Groq"""
        if not self._client:
            return GenerationResult(
                text="",
                model=self.model,
                provider=self.name,
                success=False,
                error="Groq client not initialized",
            )
        
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            
            response = self._client.chat.completions.create(**kwargs)
            
            text = response.choices[0].message.content
            tokens = response.usage.total_tokens if response.usage else 0
            
            return GenerationResult(
                text=text,
                model=self.model,
                provider=self.name,
                tokens_used=tokens,
                success=True,
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
    ) -> Dict[str, Any]:
        """Generate JSON response"""
        # Add JSON instruction to system prompt
        json_system = (system_prompt or "") + "\nRespond only with valid JSON."
        
        result = self.generate(
            prompt=prompt,
            system_prompt=json_system,
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


def get_groq_provider(
    api_key: str = None,
    model: str = None,
) -> GroqProvider:
    """Get Groq provider instance"""
    return GroqProvider(api_key=api_key, model=model)
