"""
Ollama AI Provider
Local LLM inference using Ollama.
"""

import os
import json
import requests
from typing import Dict, List, Any, Optional

from . import AIProvider, GenerationResult


class OllamaProvider(AIProvider):
    """
    Ollama provider for local LLM inference.
    
    Supports various open-source models running locally.
    Requires Ollama server running at localhost:11434.
    """
    
    DEFAULT_HOST = "http://localhost:11434"
    DEFAULT_MODEL = "llama3.2:3b"
    
    def __init__(
        self,
        host: str = None,
        model: str = None,
        timeout: int = 60,
    ):
        self.host = host or os.getenv("OLLAMA_HOST", self.DEFAULT_HOST)
        self.model = model or os.getenv("WEBCROSS_MODEL", self.DEFAULT_MODEL)
        self.timeout = timeout
    
    @property
    def name(self) -> str:
        return "ollama"
    
    def is_available(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = requests.get(
                f"{self.host}/api/tags",
                timeout=5,
            )
            if response.status_code != 200:
                return False
            
            # Check if model is available
            tags = response.json().get("models", [])
            model_names = [m.get("name", "") for m in tags]
            
            # Check for exact match or partial match
            return any(
                self.model in name or name in self.model 
                for name in model_names
            )
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
        """Generate text using Ollama"""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            if json_mode:
                payload["format"] = "json"
            
            response = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            
            if response.status_code != 200:
                return GenerationResult(
                    text="",
                    model=self.model,
                    provider=self.name,
                    success=False,
                    error=f"HTTP {response.status_code}",
                )
            
            data = response.json()
            text = data.get("response", "")
            
            return GenerationResult(
                text=text,
                model=self.model,
                provider=self.name,
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
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> GenerationResult:
        """Chat completion using Ollama"""
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
            
            response = requests.post(
                f"{self.host}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            
            if response.status_code != 200:
                return GenerationResult(
                    text="",
                    model=self.model,
                    provider=self.name,
                    success=False,
                    error=f"HTTP {response.status_code}",
                )
            
            data = response.json()
            text = data.get("message", {}).get("content", "")
            
            return GenerationResult(
                text=text,
                model=self.model,
                provider=self.name,
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


def get_ollama_provider(
    host: str = None,
    model: str = None,
) -> OllamaProvider:
    """Get Ollama provider instance"""
    return OllamaProvider(host=host, model=model)
