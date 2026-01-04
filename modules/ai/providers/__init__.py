"""
AI Provider Base Class
Abstract interface for LLM providers.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class GenerationResult:
    """Result from LLM generation"""
    text: str
    model: str
    provider: str
    tokens_used: int = 0
    success: bool = True
    error: Optional[str] = None


class AIProvider(ABC):
    """Abstract base class for AI providers"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name"""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available"""
        pass
    
    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> GenerationResult:
        """Generate text from prompt"""
        pass
    
    @abstractmethod
    def generate_json(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> Dict[str, Any]:
        """Generate JSON response"""
        pass
