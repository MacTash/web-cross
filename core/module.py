"""
Module System - Core interfaces and types for modular scanner architecture.
Inspired by sif's Go module system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class ModuleType(Enum):
    """Type of module"""
    HTTP = "http"
    DNS = "dns"
    TCP = "tcp"
    SCRIPT = "script"


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        """Get numeric score for severity"""
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from string"""
        return cls(value.lower())


@dataclass
class ModuleInfo:
    """Module metadata"""
    id: str
    name: str
    author: str = "webcross"
    severity: Severity = Severity.INFO
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "author": self.author,
            "severity": self.severity.value,
            "description": self.description,
            "tags": self.tags,
        }


@dataclass
class ModuleOptions:
    """Options for module execution"""
    timeout: int = 10
    threads: int = 10
    log_dir: str | None = None
    user_agent: str = "WebCross-Scanner/3.0"
    verify_ssl: bool = False
    follow_redirects: bool = True
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    """A single finding from module execution"""
    url: str = ""
    severity: Severity = Severity.INFO
    evidence: str = ""
    extracted: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "extracted": self.extracted,
        }


@dataclass
class ModuleResult:
    """Result from module execution"""
    module_id: str
    target: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
        }


@runtime_checkable
class Module(Protocol):
    """Protocol for all modules to implement"""

    def info(self) -> ModuleInfo:
        """Return module metadata"""
        ...

    def module_type(self) -> ModuleType:
        """Return the module type"""
        ...

    async def execute(self, target: str, opts: ModuleOptions) -> ModuleResult:
        """Execute the module against target"""
        ...


class BaseModule(ABC):
    """Base class for modules providing common functionality"""

    @abstractmethod
    def info(self) -> ModuleInfo:
        """Return module metadata"""
        pass

    @abstractmethod
    def module_type(self) -> ModuleType:
        """Return the module type"""
        pass

    @abstractmethod
    async def execute(self, target: str, opts: ModuleOptions) -> ModuleResult:
        """Execute the module against target"""
        pass

    def __repr__(self) -> str:
        return f"<Module {self.info().id}>"
