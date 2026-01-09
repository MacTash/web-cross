"""
Module Registry - Thread-safe registry for module management.
Ported from sif's Go registry pattern.
"""

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .module import Module, ModuleType


class ModuleRegistry:
    """
    Thread-safe registry for managing scanner modules.
    
    Features:
    - Register modules by ID
    - Query by ID, tag, or type
    - Thread-safe operations
    """

    def __init__(self):
        self._modules: dict[str, "Module"] = {}
        self._lock = threading.RLock()

    def register(self, module: "Module") -> None:
        """
        Register a module with the registry.
        If a module with the same ID exists, it will be overwritten.
        """
        with self._lock:
            self._modules[module.info().id] = module

    def get(self, module_id: str) -> "Module | None":
        """Get a module by ID, returns None if not found"""
        with self._lock:
            return self._modules.get(module_id)

    def get_or_raise(self, module_id: str) -> "Module":
        """Get a module by ID, raises KeyError if not found"""
        with self._lock:
            if module_id not in self._modules:
                raise KeyError(f"Module not found: {module_id}")
            return self._modules[module_id]

    def all(self) -> list["Module"]:
        """Return all registered modules"""
        with self._lock:
            return list(self._modules.values())

    def by_tag(self, tag: str) -> list["Module"]:
        """Return modules matching a specific tag"""
        with self._lock:
            return [
                m for m in self._modules.values()
                if tag in m.info().tags
            ]

    def by_type(self, module_type: "ModuleType") -> list["Module"]:
        """Return modules of a specific type"""
        with self._lock:
            return [
                m for m in self._modules.values()
                if m.module_type() == module_type
            ]

    def by_severity(self, severity: str) -> list["Module"]:
        """Return modules matching a severity level"""
        with self._lock:
            return [
                m for m in self._modules.values()
                if m.info().severity.value == severity.lower()
            ]

    def count(self) -> int:
        """Return number of registered modules"""
        with self._lock:
            return len(self._modules)

    def clear(self) -> None:
        """Remove all modules (primarily for testing)"""
        with self._lock:
            self._modules.clear()

    def ids(self) -> list[str]:
        """Return all registered module IDs"""
        with self._lock:
            return list(self._modules.keys())

    def __contains__(self, module_id: str) -> bool:
        with self._lock:
            return module_id in self._modules

    def __len__(self) -> int:
        return self.count()


# Global singleton registry
_registry: ModuleRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> ModuleRegistry:
    """Get the global module registry (singleton)"""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ModuleRegistry()
    return _registry


# Convenience functions using global registry
def register(module: "Module") -> None:
    """Register a module with the global registry"""
    get_registry().register(module)


def get(module_id: str) -> "Module | None":
    """Get a module from the global registry"""
    return get_registry().get(module_id)


def all_modules() -> list["Module"]:
    """Get all modules from the global registry"""
    return get_registry().all()


def by_tag(tag: str) -> list["Module"]:
    """Get modules by tag from the global registry"""
    return get_registry().by_tag(tag)


def by_type(module_type: "ModuleType") -> list["Module"]:
    """Get modules by type from the global registry"""
    return get_registry().by_type(module_type)
