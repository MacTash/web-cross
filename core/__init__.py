"""
Web-Cross Core Module
Async HTTP client, caching, performance utilities, and module system.
"""

from .cache import ResponseCache, get_cache
from .executor import execute_http_module, execute_yaml_module
from .http_client import AsyncHTTPClient, HTTPResponse, get_http_client
from .module import (
    BaseModule,
    Finding,
    Module,
    ModuleInfo,
    ModuleOptions,
    ModuleResult,
    ModuleType,
    Severity,
)
from .output import (
    ModuleLogger,
    error,
    highlight,
    info,
    muted,
    print_summary,
    scan_complete,
    scan_start,
    severity_style,
    set_api_mode,
    status,
    success,
    warn,
)
from .progress import MultiProgress, ScanProgress, set_api_mode as set_progress_api_mode
from .rate_limiter import RateLimiter, get_rate_limiter
from .registry import (
    ModuleRegistry,
    all_modules,
    by_tag,
    by_type,
    get,
    get_registry,
    register,
)
from .spinner import SimpleSpinner, Spinner
from .state_manager import ScanStateManager, get_state_manager
from .worker_pool import WorkerPool, parallel_filter, parallel_map
from .yaml_modules import (
    Extractor,
    HTTPConfig,
    Matcher,
    YAMLModule,
    check_matchers,
    load_yaml_module,
    load_yaml_modules_from_dir,
    run_extractors,
    substitute_variables,
)

__all__ = [
    # HTTP Client
    "AsyncHTTPClient",
    "HTTPResponse",
    "get_http_client",
    # Cache
    "ResponseCache",
    "get_cache",
    # Rate Limiter
    "RateLimiter",
    "get_rate_limiter",
    # State Manager
    "ScanStateManager",
    "get_state_manager",
    # Module System
    "Module",
    "BaseModule",
    "ModuleInfo",
    "ModuleType",
    "ModuleOptions",
    "ModuleResult",
    "Finding",
    "Severity",
    # Registry
    "ModuleRegistry",
    "get_registry",
    "register",
    "get",
    "all_modules",
    "by_tag",
    "by_type",
    # Worker Pool
    "WorkerPool",
    "parallel_map",
    "parallel_filter",
    # YAML Modules
    "YAMLModule",
    "HTTPConfig",
    "Matcher",
    "Extractor",
    "load_yaml_module",
    "load_yaml_modules_from_dir",
    "substitute_variables",
    "check_matchers",
    "run_extractors",
    # Executor
    "execute_http_module",
    "execute_yaml_module",
    # Output
    "ModuleLogger",
    "info",
    "success",
    "warn",
    "error",
    "scan_start",
    "scan_complete",
    "highlight",
    "muted",
    "status",
    "severity_style",
    "print_summary",
    "set_api_mode",
    # Progress
    "ScanProgress",
    "MultiProgress",
    "set_progress_api_mode",
    # Spinner
    "Spinner",
    "SimpleSpinner",
]

