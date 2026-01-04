"""Web-Cross Vulnerability Scanner Modules v3.0"""

# Core scanners
from .sql_injection import SQLiScanner
from .xss import XSSScanner
from .csrf import CSRFScanner
from .html_attacks import HTMLAttackScanner
from .input_fields import InputFieldScanner
from .headers import HeaderScanner

# Advanced scanners
from .command_injection import CommandInjectionScanner
from .path_traversal import PathTraversalScanner
from .ssrf import SSRFScanner
from .xxe import XXEScanner
from .cors import CORSScanner
from .jwt import JWTScanner

# Recon modules
from .fingerprint import TechFingerprinter
from .waf import WAFDetector
from .directory import DirectoryScanner

# AI-powered analysis
from .llm_analyzer import LLMAnalyzer, get_analyzer

# 2025 New Scanners
from .graphql import GraphQLScanner, get_scanner as get_graphql_scanner
from .ssti import SSTIScanner, get_scanner as get_ssti_scanner

# 2026 v3.0 New Scanners
from .open_redirect import OpenRedirectScanner, get_scanner as get_open_redirect_scanner
from .deserialization import DeserializationScanner, get_scanner as get_deserialization_scanner
from .websocket_scanner import WebSocketScanner, get_scanner as get_websocket_scanner
from .rate_limiting import RateLimitingScanner, get_scanner as get_rate_limiting_scanner
from .subdomain_takeover import SubdomainTakeoverScanner, get_scanner as get_subdomain_takeover_scanner
from .broken_access import BrokenAccessScanner, get_scanner as get_broken_access_scanner

__all__ = [
    # Core
    'SQLiScanner',
    'XSSScanner', 
    'CSRFScanner',
    'HTMLAttackScanner',
    'InputFieldScanner',
    'HeaderScanner',
    # Advanced
    'CommandInjectionScanner',
    'PathTraversalScanner',
    'SSRFScanner',
    'XXEScanner',
    'CORSScanner',
    'JWTScanner',
    # Recon
    'TechFingerprinter',
    'WAFDetector',
    'DirectoryScanner',
    # AI
    'LLMAnalyzer',
    'get_analyzer',
    # 2025 New
    'GraphQLScanner',
    'get_graphql_scanner',
    'SSTIScanner',
    'get_ssti_scanner',
    # 2026 v3.0 New
    'OpenRedirectScanner',
    'get_open_redirect_scanner',
    'DeserializationScanner',
    'get_deserialization_scanner',
    'WebSocketScanner',
    'get_websocket_scanner',
    'RateLimitingScanner',
    'get_rate_limiting_scanner',
    'SubdomainTakeoverScanner',
    'get_subdomain_takeover_scanner',
    'BrokenAccessScanner',
    'get_broken_access_scanner',
]
