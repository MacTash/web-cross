"""Web-Cross Vulnerability Scanner Modules v3.0"""

# Core scanners
from .broken_access import BrokenAccessScanner
from .broken_access import get_scanner as get_broken_access_scanner

# Advanced scanners
from .command_injection import CommandInjectionScanner
from .cors import CORSScanner
from .csrf import CSRFScanner
from .deserialization import DeserializationScanner
from .deserialization import get_scanner as get_deserialization_scanner
from .directory import DirectoryScanner

# Recon modules
from .fingerprint import TechFingerprinter

# 2025 New Scanners
from .graphql import GraphQLScanner
from .graphql import get_scanner as get_graphql_scanner
from .headers import HeaderScanner
from .html_attacks import HTMLAttackScanner
from .input_fields import InputFieldScanner
from .jwt import JWTScanner

# AI-powered analysis
from .llm_analyzer import LLMAnalyzer, get_analyzer

# 2026 v3.0 New Scanners
from .open_redirect import OpenRedirectScanner
from .open_redirect import get_scanner as get_open_redirect_scanner
from .path_traversal import PathTraversalScanner
from .rate_limiting import RateLimitingScanner
from .rate_limiting import get_scanner as get_rate_limiting_scanner
from .sql_injection import SQLiScanner
from .ssrf import SSRFScanner
from .ssti import SSTIScanner
from .ssti import get_scanner as get_ssti_scanner
from .subdomain_takeover import SubdomainTakeoverScanner
from .subdomain_takeover import get_scanner as get_subdomain_takeover_scanner
from .waf import WAFDetector
from .websocket_scanner import WebSocketScanner
from .websocket_scanner import get_scanner as get_websocket_scanner
from .xss import XSSScanner
from .xxe import XXEScanner

# 2026 v3.1 Sif-ported Scanners
from .cloud_storage import CloudStorageScanner
from .cloud_storage import get_scanner as get_cloud_storage_scanner
from .supabase import SupabaseScanner
from .supabase import get_scanner as get_supabase_scanner

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
    # 2026 v3.1 Sif-ported
    'CloudStorageScanner',
    'get_cloud_storage_scanner',
    'SupabaseScanner',
    'get_supabase_scanner',
]

