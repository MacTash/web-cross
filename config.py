"""
Web-Cross v3.0 Configuration Module
Centralized configuration using Pydantic Settings with YAML and .env support.
"""

import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Literal
from functools import lru_cache

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Base directory
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / "config.yaml"
ENV_FILE = BASE_DIR / ".env"


class ScannerSettings(BaseSettings):
    """Scanner-specific settings"""
    timeout: int = Field(default=10, description="Request timeout in seconds")
    threads: int = Field(default=10, description="Number of concurrent threads")
    max_depth: int = Field(default=3, description="Maximum crawl depth")
    max_urls: int = Field(default=100, description="Maximum URLs to crawl")
    user_agent: str = Field(
        default="WebCross-Scanner/3.0 (Security Testing)",
        description="User agent string"
    )
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    
    # Rate limiting
    rate_limit_requests: int = Field(default=10, description="Requests per second limit")
    rate_limit_burst: int = Field(default=20, description="Burst limit for rate limiting")
    
    # Scope limiting
    scope_include: List[str] = Field(default_factory=list, description="Domains to include in scope")
    scope_exclude: List[str] = Field(default_factory=list, description="Domains to exclude from scope")
    
    # Scan modes
    default_mode: Literal["full", "quick", "core", "advanced", "recon"] = Field(
        default="full", description="Default scan mode"
    )


class AISettings(BaseSettings):
    """AI/LLM provider settings"""
    # Provider selection
    provider: Literal["ollama", "groq", "auto"] = Field(
        default="auto", 
        description="AI provider: ollama (local), groq (cloud), or auto (try groq, fallback to ollama)"
    )
    
    # Ollama settings
    ollama_host: str = Field(default="http://localhost:11434", description="Ollama server URL")
    ollama_model: str = Field(default="llama3.2:3b", description="Ollama model name")
    
    # Groq settings
    groq_api_key: Optional[str] = Field(default=None, description="Groq API key")
    groq_model: str = Field(default="llama-3.3-70b-versatile", description="Groq model name")
    
    # Generation settings
    temperature: float = Field(default=0.3, description="LLM temperature")
    max_tokens: int = Field(default=2048, description="Maximum tokens for generation")
    timeout: int = Field(default=60, description="AI request timeout")
    
    # Features
    enable_payload_mutation: bool = Field(default=True, description="Enable AI payload mutation")
    enable_chain_analysis: bool = Field(default=True, description="Enable vulnerability chaining")
    enable_natural_reports: bool = Field(default=True, description="Enable natural language reports")
    
    model_config = SettingsConfigDict(env_prefix="WEBCROSS_AI_")


class DatabaseSettings(BaseSettings):
    """Database settings for scan history"""
    enabled: bool = Field(default=True, description="Enable database storage")
    url: str = Field(
        default=f"sqlite:///{BASE_DIR / 'data' / 'webcross.db'}", 
        description="Database URL"
    )
    echo: bool = Field(default=False, description="Echo SQL queries")
    
    # History settings
    max_history_days: int = Field(default=90, description="Days to keep scan history")
    auto_cleanup: bool = Field(default=True, description="Auto cleanup old records")
    
    model_config = SettingsConfigDict(env_prefix="WEBCROSS_DB_")


class ReportingSettings(BaseSettings):
    """Reporting settings"""
    output_dir: Path = Field(default=BASE_DIR, description="Report output directory")
    default_format: Literal["html", "json", "text", "pdf", "all"] = Field(
        default="html", description="Default report format"
    )
    
    # PDF settings
    pdf_enabled: bool = Field(default=True, description="Enable PDF generation")
    
    # Compliance mapping
    include_owasp: bool = Field(default=True, description="Include OWASP Top 10 mapping")
    include_cwe: bool = Field(default=True, description="Include CWE references")
    include_cvss: bool = Field(default=True, description="Include CVSS scores")
    
    # Trend analysis
    enable_trends: bool = Field(default=True, description="Enable historical trend analysis")


class ServerSettings(BaseSettings):
    """Web server settings"""
    host: str = Field(default="127.0.0.1", description="Server bind address")
    port: int = Field(default=5000, description="Server port")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # Authentication
    auth_enabled: bool = Field(default=False, description="Enable authentication")
    secret_key: str = Field(
        default="change-me-in-production", 
        description="Flask secret key"
    )
    
    # Session
    session_lifetime_hours: int = Field(default=24, description="Session lifetime")
    
    model_config = SettingsConfigDict(env_prefix="WEBCROSS_SERVER_")


class WebCrossConfig(BaseSettings):
    """Main configuration class"""
    # Sub-configurations
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    ai: AISettings = Field(default_factory=AISettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    
    # Global settings
    version: str = "3.0"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="Logging level"
    )
    log_file: Optional[Path] = Field(default=None, description="Log file path")
    
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE) if ENV_FILE.exists() else None,
        env_prefix="WEBCROSS_",
        env_nested_delimiter="__",
        extra="ignore"
    )
    
    @classmethod
    def from_yaml(cls, config_path: Path = CONFIG_FILE) -> "WebCrossConfig":
        """Load configuration from YAML file"""
        if not config_path.exists():
            return cls()
        
        with open(config_path, "r") as f:
            yaml_config = yaml.safe_load(f) or {}
        
        # Merge YAML config with defaults
        return cls(**yaml_config)
    
    def to_yaml(self, config_path: Path = CONFIG_FILE) -> None:
        """Save configuration to YAML file"""
        config_dict = self.model_dump(exclude_none=True)
        
        # Convert Path objects to strings
        def convert_paths(obj: Any) -> Any:
            if isinstance(obj, Path):
                return str(obj)
            elif isinstance(obj, dict):
                return {k: convert_paths(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_paths(v) for v in obj]
            return obj
        
        config_dict = convert_paths(config_dict)
        
        with open(config_path, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)


@lru_cache()
def get_config() -> WebCrossConfig:
    """Get singleton configuration instance"""
    # Try loading from YAML first, then fall back to env vars
    if CONFIG_FILE.exists():
        return WebCrossConfig.from_yaml(CONFIG_FILE)
    return WebCrossConfig()


def reload_config() -> WebCrossConfig:
    """Reload configuration (clears cache)"""
    get_config.cache_clear()
    return get_config()


# Convenience accessors
def get_scanner_config() -> ScannerSettings:
    return get_config().scanner


def get_ai_config() -> AISettings:
    return get_config().ai


def get_db_config() -> DatabaseSettings:
    return get_config().database


def get_reporting_config() -> ReportingSettings:
    return get_config().reporting


def get_server_config() -> ServerSettings:
    return get_config().server
