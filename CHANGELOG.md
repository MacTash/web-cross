# Changelog

All notable changes to Web-Cross will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-01-02

### Added

#### New Detection Modules
- **Open Redirect Scanner** - Detects URL redirect vulnerabilities with 10+ bypass techniques
- **Insecure Deserialization Scanner** - Java, PHP, Python pickle, .NET ViewState detection
- **WebSocket Security Scanner** - CSWSH, message injection, transport security checks
- **API Rate Limiting Tester** - Detects missing/weak rate limits and bypass techniques
- **Subdomain Takeover Checker** - 25+ cloud service fingerprints (AWS, Azure, GitHub, etc.)
- **Broken Access Control Scanner** - IDOR, HTTP method tampering, path-based bypass

#### AI/LLM Enhancements
- Multi-provider AI support (Groq Cloud + Ollama local)
- AI-powered payload mutation for WAF bypass
- Vulnerability chain analysis and attack path detection
- Natural language report generation

#### Performance Improvements
- Async HTTP client with httpx for concurrent scanning
- Response caching with SQLite persistence
- Token bucket rate limiting
- Scan state persistence for pause/resume capability

#### Reporting
- PDF report generation with WeasyPrint
- Modern HTML reports with dark/light theme toggle
- Compliance mapping (OWASP Top 10, CWE, PCI-DSS, NIST, GDPR)
- Interactive severity filtering

#### Infrastructure
- Centralized configuration system (Pydantic + YAML)
- SQLite database for scan history
- Docker containerization with multi-stage build
- GitHub Actions CI/CD pipeline
- Comprehensive test suite (50+ unit tests)

### Changed
- Updated `requirements.txt` with new dependencies
- Enhanced `modules/__init__.py` to export new scanners
- Improved logging with structured JSON output

### Fixed
- N/A (new release)

## [2.1.0] - 2025-XX-XX

### Added
- GraphQL vulnerability scanner
- SSTI (Server-Side Template Injection) scanner
- Enhanced WAF detection

---

## [2.0.0] - 2025-XX-XX

Initial open source release with core scanning capabilities.
