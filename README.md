# Web-Cross Vulnerability Scanner v3.0

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9%2B-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/AI-Groq%20%7C%20Ollama-purple.svg" alt="AI">
</p>

A comprehensive, AI-powered web vulnerability scanner with 15+ detection modules, async performance, and compliance-ready reporting.

## ✨ Features

### Detection Modules
- **Injection**: SQL Injection, XSS, Command Injection, SSTI, XXE
- **Access Control**: IDOR, Broken Access Control, CSRF
- **Configuration**: CORS, Security Headers, Open Redirect
- **Modern Attacks**: GraphQL, WebSocket, Insecure Deserialization
- **Infrastructure**: Subdomain Takeover, Rate Limiting, JWT

### AI-Powered Analysis
- **Multi-model support**: Groq Cloud (fast) & Ollama (local)
- **Smart payload mutation** for WAF bypass
- **Vulnerability chaining** detection
- **Natural language reports**

### Enterprise Features
- Compliance mapping (OWASP Top 10, CWE, PCI-DSS, NIST, GDPR)
- PDF & HTML report generation
- Scan pause/resume capability
- Docker deployment ready

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web-cross.git
cd web-cross

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### Basic Usage

```bash
# Quick scan
python3 web-cross.py -u https://target.com

# Full scan with AI analysis
python3 web-cross.py -u https://target.com --full --ai

# Specific modules
python3 web-cross.py -u https://target.com --modules sqli,xss,csrf

# Generate PDF report
python3 web-cross.py -u https://target.com --report pdf
```

### Docker

```bash
# Build and run
docker-compose up -d

# With local AI (Ollama)
docker-compose --profile ai-local up -d
```

## 📊 Scan Modes

| Mode | Description |
|------|-------------|
| `--quick` | Fast scan with common vulnerabilities |
| `--full` | Complete scan with all modules |
| `--ai` | Enable AI-powered analysis |
| `--stealth` | Reduced rate for evasion |

## 🔧 Configuration

Configuration via environment variables or `config.yaml`:

```yaml
scanner:
  timeout: 10
  threads: 10
  rate_limit: 10  # requests/second

ai:
  provider: groq  # groq, ollama, or auto
  groq_model: llama-3.3-70b-versatile

reporting:
  format: html
  include_compliance: true
```

## 📁 Project Structure

```
web-cross/
├── modules/           # Detection modules
│   ├── ai/            # AI analysis components
│   ├── sql_injection.py
│   ├── xss.py
│   └── ...
├── core/              # Performance layer
│   ├── http_client.py
│   ├── cache.py
│   └── rate_limiter.py
├── reporting/         # Report generation
│   ├── pdf_generator.py
│   ├── html_generator.py
│   └── compliance.py
├── tests/             # Unit tests
├── config.py          # Configuration
└── web-cross.py       # Main entry point
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=modules --cov=core --cov-report=html
```

## ⚠️ Legal Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any systems. The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

## 📬 Contact

For issues and feature requests, please use [GitHub Issues](https://github.com/yourusername/web-cross/issues).
