# Contributing to Web-Cross

Thank you for your interest in contributing to Web-Cross! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful and constructive. We're all here to make security testing better.

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Discuss implementation approach if possible

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes following our coding standards
4. Write/update tests
5. Run the test suite
   ```bash
   pytest tests/ -v
   ```
6. Run linting
   ```bash
   ruff check .
   ```
7. Commit with clear messages
8. Push and create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/web-cross.git
cd web-cross

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install pytest pytest-cov ruff mypy
```

## Coding Standards

### Python Style
- Follow PEP 8
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use docstrings for classes and public functions

### File Structure
- New scanners go in `modules/`
- Core utilities go in `core/`
- Reporting features go in `reporting/`
- Tests mirror the source structure in `tests/`

### Testing Requirements
- All new features need tests
- Maintain or improve code coverage
- Use pytest fixtures for common test data

### Commit Messages
- Use present tense ("Add feature" not "Added feature")
- Be descriptive but concise
- Reference issues when applicable

## Adding a New Scanner Module

1. Create `modules/your_scanner.py`:
   ```python
   class YourScanner:
       def __init__(self, timeout: int = 10):
           self.timeout = timeout
       
       def scan_url(self, url: str) -> List[Dict]:
           # Implementation
           pass
   
   def get_scanner(**kwargs) -> YourScanner:
       return YourScanner(**kwargs)
   ```

2. Add to `modules/__init__.py`:
   ```python
   from .your_scanner import YourScanner, get_scanner as get_your_scanner
   ```

3. Create tests in `tests/modules/test_your_scanner.py`

4. Update documentation

## Questions?

Open a discussion or issue if you have questions!
