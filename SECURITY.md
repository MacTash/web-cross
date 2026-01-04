# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| 2.x.x   | :x:                |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Web-Cross itself (not in targets you're scanning), please report it responsibly:

1. **DO NOT** open a public issue
2. Email: security@your-domain.com (replace with actual email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to understand and address the issue.

## Responsible Disclosure

- Allow reasonable time for fixes before public disclosure
- Do not exploit vulnerabilities beyond proof-of-concept
- Do not access or modify data beyond what's necessary to demonstrate the issue

## Security Best Practices for Users

1. **Always get authorization** before scanning any system
2. **Keep your API keys secure** - never commit `.env` files
3. **Run in isolated environments** when testing
4. **Review scan scope** to avoid unintended targets
5. **Update regularly** to get security patches

## Scope

This security policy applies to the Web-Cross scanner application itself, not to vulnerabilities discovered in target systems during scanning.
