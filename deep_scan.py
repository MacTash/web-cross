#!/usr/bin/env python3
"""
Deep Security Analysis Script using Anthropic Claude
Run comprehensive security analysis beyond standard vulnerability scanning.

Usage:
    python deep_scan.py <url> --api-key <anthropic_key>
    
    # Or set environment variable
    ANTHROPIC_API_KEY=sk-ant-xxx python deep_scan.py <url>
"""

import argparse
import json
import os
import re
import sys
import warnings

import requests

warnings.filterwarnings('ignore')

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("Error: anthropic library not installed. Run: pip install anthropic")
    sys.exit(1)


DEEP_ANALYSIS_PROMPT = """You are an elite security researcher performing a comprehensive security assessment for a bug bounty program.

TARGET: {url}
The site has a bug bounty program inviting whitehats to find vulnerabilities.

=== HTTP RESPONSE HEADERS ===
{headers}

=== HTML PAGE SOURCE ===
{page_content}

=== JAVASCRIPT SOURCES (partial) ===
{js_content}

═══════════════════════════════════════════════════════════════════════════
COMPREHENSIVE SECURITY ANALYSIS REQUEST
═══════════════════════════════════════════════════════════════════════════

Go BEYOND traditional vulnerability scanning. Analyze this application holistically:

1. **CLIENT-SIDE SECRETS & MISCONFIGURATIONS**
   - API keys, tokens, credentials in HTML/JS
   - Firebase/Supabase/AWS configs exposed
   - Hardcoded secrets, debug flags
   - Environment variables leaked

2. **AUTHENTICATION & SESSION ANALYSIS**
   - JWT structure vulnerabilities (if visible)
   - Session token predictability
   - OAuth/OIDC misconfigurations
   - Authentication bypass vectors

3. **API SURFACE DISCOVERY**
   - API endpoints revealed in JS
   - GraphQL/REST endpoints
   - WebSocket endpoints
   - Hidden admin/debug endpoints

4. **BUSINESS LOGIC INSIGHTS**
   - User roles/permissions referenced
   - Payment/billing related code
   - Feature flags and toggles
   - Rate limiting indicators

5. **FRAMEWORK-SPECIFIC VULNERABILITIES**
   - Framework-specific issues (React, Vue, Angular, Nuxt, Next.js)
   - Server-side rendering (SSR) vectors
   - Hydration mismatches

6. **SUPPLY CHAIN & DEPENDENCIES**
   - Third-party scripts loaded
   - CDN integrity (SRI) checks
   - Vulnerable library indicators

7. **DATA EXPOSURE RISKS**
   - PII handling patterns
   - Database structure hints
   - Internal naming conventions
   - Debug/error messages

8. **NOVEL ATTACK VECTORS**
   - Prototype pollution opportunities
   - DOM clobbering possibilities
   - postMessage vulnerabilities
   - Service worker security

═══════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════════════

For EACH finding, provide:
- **Category**: (from above)
- **Severity**: Critical/High/Medium/Low/Info
- **Finding**: Clear description
- **Evidence**: EXACT code/text from the source
- **Exploitation**: How an attacker could exploit this
- **Remediation**: How to fix it

Also provide:
- **Attack Chain**: How multiple findings could be chained together
- **Priority Targets**: Top 3 things to investigate further
- **Recommended Tools**: Specific tools for deeper testing

Be thorough but precise. Only report findings with concrete evidence."""


def fetch_page_content(url: str) -> tuple[str, dict, str]:
    """Fetch page content, headers, and JS files."""
    print(f"[*] Fetching {url}...")
    
    resp = requests.get(url, timeout=30, verify=False)
    page_content = resp.text
    headers = dict(resp.headers)
    
    # Extract and fetch JS files
    js_content = ""
    js_matches = re.findall(r'src="([^"]*\.js[^"]*)"', page_content)
    
    for js_url in js_matches[:5]:  # First 5 JS files
        if js_url.startswith("/"):
            full_url = f"{url.rstrip('/')}{js_url}"
        elif not js_url.startswith("http"):
            full_url = f"{url.rstrip('/')}/{js_url}"
        else:
            full_url = js_url
        
        try:
            print(f"[*] Fetching JS: {full_url[:60]}...")
            js_resp = requests.get(full_url, timeout=10, verify=False)
            js_content += f"\n\n=== {full_url} ===\n{js_resp.text[:4000]}"
        except Exception as e:
            print(f"[!] Failed to fetch {full_url}: {e}")
    
    return page_content, headers, js_content[:15000]


def run_deep_analysis(url: str, api_key: str, model: str = "claude-sonnet-4-20250514"):
    """Run comprehensive security analysis using Anthropic Claude."""
    
    # Fetch content
    page_content, headers, js_content = fetch_page_content(url)
    
    # Format headers nicely
    headers_str = json.dumps(headers, indent=2)
    
    # Build prompt
    prompt = DEEP_ANALYSIS_PROMPT.format(
        url=url,
        headers=headers_str,
        page_content=page_content[:20000],
        js_content=js_content
    )
    
    print(f"\n[*] Sending to Claude ({model})...")
    print(f"[*] Prompt size: {len(prompt):,} characters")
    
    # Create client and send request
    client = anthropic.Anthropic(api_key=api_key)
    
    message = client.messages.create(
        model=model,
        max_tokens=8192,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    
    return message.content[0].text


def main():
    parser = argparse.ArgumentParser(
        description="Deep Security Analysis using Anthropic Claude",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python deep_scan.py https://example.com --api-key sk-ant-xxx
    ANTHROPIC_API_KEY=sk-ant-xxx python deep_scan.py https://example.com
    python deep_scan.py https://example.com --api-key sk-ant-xxx --model claude-3-opus-20240229
        """
    )
    
    parser.add_argument("url", help="Target URL to analyze")
    parser.add_argument("--api-key", help="Anthropic API key", 
                        default=os.getenv("ANTHROPIC_API_KEY"))
    parser.add_argument("--model", default="claude-sonnet-4-20250514",
                        help="Claude model to use")
    parser.add_argument("-o", "--output", help="Output file path")
    
    args = parser.parse_args()
    
    if not args.api_key:
        print("Error: Anthropic API key required. Use --api-key or set ANTHROPIC_API_KEY")
        sys.exit(1)
    
    print("=" * 80)
    print("DEEP SECURITY ANALYSIS - Anthropic Claude")
    print("=" * 80)
    print(f"Target: {args.url}")
    print(f"Model:  {args.model}")
    print("=" * 80)
    
    try:
        result = run_deep_analysis(args.url, args.api_key, args.model)
        
        print("\n" + "=" * 80)
        print("ANALYSIS RESULTS")
        print("=" * 80 + "\n")
        print(result)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"# Deep Security Analysis: {args.url}\n\n")
                f.write(result)
            print(f"\n[+] Results saved to: {args.output}")
            
    except anthropic.AuthenticationError:
        print("\n[!] ERROR: Invalid API key")
        sys.exit(1)
    except anthropic.RateLimitError:
        print("\n[!] ERROR: Rate limit exceeded")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
