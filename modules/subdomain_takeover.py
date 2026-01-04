"""
Subdomain Takeover Scanner Module
Detects dangling DNS records that can be hijacked.
"""

import re
import socket
from typing import Any
from urllib.parse import urlparse

import requests

try:
    import dns.exception
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class SubdomainTakeoverScanner:
    """
    Subdomain Takeover vulnerability scanner.

    Detects:
    - Dangling CNAME records pointing to deprovisioned services
    - Vulnerable cloud service configurations (AWS, Azure, GitHub, etc.)
    - Unclaimed service endpoints
    - DNS misconfigurations
    """

    # Known vulnerable service fingerprints
    # Format: (service_name, cname_pattern, response_fingerprint, severity)
    VULNERABLE_SERVICES = [
        # AWS
        {
            "name": "AWS S3",
            "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3-.*\.amazonaws\.com$"],
            "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
            "severity": "HIGH",
        },
        {
            "name": "AWS Elastic Beanstalk",
            "cname_patterns": [r"\.elasticbeanstalk\.com$"],
            "fingerprints": ["NXDOMAIN"],
            "severity": "HIGH",
        },
        {
            "name": "AWS CloudFront",
            "cname_patterns": [r"\.cloudfront\.net$"],
            "fingerprints": ["Bad Request", "ERROR: The request could not be satisfied"],
            "severity": "HIGH",
        },
        # Azure
        {
            "name": "Azure Websites",
            "cname_patterns": [r"\.azurewebsites\.net$"],
            "fingerprints": ["404 Web Site not found", "The specified Azure Container"],
            "severity": "HIGH",
        },
        {
            "name": "Azure Blob",
            "cname_patterns": [r"\.blob\.core\.windows\.net$"],
            "fingerprints": ["BlobNotFound", "The specified blob does not exist"],
            "severity": "HIGH",
        },
        {
            "name": "Azure Traffic Manager",
            "cname_patterns": [r"\.trafficmanager\.net$"],
            "fingerprints": ["NXDOMAIN"],
            "severity": "HIGH",
        },
        # GitHub
        {
            "name": "GitHub Pages",
            "cname_patterns": [r"\.github\.io$", r"\.githubusercontent\.com$"],
            "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
            "severity": "HIGH",
        },
        # Heroku
        {
            "name": "Heroku",
            "cname_patterns": [r"\.herokuapp\.com$", r"\.herokussl\.com$"],
            "fingerprints": ["No such app", "There's nothing here, yet"],
            "severity": "HIGH",
        },
        # Shopify
        {
            "name": "Shopify",
            "cname_patterns": [r"\.myshopify\.com$"],
            "fingerprints": ["Sorry, this shop is currently unavailable"],
            "severity": "MEDIUM",
        },
        # Tumblr
        {
            "name": "Tumblr",
            "cname_patterns": [r"\.tumblr\.com$"],
            "fingerprints": ["There's nothing here", "Whatever you were looking for"],
            "severity": "MEDIUM",
        },
        # WordPress
        {
            "name": "WordPress.com",
            "cname_patterns": [r"\.wordpress\.com$"],
            "fingerprints": ["Do you want to register"],
            "severity": "MEDIUM",
        },
        # Pantheon
        {
            "name": "Pantheon",
            "cname_patterns": [r"\.pantheonsite\.io$"],
            "fingerprints": ["The gods are wise", "404 error"],
            "severity": "MEDIUM",
        },
        # Fastly
        {
            "name": "Fastly",
            "cname_patterns": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
            "fingerprints": ["Fastly error: unknown domain"],
            "severity": "HIGH",
        },
        # Ghost
        {
            "name": "Ghost",
            "cname_patterns": [r"\.ghost\.io$"],
            "fingerprints": ["The thing you were looking for is no longer here"],
            "severity": "MEDIUM",
        },
        # Surge
        {
            "name": "Surge.sh",
            "cname_patterns": [r"\.surge\.sh$"],
            "fingerprints": ["project not found"],
            "severity": "MEDIUM",
        },
        # Bitbucket
        {
            "name": "Bitbucket",
            "cname_patterns": [r"\.bitbucket\.io$"],
            "fingerprints": ["Repository not found"],
            "severity": "MEDIUM",
        },
        # Zendesk
        {
            "name": "Zendesk",
            "cname_patterns": [r"\.zendesk\.com$"],
            "fingerprints": ["Help Center Closed", "Oops, this help center"],
            "severity": "MEDIUM",
        },
        # Unbounce
        {
            "name": "Unbounce",
            "cname_patterns": [r"\.unbounce\.com$", r"unbouncepages\.com$"],
            "fingerprints": ["The requested URL was not found"],
            "severity": "MEDIUM",
        },
        # Desk
        {
            "name": "Desk",
            "cname_patterns": [r"\.desk\.com$"],
            "fingerprints": ["Please try again or try Desk.com free"],
            "severity": "LOW",
        },
        # Teamwork
        {
            "name": "Teamwork",
            "cname_patterns": [r"\.teamwork\.com$"],
            "fingerprints": ["Oops - We didn't find your site"],
            "severity": "LOW",
        },
        # Helpjuice
        {
            "name": "Helpjuice",
            "cname_patterns": [r"\.helpjuice\.com$"],
            "fingerprints": ["We could not find what you're looking for"],
            "severity": "LOW",
        },
        # Helpscout
        {
            "name": "Helpscout",
            "cname_patterns": [r"\.helpscoutdocs\.com$"],
            "fingerprints": ["No settings were found for this company"],
            "severity": "LOW",
        },
        # Cargo
        {
            "name": "Cargo",
            "cname_patterns": [r"\.cargocollective\.com$"],
            "fingerprints": ["404 Not Found"],
            "severity": "LOW",
        },
        # Feedpress
        {
            "name": "Feedpress",
            "cname_patterns": [r"\.feedpress\.me$", r"redirect\.feedpress\.me$"],
            "fingerprints": ["The feed has not been found"],
            "severity": "LOW",
        },
        # Netlify
        {
            "name": "Netlify",
            "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
            "fingerprints": ["Not Found", "Page not found"],
            "severity": "MEDIUM",
        },
        # Vercel/Zeit
        {
            "name": "Vercel",
            "cname_patterns": [r"\.vercel\.app$", r"\.now\.sh$"],
            "fingerprints": ["The deployment could not be found"],
            "severity": "MEDIUM",
        },
        # Firebase
        {
            "name": "Firebase",
            "cname_patterns": [r"\.firebaseapp\.com$", r"\.web\.app$"],
            "fingerprints": ["Site Not Found"],
            "severity": "MEDIUM",
        },
    ]

    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })

        # DNS resolver
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout

    def _get_cname_records(self, domain: str) -> list[str]:
        """Get CNAME records for a domain"""
        if not DNS_AVAILABLE:
            return []

        cnames = []
        try:
            answers = self.resolver.resolve(domain, "CNAME")
            for rdata in answers:
                cnames.append(str(rdata.target).rstrip("."))
        except dns.exception.DNSException:
            pass

        return cnames

    def _check_domain_exists(self, domain: str) -> bool:
        """Check if domain resolves to any address"""
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

    def _get_http_response(self, domain: str) -> requests.Response | None:
        """Get HTTP response from domain"""
        for scheme in ["https", "http"]:
            try:
                response = self.session.get(
                    f"{scheme}://{domain}",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                return response
            except requests.RequestException:
                continue
        return None

    def _match_fingerprint(
        self,
        response: requests.Response,
        fingerprints: list[str],
    ) -> str | None:
        """Check if response matches any fingerprint"""
        content = response.text

        for fingerprint in fingerprints:
            if fingerprint == "NXDOMAIN":
                continue  # Handled separately
            if fingerprint.lower() in content.lower():
                return fingerprint

        return None

    def _check_subdomain_vulnerable(
        self,
        subdomain: str,
    ) -> list[dict[str, Any]]:
        """Check if a subdomain is vulnerable to takeover"""
        findings = []

        # Get CNAME records
        cnames = self._get_cname_records(subdomain)

        if not cnames:
            # No CNAME - check A record
            if not self._check_domain_exists(subdomain):
                # Domain doesn't resolve at all
                findings.append({
                    "type": "SUBDOMAIN_TAKEOVER",
                    "subtype": "DANGLING_RECORD",
                    "subdomain": subdomain,
                    "evidence": "Domain does not resolve to any IP address",
                    "severity": "MEDIUM",
                    "confidence": "LOW",
                    "description": (
                        f"Subdomain {subdomain} does not resolve. "
                        f"This might indicate a dangling DNS record."
                    ),
                    "remediation": (
                        "Remove unused DNS records. "
                        "Ensure all subdomains point to active resources."
                    ),
                    "owasp": "A05:2021",
                    "cwe": "CWE-284",
                })
            return findings

        # Check each CNAME against known vulnerable services
        for cname in cnames:
            for service in self.VULNERABLE_SERVICES:
                # Check if CNAME matches service pattern
                for pattern in service["cname_patterns"]:
                    if re.search(pattern, cname, re.IGNORECASE):
                        # Found matching service - check if vulnerable

                        # First check if CNAME target resolves
                        if not self._check_domain_exists(cname):
                            findings.append({
                                "type": "SUBDOMAIN_TAKEOVER",
                                "subtype": service["name"].upper().replace(" ", "_"),
                                "subdomain": subdomain,
                                "cname": cname,
                                "service": service["name"],
                                "evidence": f"CNAME target {cname} does not resolve (NXDOMAIN)",
                                "severity": service["severity"],
                                "confidence": "HIGH",
                                "description": (
                                    f"Subdomain {subdomain} has CNAME pointing to "
                                    f"{service['name']} ({cname}) which does not exist. "
                                    f"An attacker can claim this endpoint to take over the subdomain."
                                ),
                                "remediation": (
                                    f"Remove the DNS record for {subdomain} or "
                                    f"reclaim the {service['name']} resource. "
                                    f"Monitor for dangling records."
                                ),
                                "owasp": "A05:2021",
                                "cwe": "CWE-284",
                            })
                            break

                        # CNAME resolves - check HTTP response fingerprint
                        response = self._get_http_response(subdomain)
                        if response:
                            matched = self._match_fingerprint(
                                response,
                                service["fingerprints"],
                            )
                            if matched:
                                findings.append({
                                    "type": "SUBDOMAIN_TAKEOVER",
                                    "subtype": service["name"].upper().replace(" ", "_"),
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": service["name"],
                                    "evidence": f"Response matches fingerprint: {matched}",
                                    "severity": service["severity"],
                                    "confidence": "HIGH",
                                    "description": (
                                        f"Subdomain {subdomain} points to unclaimed "
                                        f"{service['name']} resource. The service "
                                        f"indicates the resource is available for claiming."
                                    ),
                                    "remediation": (
                                        f"Claim the {service['name']} resource or "
                                        f"remove the DNS record. Register the resource "
                                        f"before an attacker does."
                                    ),
                                    "owasp": "A05:2021",
                                    "cwe": "CWE-284",
                                })
                        break

        return findings

    def _discover_subdomains(self, domain: str) -> set[str]:
        """Discover subdomains from various sources"""
        subdomains = set()

        # Common subdomain prefixes
        common_prefixes = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
            "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
            "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
            "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
            "2tty", "vps", "govyty", "hgfgdf", "news", "1mail", "static", "staging",
            "beta", "alpha", "demo", "v2", "api2", "internal", "external", "legacy",
        ]

        for prefix in common_prefixes:
            subdomains.add(f"{prefix}.{domain}")

        return subdomains

    def scan_domain(self, domain: str) -> list[dict[str, Any]]:
        """
        Scan a domain for subdomain takeover vulnerabilities.

        Args:
            domain: Target domain to scan (e.g., example.com)

        Returns:
            List of vulnerability findings
        """
        findings = []

        if not DNS_AVAILABLE:
            return [{
                "type": "SCAN_ERROR",
                "message": "dnspython library not installed. Run: pip install dnspython",
            }]

        # Extract base domain from URL if needed
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc

        # Remove any port
        domain = domain.split(":")[0]

        # Discover subdomains
        subdomains = self._discover_subdomains(domain)

        # Also check the main domain
        subdomains.add(domain)

        # Check each subdomain
        for subdomain in subdomains:
            subdomain_findings = self._check_subdomain_vulnerable(subdomain)
            findings.extend(subdomain_findings)

        return findings

    def scan_subdomain(self, subdomain: str) -> list[dict[str, Any]]:
        """
        Scan a specific subdomain for takeover vulnerability.

        Args:
            subdomain: Specific subdomain to check

        Returns:
            List of vulnerability findings
        """
        if not DNS_AVAILABLE:
            return [{
                "type": "SCAN_ERROR",
                "message": "dnspython library not installed",
            }]

        # Clean subdomain
        if subdomain.startswith(("http://", "https://")):
            subdomain = urlparse(subdomain).netloc
        subdomain = subdomain.split(":")[0]

        return self._check_subdomain_vulnerable(subdomain)

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """
        Scan URL for subdomain takeover (extracts domain from URL).

        Args:
            url: Target URL

        Returns:
            List of vulnerability findings
        """
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]

        # Check if it's already a subdomain or base domain
        parts = domain.split(".")
        if len(parts) > 2:
            # It's a subdomain - check it specifically
            return self.scan_subdomain(domain)
        else:
            # It's a base domain - scan for vulnerable subdomains
            return self.scan_domain(domain)


def get_scanner(timeout: int = 10, user_agent: str = None) -> SubdomainTakeoverScanner:
    """Get a Subdomain Takeover scanner instance"""
    return SubdomainTakeoverScanner(timeout=timeout, user_agent=user_agent)
