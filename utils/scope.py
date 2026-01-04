"""
Web-Cross Scope Validator
URL and domain scope limiting to prevent unintended scanning.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScopeValidator:
    """
    Validates URLs and domains against configured scope rules.
    Prevents scanning of out-of-scope targets.
    """

    # Domains/patterns to include (empty = allow all)
    include_domains: list[str] = field(default_factory=list)

    # Domains/patterns to exclude
    exclude_domains: list[str] = field(default_factory=list)

    # IP ranges to include (CIDR notation)
    include_ips: list[str] = field(default_factory=list)

    # IP ranges to exclude
    exclude_ips: list[str] = field(default_factory=list)

    # Always excluded (private networks, localhost)
    exclude_private: bool = True

    # Excluded TLDs (internal/reserved)
    excluded_tlds: set[str] = field(default_factory=lambda: {
        "local", "localhost", "internal", "lan", "home",
        "corp", "example", "test", "invalid",
    })

    # Critical domains that should never be scanned
    critical_blacklist: set[str] = field(default_factory=lambda: {
        # Major platforms
        "google.com", "googleapis.com", "gstatic.com",
        "facebook.com", "fb.com", "fbcdn.net",
        "twitter.com", "x.com", "twimg.com",
        "microsoft.com", "azure.com", "office.com", "live.com",
        "amazon.com", "amazonaws.com", "aws.amazon.com",
        "apple.com", "icloud.com",
        # Infrastructure
        "cloudflare.com", "cloudflare-dns.com",
        "akamai.com", "akamaitechnologies.com",
        "fastly.com", "jsdelivr.net",
        # Security services
        "virustotal.com", "shodan.io",
        # Payment
        "paypal.com", "stripe.com",
        # Government
        "gov", "mil",
    })

    def __post_init__(self):
        """Compile patterns after initialization"""
        self._include_patterns = self._compile_patterns(self.include_domains)
        self._exclude_patterns = self._compile_patterns(self.exclude_domains)
        self._include_networks = self._parse_networks(self.include_ips)
        self._exclude_networks = self._parse_networks(self.exclude_ips)

    def _compile_patterns(self, patterns: list[str]) -> list[re.Pattern]:
        """Compile domain patterns to regex"""
        compiled = []
        for pattern in patterns:
            # Convert glob-like patterns to regex
            regex = pattern.replace(".", r"\.")
            regex = regex.replace("*", r".*")
            regex = f"^{regex}$"
            try:
                compiled.append(re.compile(regex, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid pattern '{pattern}': {e}")
        return compiled

    def _parse_networks(self, networks: list[str]) -> list[ipaddress.IPv4Network]:
        """Parse CIDR network strings"""
        parsed = []
        for network in networks:
            try:
                parsed.append(ipaddress.ip_network(network, strict=False))
            except ValueError as e:
                logger.warning(f"Invalid network '{network}': {e}")
        return parsed

    def _extract_domain(self, url: str) -> str | None:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower().split(":")[0]  # Remove port
        except Exception:
            return None

    def _is_ip_address(self, host: str) -> bool:
        """Check if host is an IP address"""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _is_private_ip(self, host: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_reserved
        except ValueError:
            return False

    def _domain_matches_patterns(
        self,
        domain: str,
        patterns: list[re.Pattern]
    ) -> bool:
        """Check if domain matches any pattern"""
        for pattern in patterns:
            if pattern.match(domain):
                return True
        return False

    def _ip_in_networks(
        self,
        ip_str: str,
        networks: list[ipaddress.IPv4Network]
    ) -> bool:
        """Check if IP is in any network range"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in networks:
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain"""
        parts = domain.split(".")
        return parts[-1] if parts else ""

    def _is_subdomain_of(self, domain: str, parent: str) -> bool:
        """Check if domain is a subdomain of parent"""
        return domain == parent or domain.endswith(f".{parent}")

    def is_critical_blacklisted(self, domain: str) -> bool:
        """Check if domain is in critical blacklist"""
        for blacklisted in self.critical_blacklist:
            if self._is_subdomain_of(domain, blacklisted):
                return True
        return False

    def validate_url(self, url: str) -> tuple[bool, str]:
        """
        Validate if URL is in scope.
        Returns:
            Tuple of (is_valid, reason)
        """
        domain = self._extract_domain(url)
        if not domain:
            return False, "Invalid URL format"

        # Check TLD
        tld = self._get_tld(domain)
        if tld in self.excluded_tlds:
            return False, f"Excluded TLD: .{tld}"

        # Check critical blacklist
        if self.is_critical_blacklisted(domain):
            return False, f"Critical blacklist: {domain}"

        # Handle IP addresses
        if self._is_ip_address(domain):
            # Check private IP exclusion
            if self.exclude_private and self._is_private_ip(domain):
                return False, "Private IP addresses excluded"

            # Check IP exclusions
            if self._exclude_networks and self._ip_in_networks(domain, self._exclude_networks):
                return False, "IP in excluded range"

            # Check IP inclusions
            if self._include_networks:
                if not self._ip_in_networks(domain, self._include_networks):
                    return False, "IP not in included range"

            return True, "Valid"

        # Check domain exclusions
        if self._exclude_patterns and self._domain_matches_patterns(domain, self._exclude_patterns):
            return False, "Domain matches exclusion pattern"

        # Check domain inclusions
        if self._include_patterns:
            if not self._domain_matches_patterns(domain, self._include_patterns):
                return False, "Domain not in allowed scope"

        return True, "Valid"

    def validate_and_log(self, url: str) -> bool:
        """Validate URL and log if out of scope"""
        is_valid, reason = self.validate_url(url)
        if not is_valid:
            logger.warning(f"Out of scope: {url} - {reason}")
        return is_valid

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs to only in-scope ones"""
        return [url for url in urls if self.validate_url(url)[0]]


# Default scope validator instance
_default_validator: ScopeValidator | None = None


def get_scope_validator(
    include_domains: list[str] = None,
    exclude_domains: list[str] = None,
) -> ScopeValidator:
    """Get or create scope validator"""
    global _default_validator

    if include_domains is not None or exclude_domains is not None:
        return ScopeValidator(
            include_domains=include_domains or [],
            exclude_domains=exclude_domains or [],
        )

    if _default_validator is None:
        _default_validator = ScopeValidator()

    return _default_validator


def is_in_scope(url: str) -> bool:
    """Quick check if URL is in scope using default validator"""
    return get_scope_validator().validate_url(url)[0]


def create_scope_for_target(target_url: str) -> ScopeValidator:
    """
    Create a scope validator that only allows the target domain and subdomains.
    Args:
        target_url: The primary target URL
    Returns:
        ScopeValidator configured for the target
    """
    domain = urlparse(target_url).netloc.lower().split(":")[0]

    # Allow the domain and all subdomains
    return ScopeValidator(
        include_domains=[f"*.{domain}", domain],
        exclude_domains=[],
    )
