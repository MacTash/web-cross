"""Directory and Endpoint Discovery Module"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests


class DirectoryScanner:
    """Directory bruteforce and endpoint discovery"""

    def __init__(self, timeout: int = 5, user_agent: str = None, threads: int = 10):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        self.threads = threads

        # Common directories to check
        self.common_paths = [
            # Admin panels
            "/admin", "/administrator", "/admin.php", "/admin.html",
            "/login", "/signin", "/auth", "/authenticate",
            "/wp-admin", "/wp-login.php", "/cpanel", "/phpmyadmin",
            "/adminer", "/adminer.php", "/manager", "/dashboard",

            # Configuration/sensitive
            "/.git/config", "/.git/HEAD", "/.gitignore",
            "/.env", "/.env.local", "/.env.production",
            "/config.php", "/configuration.php", "/settings.php",
            "/wp-config.php", "/web.config", "/config.yml",
            "/config.json", "/package.json", "/composer.json",

            # Backup files
            "/backup", "/backup.sql", "/backup.zip", "/backup.tar.gz",
            "/db.sql", "/database.sql", "/dump.sql",
            "/old", "/bak", "/temp", "/tmp",

            # API endpoints
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/rest", "/swagger", "/swagger.json", "/swagger.yaml",
            "/api-docs", "/openapi.json", "/docs",

            # Common files
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/security.txt", "/.well-known/security.txt",
            "/humans.txt", "/readme.html", "/readme.txt",
            "/changelog.txt", "/license.txt",

            # Debug/dev
            "/debug", "/test", "/testing", "/dev",
            "/phpinfo.php", "/info.php", "/server-status",
            "/server-info", "/.htaccess", "/.htpasswd",

            # Upload directories
            "/uploads", "/upload", "/files", "/images",
            "/media", "/assets", "/static", "/public",

            # Error pages
            "/error", "/404", "/500", "/errors",
        ]

        # Status codes that indicate interesting findings
        self.interesting_codes = {
            200: "OK",
            201: "Created",
            301: "Redirect",
            302: "Redirect",
            401: "Auth Required",
            403: "Forbidden",
        }

        # High-value targets
        self.high_value = [
            "/.git", "/.env", "/backup", "/admin", "/phpmyadmin",
            "/wp-config.php", "/config", "/api", "/swagger",
        ]

    def _check_path(self, base_url: str, path: str) -> dict | None:
        """Check if path exists"""
        url = f"{base_url.rstrip('/')}{path}"

        try:
            headers = {"User-Agent": self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout,
                                  verify=False, allow_redirects=False)

            if response.status_code in self.interesting_codes:
                is_high_value = any(hv in path for hv in self.high_value)

                return {
                    "type": "DIRECTORY_FOUND" if is_high_value else "PATH_FOUND",
                    "url": url,
                    "path": path,
                    "status_code": response.status_code,
                    "status": self.interesting_codes.get(response.status_code, ""),
                    "content_length": len(response.content),
                    "confidence": "HIGH" if is_high_value else "MEDIUM"
                }
        except Exception:
            pass

        return None

    def scan_url(self, url: str, custom_paths: list[str] = None) -> list[dict[str, Any]]:
        """Scan URL for directories and endpoints"""
        findings = []
        paths = custom_paths if custom_paths else self.common_paths

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_path, url, path): path
                for path in paths
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)

        # Sort by confidence
        findings.sort(key=lambda x: (x.get("confidence") == "HIGH", x.get("status_code", 0)), reverse=True)

        return findings

    def scan_with_wordlist(self, url: str, wordlist_path: str) -> list[dict[str, Any]]:
        """Scan using custom wordlist"""
        try:
            with open(wordlist_path) as f:
                paths = [f"/{line.strip()}" for line in f if line.strip() and not line.startswith('#')]
            return self.scan_url(url, paths)
        except Exception:
            return []
