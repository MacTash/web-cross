"""Technology Fingerprinting Module"""

import re
import requests
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup


class TechFingerprinter:
    """Technology stack fingerprinting scanner"""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        
        # Header-based detection
        self.header_signatures = {
            "Server": {
                "Apache": {"tech": "Apache", "category": "Web Server"},
                "nginx": {"tech": "Nginx", "category": "Web Server"},
                "Microsoft-IIS": {"tech": "IIS", "category": "Web Server"},
                "LiteSpeed": {"tech": "LiteSpeed", "category": "Web Server"},
                "cloudflare": {"tech": "Cloudflare", "category": "CDN"},
            },
            "X-Powered-By": {
                "PHP": {"tech": "PHP", "category": "Backend"},
                "ASP.NET": {"tech": "ASP.NET", "category": "Framework"},
                "Express": {"tech": "Express.js", "category": "Framework"},
                "Next.js": {"tech": "Next.js", "category": "Framework"},
                "Servlet": {"tech": "Java Servlet", "category": "Backend"},
            },
            "X-AspNet-Version": {
                "": {"tech": "ASP.NET", "category": "Framework"}
            },
            "X-Generator": {
                "Drupal": {"tech": "Drupal", "category": "CMS"},
                "WordPress": {"tech": "WordPress", "category": "CMS"},
            },
        }
        
        # Cookie-based detection
        self.cookie_signatures = {
            "PHPSESSID": {"tech": "PHP", "category": "Backend"},
            "JSESSIONID": {"tech": "Java/Tomcat", "category": "Backend"},
            "ASP.NET_SessionId": {"tech": "ASP.NET", "category": "Framework"},
            "csrftoken": {"tech": "Django", "category": "Framework"},
            "_csrf": {"tech": "Rails/Express", "category": "Framework"},
            "laravel_session": {"tech": "Laravel", "category": "Framework"},
            "rack.session": {"tech": "Ruby Rack", "category": "Framework"},
            "connect.sid": {"tech": "Express.js", "category": "Framework"},
            "ci_session": {"tech": "CodeIgniter", "category": "Framework"},
        }
        
        # HTML-based detection
        self.html_signatures = {
            # Meta generators
            r'<meta name="generator" content="WordPress': {"tech": "WordPress", "category": "CMS"},
            r'<meta name="generator" content="Drupal': {"tech": "Drupal", "category": "CMS"},
            r'<meta name="generator" content="Joomla': {"tech": "Joomla", "category": "CMS"},
            r'<meta name="generator" content="TYPO3': {"tech": "TYPO3", "category": "CMS"},
            r'<meta name="generator" content="Wix': {"tech": "Wix", "category": "Website Builder"},
            r'<meta name="generator" content="Squarespace': {"tech": "Squarespace", "category": "Website Builder"},
            
            # Script/CSS patterns
            r'/wp-content/': {"tech": "WordPress", "category": "CMS"},
            r'/wp-includes/': {"tech": "WordPress", "category": "CMS"},
            r'sites/all/modules': {"tech": "Drupal", "category": "CMS"},
            r'sites/default/files': {"tech": "Drupal", "category": "CMS"},
            r'/media/jui/': {"tech": "Joomla", "category": "CMS"},
            r'/_next/': {"tech": "Next.js", "category": "Framework"},
            r'__NEXT_DATA__': {"tech": "Next.js", "category": "Framework"},
            r'__nuxt': {"tech": "Nuxt.js", "category": "Framework"},
            r'ng-version=': {"tech": "Angular", "category": "Framework"},
            r'data-reactroot': {"tech": "React", "category": "Framework"},
            r'data-v-[a-f0-9]+': {"tech": "Vue.js", "category": "Framework"},
            r'ember-view': {"tech": "Ember.js", "category": "Framework"},
            
            # Analytics
            r'google-analytics.com': {"tech": "Google Analytics", "category": "Analytics"},
            r'gtag\(': {"tech": "Google Tag Manager", "category": "Analytics"},
            r'fbq\(': {"tech": "Facebook Pixel", "category": "Analytics"},
            r'hotjar.com': {"tech": "Hotjar", "category": "Analytics"},
        }
        
        # Path-based detection
        self.path_checks = [
            ("/robots.txt", [
                (r"Disallow: /wp-", {"tech": "WordPress", "category": "CMS"}),
                (r"Disallow: /admin", {"tech": "Admin Panel", "category": "Feature"}),
            ]),
            ("/sitemap.xml", []),
            ("/package.json", [
                (r'"react":', {"tech": "React", "category": "Framework"}),
                (r'"vue":', {"tech": "Vue.js", "category": "Framework"}),
                (r'"express":', {"tech": "Express.js", "category": "Framework"}),
            ]),
            ("/.git/config", [
                (r"\[core\]", {"tech": "Git Repository Exposed", "category": "Security Risk"})
            ]),
            ("/web.config", [
                (r"<configuration>", {"tech": "ASP.NET/IIS", "category": "Framework"})
            ]),
        ]
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        try:
            headers = {"User-Agent": self.user_agent}
            return requests.get(url, headers=headers, timeout=self.timeout, 
                              verify=False, allow_redirects=True)
        except Exception:
            return None
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Fingerprint technology stack"""
        technologies = []
        
        response = self._make_request(url)
        if not response:
            return technologies
        
        # Check headers
        for header, signatures in self.header_signatures.items():
            value = response.headers.get(header, '')
            for pattern, tech_info in signatures.items():
                if pattern in value:
                    technologies.append({
                        "type": "TECH_DETECTED",
                        "technology": tech_info["tech"],
                        "category": tech_info["category"],
                        "source": f"Header: {header}",
                        "value": value[:100],
                        "url": url
                    })
        
        # Check cookies
        for cookie in response.cookies:
            for cookie_name, tech_info in self.cookie_signatures.items():
                if cookie_name.lower() in cookie.name.lower():
                    technologies.append({
                        "type": "TECH_DETECTED",
                        "technology": tech_info["tech"],
                        "category": tech_info["category"],
                        "source": f"Cookie: {cookie.name}",
                        "url": url
                    })
        
        # Check HTML content
        content = response.text
        for pattern, tech_info in self.html_signatures.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.append({
                    "type": "TECH_DETECTED",
                    "technology": tech_info["tech"],
                    "category": tech_info["category"],
                    "source": "HTML Content",
                    "url": url
                })
        
        # Check paths
        from urllib.parse import urljoin
        for path, checks in self.path_checks:
            check_url = urljoin(url, path)
            path_response = self._make_request(check_url)
            if path_response and path_response.status_code == 200:
                for pattern, tech_info in checks:
                    if re.search(pattern, path_response.text, re.IGNORECASE):
                        technologies.append({
                            "type": "TECH_DETECTED",
                            "technology": tech_info["tech"],
                            "category": tech_info["category"],
                            "source": f"Path: {path}",
                            "url": check_url
                        })
                
                # Git exposure is a security risk
                if "/.git/" in path:
                    technologies.append({
                        "type": "GIT_EXPOSED",
                        "evidence": "Git repository is publicly accessible",
                        "url": check_url,
                        "confidence": "HIGH"
                    })
        
        # Deduplicate
        seen = set()
        unique = []
        for tech in technologies:
            key = (tech.get("technology", ""), tech.get("category", ""))
            if key not in seen:
                seen.add(key)
                unique.append(tech)
        
        return unique
