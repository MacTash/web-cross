"""Remediation Engine - Provides fix recommendations"""

from typing import Any


class RemediationEngine:
    """Provides remediation strategies for vulnerabilities"""

    REMEDIATIONS = {
        # SQL Injection
        "ERROR_BASED": {
            "title": "SQL Injection (Error-Based)",
            "description": "Application reveals database errors, enabling SQL injection attacks.",
            "impact": "Attackers can extract sensitive data, modify records, or take control of the database.",
            "remediation": [
                "Use parameterized queries or prepared statements for all database operations",
                "Implement input validation with whitelist approach",
                "Disable detailed error messages in production",
                "Use an ORM (Object-Relational Mapping) framework",
                "Apply the principle of least privilege to database accounts"
            ],
            "code_example": {
                "vulnerable": "query = f\"SELECT * FROM users WHERE id = {user_input}\"",
                "secure": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_input,))"
            },
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/89.html"
            ]
        },
        "BOOLEAN_BLIND": {
            "title": "SQL Injection (Boolean Blind)",
            "description": "Application behavior differs based on SQL injection payload truthiness.",
            "impact": "Attackers can extract data bit by bit through boolean conditions.",
            "remediation": [
                "Use parameterized queries or prepared statements",
                "Implement consistent error handling that doesn't reveal query results",
                "Add rate limiting to prevent automated extraction",
                "Monitor for unusual query patterns"
            ],
            "code_example": {
                "vulnerable": "query = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
                "secure": "cursor.execute(\"SELECT * FROM users WHERE name = %s\", [user_input])"
            },
            "references": [
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
            ]
        },
        "TIME_BLIND": {
            "title": "SQL Injection (Time-Based Blind)",
            "description": "Application vulnerable to time-based SQL injection.",
            "impact": "Attackers can extract data by measuring response times.",
            "remediation": [
                "Use parameterized queries or prepared statements",
                "Set query timeouts to prevent long-running injected queries",
                "Implement rate limiting and anomaly detection"
            ],
            "code_example": {
                "vulnerable": "db.execute(f\"SELECT * FROM items WHERE id = {id}\")",
                "secure": "db.execute(\"SELECT * FROM items WHERE id = :id\", {\"id\": id})"
            },
            "references": [
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
            ]
        },

        # XSS
        "REFLECTED_XSS": {
            "title": "Cross-Site Scripting (Reflected)",
            "description": "User input is reflected in the response without proper encoding.",
            "impact": "Attackers can execute malicious scripts in victim's browser, steal cookies, or perform actions.",
            "remediation": [
                "Encode all user inputs before rendering in HTML (use context-appropriate encoding)",
                "Implement Content-Security-Policy header to restrict script sources",
                "Use a templating engine with auto-escaping enabled",
                "Validate and sanitize input on the server side"
            ],
            "code_example": {
                "vulnerable": "return f\"<div>Welcome {username}</div>\"",
                "secure": "return f\"<div>Welcome {html.escape(username)}</div>\""
            },
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        },
        "DOM_XSS_POTENTIAL": {
            "title": "Potential DOM-Based XSS",
            "description": "JavaScript code may be vulnerable to DOM-based XSS.",
            "impact": "Attackers can execute scripts by manipulating DOM through URL fragments or other client-side inputs.",
            "remediation": [
                "Avoid using innerHTML, document.write(), or eval() with user-controlled data",
                "Use textContent or createTextNode() instead of innerHTML",
                "Sanitize all client-side inputs before DOM manipulation",
                "Implement CSP with strict script-src directives"
            ],
            "code_example": {
                "vulnerable": "element.innerHTML = location.hash.slice(1);",
                "secure": "element.textContent = decodeURIComponent(location.hash.slice(1));"
            },
            "references": [
                "https://owasp.org/www-community/attacks/DOM_Based_XSS"
            ]
        },

        # CSRF
        "CSRF_NO_TOKEN": {
            "title": "Missing CSRF Token",
            "description": "Form lacks CSRF protection token.",
            "impact": "Attackers can trick users into performing unwanted actions.",
            "remediation": [
                "Implement anti-CSRF tokens in all state-changing forms",
                "Use SameSite cookie attribute (Strict or Lax)",
                "Verify Origin and Referer headers for sensitive requests",
                "Use framework-provided CSRF protection mechanisms"
            ],
            "code_example": {
                "vulnerable": "<form action='/transfer' method='POST'>...</form>",
                "secure": "<form action='/transfer' method='POST'><input type='hidden' name='csrf_token' value='{{token}}'>...</form>"
            },
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        },
        "MISSING_SAMESITE": {
            "title": "Missing SameSite Cookie Attribute",
            "description": "Session cookie lacks SameSite attribute.",
            "impact": "Cookies may be sent with cross-site requests, enabling CSRF attacks.",
            "remediation": [
                "Set SameSite=Strict for session cookies if cross-site access is not needed",
                "Set SameSite=Lax as minimum protection",
                "Combine with CSRF tokens for defense in depth"
            ],
            "code_example": {
                "vulnerable": "Set-Cookie: session=abc123",
                "secure": "Set-Cookie: session=abc123; SameSite=Strict; HttpOnly; Secure"
            },
            "references": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
            ]
        },

        # HTML Attacks
        "HTML_INJECTION": {
            "title": "HTML Injection",
            "description": "User input is rendered as HTML without sanitization.",
            "impact": "Attackers can inject malicious HTML to phish users or manipulate page content.",
            "remediation": [
                "HTML-encode all user inputs before rendering",
                "Use a whitelist-based HTML sanitizer for rich text inputs",
                "Implement Content-Security-Policy header"
            ],
            "code_example": {
                "vulnerable": "document.body.innerHTML += userComment;",
                "secure": "const text = document.createTextNode(userComment); document.body.appendChild(text);"
            },
            "references": [
                "https://owasp.org/www-community/attacks/Content_Spoofing"
            ]
        },
        "CLICKJACKING": {
            "title": "Clickjacking Vulnerability",
            "description": "Page can be embedded in frames, enabling clickjacking attacks.",
            "impact": "Attackers can trick users into clicking hidden elements.",
            "remediation": [
                "Set X-Frame-Options header to DENY or SAMEORIGIN",
                "Implement CSP frame-ancestors directive",
                "Add JavaScript frame-busting code as fallback"
            ],
            "code_example": {
                "vulnerable": "# No X-Frame-Options header",
                "secure": "X-Frame-Options: DENY\nContent-Security-Policy: frame-ancestors 'none'"
            },
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
            ]
        },

        # Input Fields
        "SENSITIVE_HIDDEN_FIELD": {
            "title": "Sensitive Data in Hidden Field",
            "description": "Sensitive data stored in client-modifiable hidden form field.",
            "impact": "Attackers can modify hidden values to bypass business logic.",
            "remediation": [
                "Never trust hidden field values - validate all inputs server-side",
                "Store sensitive data server-side (session/database)",
                "Use signed/encrypted tokens if client storage is required"
            ],
            "code_example": {
                "vulnerable": "<input type='hidden' name='price' value='99.99'>",
                "secure": "# Store price server-side, reference by product_id only"
            },
            "references": [
                "https://cwe.mitre.org/data/definitions/472.html"
            ]
        },
        "UNRESTRICTED_FILE_UPLOAD": {
            "title": "Unrestricted File Upload",
            "description": "File upload lacks proper type restrictions.",
            "impact": "Attackers may upload malicious files (webshells, malware).",
            "remediation": [
                "Validate file type by content (magic bytes), not just extension",
                "Restrict allowed file types to minimum required",
                "Store uploads outside webroot or use separate domain",
                "Rename uploaded files with random names",
                "Scan uploads with antivirus"
            ],
            "code_example": {
                "vulnerable": "<input type='file' name='upload'>",
                "secure": "<input type='file' name='upload' accept='.pdf,.doc,.docx'>"
            },
            "references": [
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
            ]
        },

        # Headers
        "MISSING_HEADER": {
            "title": "Missing Security Header",
            "description": "Important security header is not configured.",
            "impact": "Application may be vulnerable to various attacks that the header would prevent.",
            "remediation": [
                "Configure all recommended security headers",
                "Use a security header middleware/library",
                "Test headers with tools like securityheaders.com"
            ],
            "headers_config": {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin"
            },
            "references": [
                "https://owasp.org/www-project-secure-headers/"
            ]
        },
        "INFORMATION_DISCLOSURE": {
            "title": "Information Disclosure via Headers",
            "description": "Server headers reveal technology stack information.",
            "impact": "Attackers can target known vulnerabilities in disclosed technologies.",
            "remediation": [
                "Remove or obscure Server, X-Powered-By headers",
                "Configure web server to hide version information",
                "Use generic error pages"
            ],
            "code_example": {
                "vulnerable": "Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3",
                "secure": "# Remove these headers in server configuration"
            },
            "references": [
                "https://cwe.mitre.org/data/definitions/200.html"
            ]
        }
    }

    @classmethod
    def get_remediation(cls, finding: dict[str, Any]) -> dict[str, Any]:
        """Get remediation for a finding"""
        vuln_type = finding.get("type", "UNKNOWN")

        # Get remediation from database
        remediation = cls.REMEDIATIONS.get(vuln_type, {})

        if not remediation:
            # Generic remediation
            return {
                "title": vuln_type.replace("_", " ").title(),
                "description": finding.get("evidence", "Vulnerability detected"),
                "impact": "Potential security impact - review and assess.",
                "remediation": [
                    "Review the specific vulnerability details",
                    "Consult security documentation for this vulnerability type",
                    "Implement appropriate security controls"
                ],
                "references": []
            }

        return remediation

    @classmethod
    def get_all_remediations(cls, findings: list) -> list:
        """Get remediations for all findings"""
        result = []
        seen_types = set()

        for finding in findings:
            vuln_type = finding.get("type", "UNKNOWN")
            if vuln_type not in seen_types:
                remediation = cls.get_remediation(finding)
                remediation["findings"] = [f for f in findings if f.get("type") == vuln_type]
                result.append(remediation)
                seen_types.add(vuln_type)

        return result
