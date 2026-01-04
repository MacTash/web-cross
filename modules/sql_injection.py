"""SQL Injection Scanner Module"""

import re
import time
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import os

class SQLiScanner:
    """SQL Injection vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        self.payloads = self._load_payloads()
        self.findings = []
        
        # SQL error patterns for detection
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB)",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"Warning.*odbc_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"ODBC SQL Server Driver",
            r"ODBC Driver \d+ for SQL Server",
            r"SQLServer JDBC Driver",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"macaboret function\.ibase_",
            r"Firebird",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            r"db2_\w+\(",
            r"SQLSTATE",
            r"SQLITE_ERROR",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQL error.*POS([0-9]+)",
            r"Exception.*Sybase",
            r"Sybase message",
            r"Sybase.*Server message",
            r"you have an error in your sql syntax",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
        ]
        
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads from file"""
        payload_file = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'sqli.txt')
        payloads = []
        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except FileNotFoundError:
            # Default payloads if file not found
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "1' OR '1'='1",
                "' UNION SELECT NULL--",
                "' AND SLEEP(5)--",
            ]
        return payloads
    
    def _make_request(self, url: str, method: str = "GET", 
                      data: Dict = None, params: Dict = None) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
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
    
    def _check_error_based(self, response: requests.Response, payload: str) -> Optional[Dict]:
        """Check for error-based SQL injection"""
        if not response:
            return None
            
        content = response.text.lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return {
                    "type": "ERROR_BASED",
                    "payload": payload,
                    "evidence": re.search(pattern, response.text, re.IGNORECASE).group(0),
                    "confidence": "HIGH"
                }
        return None
    
    def _check_boolean_based(self, url: str, param: str, 
                             original_response: requests.Response) -> Optional[Dict]:
        """Check for boolean-based blind SQL injection"""
        if not original_response:
            return None
            
        # True condition
        true_payload = "' OR '1'='1"
        # False condition  
        false_payload = "' AND '1'='2"
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test true condition
        params[param] = [true_payload]
        true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        true_response = self._make_request(true_url)
        
        # Test false condition
        params[param] = [false_payload]
        false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
        false_response = self._make_request(false_url)
        
        if true_response and false_response:
            # Compare response lengths
            true_len = len(true_response.text)
            false_len = len(false_response.text)
            orig_len = len(original_response.text)
            
            # If true response is similar to original but false is different
            if abs(true_len - orig_len) < 100 and abs(false_len - orig_len) > 100:
                return {
                    "type": "BOOLEAN_BLIND",
                    "payload": f"{true_payload} vs {false_payload}",
                    "evidence": f"Response length diff: true={true_len}, false={false_len}, orig={orig_len}",
                    "confidence": "MEDIUM"
                }
        return None
    
    def _check_time_based(self, url: str, param: str) -> Optional[Dict]:
        """Check for time-based blind SQL injection"""
        time_payloads = [
            ("' AND SLEEP(3)--", 3),
            ("'; WAITFOR DELAY '0:0:3'--", 3),
            ("' OR SLEEP(3)--", 3),
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload, expected_delay in time_payloads:
            params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
            
            start_time = time.time()
            response = self._make_request(test_url)
            elapsed = time.time() - start_time
            
            if elapsed >= expected_delay - 0.5:  # Allow 0.5s tolerance
                return {
                    "type": "TIME_BLIND",
                    "payload": payload,
                    "evidence": f"Response delayed by {elapsed:.2f}s (expected {expected_delay}s)",
                    "confidence": "HIGH"
                }
        return None
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Scan a URL for SQL injection vulnerabilities"""
        findings = []
        
        # Get original response
        original_response = self._make_request(url)
        if not original_response:
            return findings
        
        # Parse URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return findings
        
        # Test each parameter
        for param in params:
            for payload in self.payloads[:15]:  # Limit payloads for speed
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                response = self._make_request(test_url)
                
                # Check error-based
                error_result = self._check_error_based(response, payload)
                if error_result:
                    error_result["parameter"] = param
                    error_result["url"] = url
                    findings.append(error_result)
                    break  # Found vuln in this param, move on
            
            # Check boolean-based
            bool_result = self._check_boolean_based(url, param, original_response)
            if bool_result:
                bool_result["parameter"] = param
                bool_result["url"] = url
                findings.append(bool_result)
            
            # Check time-based (slower, do last)
            time_result = self._check_time_based(url, param)
            if time_result:
                time_result["parameter"] = param
                time_result["url"] = url
                findings.append(time_result)
        
        return findings
    
    def scan_form(self, url: str, form: Dict) -> List[Dict[str, Any]]:
        """Scan a form for SQL injection vulnerabilities"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})
        
        if not inputs:
            return findings
        
        for field_name in inputs:
            for payload in self.payloads[:10]:
                test_data = inputs.copy()
                test_data[field_name] = payload
                
                if method == "GET":
                    response = self._make_request(action, params=test_data)
                else:
                    response = self._make_request(action, method="POST", data=test_data)
                
                error_result = self._check_error_based(response, payload)
                if error_result:
                    error_result["parameter"] = field_name
                    error_result["url"] = action
                    error_result["method"] = method
                    findings.append(error_result)
                    break
        
        return findings
