"""Input Field Vulnerability Scanner Module"""

import re
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class InputFieldScanner:
    """Input field vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/1.0"
        
        # Input validation bypass payloads
        self.type_confusion_payloads = {
            "number": ["abc", "-1", "999999999999", "1.1.1", "1e999", "NaN", "Infinity"],
            "email": ["test", "test@", "@test.com", "test@@test.com", "<script>@x.com"],
            "url": ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
            "tel": ["abc", "+++", "--", "12345678901234567890"],
            "date": ["invalid", "9999-99-99", "0000-00-00", "2023-13-45"],
        }
        
        # Special character payloads
        self.special_char_payloads = [
            "'; DROP TABLE --",
            "<>\"'`;!--",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "%00",
            "%0d%0a",
            "\x00",
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\config\\sam",
        ]
        
        # Buffer overflow indicators
        self.overflow_payloads = [
            "A" * 1000,
            "A" * 5000,
            "A" * 10000,
        ]
    
    def _make_request(self, url: str, method: str = "GET",
                      data: Dict = None, params: Dict = None) -> Optional[requests.Response]:
        """Make HTTP request"""
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
    
    def _check_input_validation(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Check for weak input validation"""
        findings = []
        
        for form in soup.find_all('form'):
            for inp in form.find_all('input'):
                inp_type = inp.get('type', 'text').lower()
                inp_name = inp.get('name', '')
                
                # Check for missing maxlength on text inputs
                if inp_type in ['text', 'password', 'email']:
                    if not inp.get('maxlength') and not inp.get('pattern'):
                        field_desc = f"<input name='{inp_name}' type='{inp_type}'>" if inp_name else f"<input type='{inp_type}'>"
                        findings.append({
                            "type": "MISSING_INPUT_VALIDATION",
                            "url": url,
                            "field": inp_name,
                            "field_type": inp_type,
                            "evidence": f"{field_desc} - No maxlength/pattern attribute",
                            "confidence": "LOW"
                        })
                
                # Check for client-side only validation
                if inp.get('required') and not inp.get('pattern'):
                    # Required but no pattern - only checks presence
                    pass
                
                # Check for password field attributes
                if inp_type == 'password':
                    if not inp.get('minlength'):
                        findings.append({
                            "type": "WEAK_PASSWORD_POLICY",
                            "url": url,
                            "field": inp_name,
                            "evidence": "Password field lacks minlength attribute",
                            "confidence": "LOW"
                        })
        
        return findings
    
    def _check_hidden_field_manipulation(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Check for manipulable hidden fields"""
        findings = []
        
        sensitive_hidden_names = [
            'price', 'amount', 'total', 'discount', 'role', 'admin',
            'user_id', 'userid', 'uid', 'level', 'permission', 'is_admin',
            'quantity', 'qty', 'credit', 'balance'
        ]
        
        for form in soup.find_all('form'):
            for inp in form.find_all('input', type='hidden'):
                name = inp.get('name', '').lower()
                value = inp.get('value', '')
                
                for sensitive in sensitive_hidden_names:
                    if sensitive in name:
                        findings.append({
                            "type": "SENSITIVE_HIDDEN_FIELD",
                            "url": url,
                            "field": inp.get('name'),
                            "value": value[:50] if len(value) > 50 else value,
                            "evidence": f"Hidden field with sensitive name: {name}",
                            "confidence": "MEDIUM"
                        })
                        break
        
        return findings
    
    def _check_file_upload(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Check for file upload vulnerabilities"""
        findings = []
        
        for form in soup.find_all('form'):
            file_inputs = form.find_all('input', type='file')
            
            for file_inp in file_inputs:
                accept = file_inp.get('accept', '')
                name = file_inp.get('name', 'unknown')
                
                # Check enctype
                enctype = form.get('enctype', '')
                if enctype != 'multipart/form-data':
                    findings.append({
                        "type": "INCORRECT_ENCTYPE",
                        "url": url,
                        "field": name,
                        "evidence": "File upload form missing multipart/form-data enctype",
                        "confidence": "MEDIUM"
                    })
                
                # Check accept attribute
                if not accept:
                    findings.append({
                        "type": "UNRESTRICTED_FILE_UPLOAD",
                        "url": url,
                        "field": name,
                        "evidence": "File input lacks accept attribute (client-side restriction)",
                        "confidence": "LOW"
                    })
                elif '*/*' in accept:
                    findings.append({
                        "type": "UNRESTRICTED_FILE_UPLOAD",
                        "url": url,
                        "field": name,
                        "evidence": "File input accepts all file types",
                        "confidence": "LOW"
                    })
        
        return findings
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Scan a URL for input field vulnerabilities"""
        findings = []
        
        response = self._make_request(url)
        if not response:
            return findings
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check input validation
        findings.extend(self._check_input_validation(soup, url))
        
        # Check hidden fields
        findings.extend(self._check_hidden_field_manipulation(soup, url))
        
        # Check file uploads
        findings.extend(self._check_file_upload(soup, url))
        
        return findings
    
    def scan_form(self, url: str, form: Dict) -> List[Dict[str, Any]]:
        """Scan a form with active payloads"""
        findings = []
        action = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', {})
        input_types = form.get('input_types', {})
        
        if not inputs:
            return findings
        
        for field_name in inputs:
            field_type = input_types.get(field_name, 'text')
            
            # Test type confusion
            if field_type in self.type_confusion_payloads:
                for payload in self.type_confusion_payloads[field_type]:
                    test_data = inputs.copy()
                    test_data[field_name] = payload
                    
                    if method == "GET":
                        response = self._make_request(action, params=test_data)
                    else:
                        response = self._make_request(action, method="POST", data=test_data)
                    
                    if response and response.status_code == 200:
                        # Check if the invalid value was accepted
                        if payload in response.text:
                            findings.append({
                                "type": "TYPE_CONFUSION",
                                "url": action,
                                "field": field_name,
                                "payload": payload,
                                "evidence": f"Invalid {field_type} value accepted",
                                "confidence": "MEDIUM"
                            })
                            break
            
            # Test special characters
            for payload in self.special_char_payloads[:5]:
                test_data = inputs.copy()
                test_data[field_name] = payload
                
                if method == "GET":
                    response = self._make_request(action, params=test_data)
                else:
                    response = self._make_request(action, method="POST", data=test_data)
                
                if response and response.status_code >= 500:
                    findings.append({
                        "type": "SERVER_ERROR_ON_INPUT",
                        "url": action,
                        "field": field_name,
                        "payload": payload,
                        "evidence": f"Server returned {response.status_code} on special characters",
                        "confidence": "HIGH"
                    })
                    break
        
        return findings
