"""Risk Score Calculator"""

from typing import List, Dict, Any


class RiskCalculator:
    """Calculate risk scores for vulnerabilities"""
    
    # CVSS-like base scores by vulnerability type
    BASE_SCORES = {
        # SQL Injection
        "ERROR_BASED": 9.0,
        "BOOLEAN_BLIND": 8.5,
        "TIME_BLIND": 8.0,
        "UNION_BASED": 9.0,
        
        # XSS
        "REFLECTED_XSS": 6.5,
        "STORED_XSS": 8.0,
        "STORED_XSS_INDICATOR": 7.0,
        "DOM_XSS_POTENTIAL": 5.5,
        
        # CSRF
        "CSRF_NO_TOKEN": 6.0,
        "MISSING_SAMESITE": 4.0,
        "MISSING_HTTPONLY": 5.0,
        "MISSING_SECURE": 3.0,
        
        # HTML Attacks
        "HTML_INJECTION": 5.5,
        "CLICKJACKING": 4.5,
        "EXTERNAL_FORM_ACTION": 5.0,
        "AUTOCOMPLETE_PASSWORD": 2.0,
        "AUTOCOMPLETE_SENSITIVE": 2.5,
        "SUSPICIOUS_BASE_TAG": 7.0,
        "META_REDIRECT_EXTERNAL": 4.0,
        
        # Input Fields
        "MISSING_INPUT_VALIDATION": 3.0,
        "WEAK_PASSWORD_POLICY": 3.5,
        "SENSITIVE_HIDDEN_FIELD": 5.0,
        "TYPE_CONFUSION": 4.5,
        "SERVER_ERROR_ON_INPUT": 6.0,
        "UNRESTRICTED_FILE_UPLOAD": 7.5,
        "INCORRECT_ENCTYPE": 3.0,
        
        # Headers
        "MISSING_HEADER": 4.0,
        "HEADER_MISCONFIGURATION": 4.5,
        "INFORMATION_DISCLOSURE": 3.0,
        "INSECURE_CACHING": 4.0,
    }
    
    # Confidence modifiers
    CONFIDENCE_MODIFIERS = {
        "HIGH": 1.0,
        "MEDIUM": 0.8,
        "LOW": 0.6
    }
    
    # Severity modifiers for headers
    SEVERITY_MODIFIERS = {
        "HIGH": 1.2,
        "MEDIUM": 1.0,
        "LOW": 0.8
    }
    
    @classmethod
    def calculate_score(cls, finding: Dict[str, Any]) -> float:
        """Calculate risk score for a single finding"""
        vuln_type = finding.get("type", "UNKNOWN")
        confidence = finding.get("confidence", "MEDIUM")
        severity = finding.get("severity", "MEDIUM")
        
        # Get base score
        base_score = cls.BASE_SCORES.get(vuln_type, 5.0)
        
        # Apply confidence modifier
        confidence_mod = cls.CONFIDENCE_MODIFIERS.get(confidence, 0.8)
        
        # Apply severity modifier (for header findings)
        severity_mod = cls.SEVERITY_MODIFIERS.get(severity, 1.0)
        
        # Calculate final score (capped at 10.0)
        final_score = min(10.0, base_score * confidence_mod * severity_mod)
        
        return round(final_score, 1)
    
    @classmethod
    def get_severity_label(cls, score: float) -> str:
        """Get severity label from score"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 2.0:
            return "LOW"
        else:
            return "INFO"
    
    @classmethod
    def get_severity_color(cls, score: float) -> str:
        """Get color for severity (for CLI/HTML)"""
        if score >= 9.0:
            return "red"
        elif score >= 7.0:
            return "orange"
        elif score >= 4.0:
            return "yellow"
        elif score >= 2.0:
            return "cyan"
        else:
            return "green"
    
    @classmethod
    def calculate_overall_score(cls, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate overall risk score for all findings"""
        if not findings:
            return {
                "score": 0.0,
                "severity": "NONE",
                "total_findings": 0,
                "breakdown": {}
            }
        
        # Score each finding
        scores = []
        breakdown = {}
        
        for finding in findings:
            score = cls.calculate_score(finding)
            finding["risk_score"] = score
            finding["severity_label"] = cls.get_severity_label(score)
            scores.append(score)
            
            vuln_type = finding.get("type", "UNKNOWN")
            if vuln_type not in breakdown:
                breakdown[vuln_type] = {"count": 0, "max_score": 0}
            breakdown[vuln_type]["count"] += 1
            breakdown[vuln_type]["max_score"] = max(breakdown[vuln_type]["max_score"], score)
        
        # Overall score is weighted average (higher scores count more)
        sorted_scores = sorted(scores, reverse=True)
        weighted_sum = 0
        weight_total = 0
        
        for i, score in enumerate(sorted_scores):
            weight = 1 / (i + 1)  # Higher weights for higher scores
            weighted_sum += score * weight
            weight_total += weight
        
        overall_score = round(weighted_sum / weight_total, 1) if weight_total > 0 else 0.0
        
        return {
            "score": overall_score,
            "max_score": max(scores) if scores else 0.0,
            "severity": cls.get_severity_label(overall_score),
            "total_findings": len(findings),
            "critical_count": len([s for s in scores if s >= 9.0]),
            "high_count": len([s for s in scores if 7.0 <= s < 9.0]),
            "medium_count": len([s for s in scores if 4.0 <= s < 7.0]),
            "low_count": len([s for s in scores if s < 4.0]),
            "breakdown": breakdown
        }
