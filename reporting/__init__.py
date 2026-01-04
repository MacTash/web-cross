"""
Web-Cross Reporting Module
Enhanced report generation with PDF export and compliance mapping.
"""

from .pdf_generator import PDFReportGenerator, get_pdf_generator
from .compliance import ComplianceMapper, get_compliance_mapper
from .html_generator import HTMLReportGenerator, get_html_generator
from .legacy import RiskCalculator, ReportGenerator

__all__ = [
    # New v3.0 classes
    "PDFReportGenerator",
    "get_pdf_generator",
    "ComplianceMapper", 
    "get_compliance_mapper",
    "HTMLReportGenerator",
    "get_html_generator",
    # Legacy compatibility
    "RiskCalculator",
    "ReportGenerator",
]

