"""
Tests for reporting module
"""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, '/home/anomaly/Extra1/aiprojects/web-cross')


class TestComplianceMapper:
    """Tests for Compliance Mapper"""

    def test_get_mapping_sql_injection(self):
        """Test SQL injection compliance mapping"""
        from reporting.compliance import ComplianceMapper
        mapper = ComplianceMapper()

        mapping = mapper.get_mapping("SQL_INJECTION")

        assert mapping is not None
        assert mapping.owasp_top_10 == "A03:2021"
        assert mapping.cwe_id == "CWE-89"
        assert mapping.cvss_base == 9.8

    def test_get_mapping_xss(self):
        """Test XSS compliance mapping"""
        from reporting.compliance import ComplianceMapper
        mapper = ComplianceMapper()

        mapping = mapper.get_mapping("XSS")

        assert mapping is not None
        assert mapping.cwe_id == "CWE-79"

    def test_enrich_finding(self):
        """Test finding enrichment"""
        from reporting.compliance import ComplianceMapper
        mapper = ComplianceMapper()

        finding = {"type": "OPEN_REDIRECT", "url": "http://example.com"}
        enriched = mapper.enrich_finding(finding)

        assert "compliance" in enriched
        assert enriched["compliance"]["cwe_id"] == "CWE-601"

    def test_generate_compliance_summary(self):
        """Test compliance summary generation"""
        from reporting.compliance import ComplianceMapper
        mapper = ComplianceMapper()

        findings = [
            {"type": "SQL_INJECTION"},
            {"type": "XSS"},
            {"type": "SQL_INJECTION"},
        ]

        summary = mapper.generate_compliance_summary(findings)

        assert "owasp_top_10" in summary
        assert "A03:2021" in summary["owasp_top_10"]
        assert summary["owasp_top_10"]["A03:2021"]["count"] == 3

    def test_unknown_vuln_type(self):
        """Test unknown vulnerability type returns None"""
        from reporting.compliance import ComplianceMapper
        mapper = ComplianceMapper()

        mapping = mapper.get_mapping("UNKNOWN_VULN_TYPE_XYZ")
        assert mapping is None


class TestHTMLReportGenerator:
    """Tests for HTML Report Generator"""

    def test_initialization(self):
        """Test HTML generator initializes"""
        from reporting.html_generator import HTMLReportGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = HTMLReportGenerator(output_dir=Path(tmpdir))
            assert generator.output_dir.exists()

    def test_generate_report(self, sample_findings, sample_target, sample_scan_info):
        """Test HTML report generation"""
        from reporting.html_generator import HTMLReportGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = HTMLReportGenerator(output_dir=Path(tmpdir))

            output_path = generator.generate(
                findings=sample_findings,
                target=sample_target,
                scan_info=sample_scan_info,
            )

            assert output_path.exists()
            assert output_path.suffix == ".html"

            content = output_path.read_text()
            assert "Security Report" in content
            assert sample_target in content

    def test_severity_filtering(self, sample_findings):
        """Test severity filtering JavaScript is included"""
        from reporting.html_generator import HTMLReportGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = HTMLReportGenerator(output_dir=Path(tmpdir))

            output_path = generator.generate(
                findings=sample_findings,
                target="http://example.com",
            )

            content = output_path.read_text()
            assert "filterFindings" in content


class TestPDFReportGenerator:
    """Tests for PDF Report Generator"""

    def test_initialization(self):
        """Test PDF generator initializes"""
        from reporting.pdf_generator import PDFReportGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = PDFReportGenerator(output_dir=Path(tmpdir))
            assert generator.output_dir.exists()

    @pytest.mark.skipif(
        not pytest.importorskip("weasyprint", reason="WeasyPrint not available"),
        reason="WeasyPrint not installed"
    )
    def test_generate_pdf(self, sample_findings, sample_target, sample_scan_info):
        """Test PDF generation (requires WeasyPrint)"""
        from reporting.pdf_generator import PDFReportGenerator

        with tempfile.TemporaryDirectory() as tmpdir:
            generator = PDFReportGenerator(output_dir=Path(tmpdir))

            try:
                output_path = generator.generate(
                    findings=sample_findings,
                    target=sample_target,
                    scan_info=sample_scan_info,
                )

                assert output_path.exists()
                assert output_path.suffix == ".pdf"
            except RuntimeError as e:
                if "WeasyPrint" in str(e):
                    pytest.skip("WeasyPrint not available")
                raise


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
