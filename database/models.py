"""
Web-Cross Database Models
SQLAlchemy ORM models for persisting scan data and history.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
import json

from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean,
    ForeignKey, JSON, Enum as SQLEnum, Index, create_engine
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class Scan(Base):
    """Represents a complete vulnerability scan"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    
    # Target information
    target_url = Column(String(2048), nullable=False)
    target_domain = Column(String(256), nullable=False, index=True)
    
    # Scan configuration
    scan_mode = Column(String(32), default="full")
    ai_enabled = Column(Boolean, default=False)
    threads = Column(Integer, default=10)
    timeout = Column(Integer, default=10)
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    
    # Status
    status = Column(String(32), default="pending", index=True)  # pending, running, completed, failed, cancelled
    error_message = Column(Text, nullable=True)
    
    # Results summary
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Risk scores
    overall_risk_score = Column(Float, default=0.0)
    max_risk_score = Column(Float, default=0.0)
    
    # URLs crawled
    urls_crawled = Column(Integer, default=0)
    forms_found = Column(Integer, default=0)
    
    # Report paths
    report_html_path = Column(String(512), nullable=True)
    report_json_path = Column(String(512), nullable=True)
    report_pdf_path = Column(String(512), nullable=True)
    
    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("ix_scans_domain_date", "target_domain", "started_at"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "target_domain": self.target_domain,
            "scan_mode": self.scan_mode,
            "ai_enabled": self.ai_enabled,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "overall_risk_score": self.overall_risk_score,
            "urls_crawled": self.urls_crawled,
        }


class Finding(Base):
    """Represents a single vulnerability finding"""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    # Vulnerability details
    vuln_type = Column(String(64), nullable=False, index=True)  # SQL_INJECTION, XSS, etc.
    vuln_subtype = Column(String(64), nullable=True)  # ERROR_BASED, REFLECTED, etc.
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    
    # Location
    url = Column(String(2048), nullable=False)
    parameter = Column(String(256), nullable=True)
    method = Column(String(16), default="GET")
    
    # Severity
    severity = Column(String(16), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score = Column(Float, default=0.0)
    confidence = Column(String(16), default="MEDIUM")  # HIGH, MEDIUM, LOW
    
    # Evidence
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response_snippet = Column(Text, nullable=True)
    
    # Remediation
    remediation = Column(Text, nullable=True)
    
    # Compliance references (stored as JSON)
    owasp_category = Column(String(64), nullable=True)  # A01:2021, etc.
    cwe_id = Column(String(32), nullable=True)  # CWE-79, etc.
    cvss_vector = Column(String(128), nullable=True)
    
    # AI analysis
    ai_analysis = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    
    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    
    # Indexes
    __table_args__ = (
        Index("ix_findings_scan_type", "scan_id", "vuln_type"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "type": self.vuln_type,
            "subtype": self.vuln_subtype,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "ai_analysis": self.ai_analysis,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "verified": self.verified,
            "false_positive": self.false_positive,
        }


class Technology(Base):
    """Detected technology/stack information"""
    __tablename__ = "technologies"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    
    # Technology details
    name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=True)  # server, framework, cms, etc.
    version = Column(String(64), nullable=True)
    confidence = Column(String(16), default="MEDIUM")
    
    # Detection source
    detection_source = Column(String(64), nullable=True)  # header, cookie, html, etc.
    evidence = Column(Text, nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="technologies")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "source": self.detection_source,
        }


class ScanConfig(Base):
    """Saved scan configurations for reuse"""
    __tablename__ = "scan_configs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    
    # Configuration JSON
    config_json = Column(JSON, nullable=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_default = Column(Boolean, default=False)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "config": self.config_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_default": self.is_default,
        }


class ScanState(Base):
    """Scan state for resume capability"""
    __tablename__ = "scan_states"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)
    
    # State data (JSON serialized)
    state_json = Column(JSON, nullable=False)
    
    # Progress
    phase = Column(String(32), nullable=False)  # crawling, scanning, reporting
    progress_percent = Column(Float, default=0.0)
    
    # URLs state
    pending_urls = Column(JSON, nullable=True)
    completed_urls = Column(JSON, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase,
            "progress_percent": self.progress_percent,
            "state": self.state_json,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
