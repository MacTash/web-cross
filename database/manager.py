"""
Web-Cross Database Manager
Database operations and connection management.
"""

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from functools import lru_cache
import json

from sqlalchemy import create_engine, select, delete, func, and_, or_
from sqlalchemy.orm import sessionmaker, Session

from .models import Base, Scan, Finding, Technology, ScanConfig, ScanState


class DatabaseManager:
    """
    Manages database connections and operations for Web-Cross.
    Provides methods for CRUD operations on scans, findings, and configurations.
    """
    
    def __init__(self, db_url: str = None, echo: bool = False):
        """
        Initialize database manager.
        
        Args:
            db_url: Database connection URL (default: SQLite in data directory)
            echo: Whether to echo SQL queries
        """
        if db_url is None:
            # Default to SQLite in data directory
            base_dir = Path(__file__).parent.parent
            data_dir = base_dir / "data"
            data_dir.mkdir(exist_ok=True)
            db_url = f"sqlite:///{data_dir / 'webcross.db'}"
        
        self.db_url = db_url
        self.engine = create_engine(db_url, echo=echo)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(self.engine)
    
    def get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()
    
    # ==================== Scan Operations ====================
    
    def create_scan(
        self,
        scan_id: str,
        target_url: str,
        target_domain: str,
        scan_mode: str = "full",
        ai_enabled: bool = False,
        threads: int = 10,
        timeout: int = 10,
    ) -> Scan:
        """Create a new scan record"""
        with self.get_session() as session:
            scan = Scan(
                scan_id=scan_id,
                target_url=target_url,
                target_domain=target_domain,
                scan_mode=scan_mode,
                ai_enabled=ai_enabled,
                threads=threads,
                timeout=timeout,
                status="pending",
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan
    
    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: str = None,
    ) -> Optional[Scan]:
        """Update scan status"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                scan.status = status
                if error_message:
                    scan.error_message = error_message
                if status in ("completed", "failed", "cancelled"):
                    scan.completed_at = datetime.utcnow()
                    if scan.started_at:
                        scan.duration_seconds = (
                            scan.completed_at - scan.started_at
                        ).total_seconds()
                session.commit()
                session.refresh(scan)
            return scan
    
    def update_scan_results(
        self,
        scan_id: str,
        findings: List[Dict],
        technologies: List[Dict] = None,
        urls_crawled: int = 0,
        forms_found: int = 0,
        risk_summary: Dict = None,
    ) -> Optional[Scan]:
        """Update scan with results"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not scan:
                return None
            
            # Update counts
            scan.urls_crawled = urls_crawled
            scan.forms_found = forms_found
            scan.total_findings = len(findings)
            
            # Update risk summary
            if risk_summary:
                scan.overall_risk_score = risk_summary.get("score", 0.0)
                scan.max_risk_score = risk_summary.get("max_score", 0.0)
                scan.critical_count = risk_summary.get("critical_count", 0)
                scan.high_count = risk_summary.get("high_count", 0)
                scan.medium_count = risk_summary.get("medium_count", 0)
                scan.low_count = risk_summary.get("low_count", 0)
            
            # Add findings
            for finding_data in findings:
                finding = Finding(
                    scan_id=scan.id,
                    vuln_type=finding_data.get("type", "UNKNOWN"),
                    vuln_subtype=finding_data.get("subtype"),
                    title=finding_data.get("title", finding_data.get("type", "Finding")),
                    description=finding_data.get("description"),
                    url=finding_data.get("url", scan.target_url),
                    parameter=finding_data.get("parameter"),
                    method=finding_data.get("method", "GET"),
                    severity=finding_data.get("severity_label", "MEDIUM"),
                    risk_score=finding_data.get("risk_score", 0.0),
                    confidence=finding_data.get("confidence", "MEDIUM"),
                    payload=finding_data.get("payload"),
                    evidence=finding_data.get("evidence"),
                    remediation=finding_data.get("remediation"),
                    owasp_category=finding_data.get("owasp"),
                    cwe_id=finding_data.get("cwe"),
                    ai_analysis=finding_data.get("ai_analysis"),
                )
                session.add(finding)
            
            # Add technologies
            if technologies:
                for tech_data in technologies:
                    tech = Technology(
                        scan_id=scan.id,
                        name=tech_data.get("name", "Unknown"),
                        category=tech_data.get("category"),
                        version=tech_data.get("version"),
                        confidence=tech_data.get("confidence", "MEDIUM"),
                        detection_source=tech_data.get("source"),
                        evidence=tech_data.get("evidence"),
                    )
                    session.add(tech)
            
            session.commit()
            session.refresh(scan)
            return scan
    
    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get scan by ID"""
        with self.get_session() as session:
            return session.query(Scan).filter(Scan.scan_id == scan_id).first()
    
    def get_scan_with_findings(self, scan_id: str) -> Optional[Dict]:
        """Get scan with all findings"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if not scan:
                return None
            
            result = scan.to_dict()
            result["findings"] = [f.to_dict() for f in scan.findings]
            result["technologies"] = [t.to_dict() for t in scan.technologies]
            return result
    
    def get_scans_for_domain(
        self,
        domain: str,
        limit: int = 10,
    ) -> List[Scan]:
        """Get recent scans for a domain"""
        with self.get_session() as session:
            return (
                session.query(Scan)
                .filter(Scan.target_domain == domain)
                .order_by(Scan.started_at.desc())
                .limit(limit)
                .all()
            )
    
    def get_recent_scans(self, limit: int = 20) -> List[Scan]:
        """Get recent scans"""
        with self.get_session() as session:
            return (
                session.query(Scan)
                .order_by(Scan.started_at.desc())
                .limit(limit)
                .all()
            )
    
    def get_scan_history(
        self,
        days: int = 30,
        domain: str = None,
    ) -> List[Dict]:
        """Get scan history for trend analysis"""
        with self.get_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = session.query(Scan).filter(Scan.started_at >= cutoff)
            
            if domain:
                query = query.filter(Scan.target_domain == domain)
            
            scans = query.order_by(Scan.started_at.asc()).all()
            return [s.to_dict() for s in scans]
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its findings"""
        with self.get_session() as session:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                session.delete(scan)
                session.commit()
                return True
            return False
    
    def cleanup_old_scans(self, days: int = 90) -> int:
        """Delete scans older than specified days"""
        with self.get_session() as session:
            cutoff = datetime.utcnow() - timedelta(days=days)
            result = session.query(Scan).filter(Scan.started_at < cutoff).delete()
            session.commit()
            return result
    
    # ==================== State Operations ====================
    
    def save_scan_state(
        self,
        scan_id: str,
        phase: str,
        progress: float,
        state_data: Dict,
        pending_urls: List[str] = None,
        completed_urls: List[str] = None,
    ) -> ScanState:
        """Save or update scan state for resume capability"""
        with self.get_session() as session:
            state = session.query(ScanState).filter(
                ScanState.scan_id == scan_id
            ).first()
            
            if state:
                state.phase = phase
                state.progress_percent = progress
                state.state_json = state_data
                state.pending_urls = pending_urls
                state.completed_urls = completed_urls
                state.updated_at = datetime.utcnow()
            else:
                state = ScanState(
                    scan_id=scan_id,
                    phase=phase,
                    progress_percent=progress,
                    state_json=state_data,
                    pending_urls=pending_urls,
                    completed_urls=completed_urls,
                )
                session.add(state)
            
            session.commit()
            session.refresh(state)
            return state
    
    def get_scan_state(self, scan_id: str) -> Optional[ScanState]:
        """Get scan state for resume"""
        with self.get_session() as session:
            return session.query(ScanState).filter(
                ScanState.scan_id == scan_id
            ).first()
    
    def delete_scan_state(self, scan_id: str) -> bool:
        """Delete scan state after completion"""
        with self.get_session() as session:
            result = session.query(ScanState).filter(
                ScanState.scan_id == scan_id
            ).delete()
            session.commit()
            return result > 0
    
    # ==================== Config Operations ====================
    
    def save_config(
        self,
        name: str,
        config: Dict,
        description: str = None,
        is_default: bool = False,
    ) -> ScanConfig:
        """Save a scan configuration"""
        with self.get_session() as session:
            # If setting as default, unset others
            if is_default:
                session.query(ScanConfig).update({"is_default": False})
            
            existing = session.query(ScanConfig).filter(
                ScanConfig.name == name
            ).first()
            
            if existing:
                existing.config_json = config
                existing.description = description
                existing.is_default = is_default
                existing.updated_at = datetime.utcnow()
                session.commit()
                session.refresh(existing)
                return existing
            
            config_obj = ScanConfig(
                name=name,
                description=description,
                config_json=config,
                is_default=is_default,
            )
            session.add(config_obj)
            session.commit()
            session.refresh(config_obj)
            return config_obj
    
    def get_config(self, name: str) -> Optional[ScanConfig]:
        """Get a saved configuration"""
        with self.get_session() as session:
            return session.query(ScanConfig).filter(
                ScanConfig.name == name
            ).first()
    
    def get_default_config(self) -> Optional[ScanConfig]:
        """Get the default configuration"""
        with self.get_session() as session:
            return session.query(ScanConfig).filter(
                ScanConfig.is_default == True
            ).first()
    
    def list_configs(self) -> List[ScanConfig]:
        """List all saved configurations"""
        with self.get_session() as session:
            return session.query(ScanConfig).order_by(ScanConfig.name).all()
    
    def delete_config(self, name: str) -> bool:
        """Delete a configuration"""
        with self.get_session() as session:
            result = session.query(ScanConfig).filter(
                ScanConfig.name == name
            ).delete()
            session.commit()
            return result > 0
    
    # ==================== Statistics ====================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        with self.get_session() as session:
            total_scans = session.query(func.count(Scan.id)).scalar()
            total_findings = session.query(func.count(Finding.id)).scalar()
            
            severity_counts = (
                session.query(Finding.severity, func.count(Finding.id))
                .group_by(Finding.severity)
                .all()
            )
            
            vuln_type_counts = (
                session.query(Finding.vuln_type, func.count(Finding.id))
                .group_by(Finding.vuln_type)
                .order_by(func.count(Finding.id).desc())
                .limit(10)
                .all()
            )
            
            return {
                "total_scans": total_scans,
                "total_findings": total_findings,
                "severity_breakdown": dict(severity_counts),
                "top_vulnerability_types": dict(vuln_type_counts),
            }


# Singleton instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager(db_url: str = None, echo: bool = False) -> DatabaseManager:
    """Get the singleton database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(db_url=db_url, echo=echo)
    return _db_manager


def reset_db_manager() -> None:
    """Reset the database manager (for testing)"""
    global _db_manager
    _db_manager = None
