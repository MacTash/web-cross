"""
Web-Cross Database Module
SQLAlchemy models and database management for scan history.
"""

from .manager import DatabaseManager, get_db_manager
from .models import Base, Finding, Scan, ScanConfig, Technology

__all__ = [
    "Base",
    "Scan",
    "Finding",
    "Technology",
    "ScanConfig",
    "DatabaseManager",
    "get_db_manager",
]
