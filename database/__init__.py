"""
Web-Cross Database Module
SQLAlchemy models and database management for scan history.
"""

from .models import Base, Scan, Finding, Technology, ScanConfig
from .manager import DatabaseManager, get_db_manager

__all__ = [
    "Base",
    "Scan",
    "Finding",
    "Technology",
    "ScanConfig",
    "DatabaseManager",
    "get_db_manager",
]
