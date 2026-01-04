"""
Scan State Manager
Persistence layer for scan state to enable resume capability.
"""

import json
import time
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path
import threading


@dataclass
class ScanState:
    """Complete state of a scan for resume capability"""
    scan_id: str
    target_url: str
    phase: str = "pending"  # pending, crawling, scanning, reporting, completed
    progress_percent: float = 0.0
    
    # URLs state
    discovered_urls: List[str] = field(default_factory=list)
    scanned_urls: List[str] = field(default_factory=list)
    pending_urls: List[str] = field(default_factory=list)
    
    # Forms state
    discovered_forms: List[Dict] = field(default_factory=list)
    scanned_forms: List[Dict] = field(default_factory=list)
    
    # Findings
    findings: List[Dict] = field(default_factory=list)
    technologies: List[Dict] = field(default_factory=list)
    
    # Timing
    started_at: float = 0.0
    last_updated: float = 0.0
    
    # Configuration
    scan_mode: str = "full"
    ai_enabled: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanState":
        return cls(**data)


class ScanStateManager:
    """
    Manages scan state for pause/resume capability.
    
    Features:
    - Periodic state persistence
    - Resume from last known state
    - Multiple scan tracking
    - Disk and database storage
    """
    
    def __init__(
        self,
        state_dir: Path = None,
        auto_save_interval: int = 30,  # seconds
    ):
        self.state_dir = state_dir or Path.cwd() / "data" / "states"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.auto_save_interval = auto_save_interval
        
        # Active scans
        self._states: Dict[str, ScanState] = {}
        self._lock = threading.Lock()
        
        # Load existing states
        self._load_existing_states()
    
    def _load_existing_states(self):
        """Load existing scan states from disk"""
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, "r") as f:
                    data = json.load(f)
                    state = ScanState.from_dict(data)
                    # Only load incomplete scans
                    if state.phase != "completed":
                        self._states[state.scan_id] = state
            except Exception:
                pass
    
    def create_scan(
        self,
        scan_id: str,
        target_url: str,
        scan_mode: str = "full",
        ai_enabled: bool = False,
    ) -> ScanState:
        """
        Create a new scan state.
        
        Args:
            scan_id: Unique scan identifier
            target_url: Target URL
            scan_mode: Scan mode
            ai_enabled: Whether AI is enabled
        
        Returns:
            New ScanState
        """
        state = ScanState(
            scan_id=scan_id,
            target_url=target_url,
            phase="pending",
            started_at=time.time(),
            last_updated=time.time(),
            scan_mode=scan_mode,
            ai_enabled=ai_enabled,
        )
        
        with self._lock:
            self._states[scan_id] = state
        
        self._save_state(state)
        return state
    
    def get_state(self, scan_id: str) -> Optional[ScanState]:
        """Get scan state by ID"""
        with self._lock:
            return self._states.get(scan_id)
    
    def update_phase(
        self,
        scan_id: str,
        phase: str,
        progress: float = None,
    ) -> Optional[ScanState]:
        """
        Update scan phase.
        
        Args:
            scan_id: Scan identifier
            phase: New phase
            progress: Optional progress percentage
        
        Returns:
            Updated state
        """
        with self._lock:
            state = self._states.get(scan_id)
            if state:
                state.phase = phase
                if progress is not None:
                    state.progress_percent = progress
                state.last_updated = time.time()
                self._save_state(state)
            return state
    
    def add_discovered_urls(
        self,
        scan_id: str,
        urls: List[str],
    ) -> Optional[ScanState]:
        """Add discovered URLs to scan state"""
        with self._lock:
            state = self._states.get(scan_id)
            if state:
                existing = set(state.discovered_urls)
                for url in urls:
                    if url not in existing:
                        state.discovered_urls.append(url)
                        state.pending_urls.append(url)
                state.last_updated = time.time()
                self._save_state(state)
            return state
    
    def mark_url_scanned(
        self,
        scan_id: str,
        url: str,
    ) -> Optional[ScanState]:
        """Mark a URL as scanned"""
        with self._lock:
            state = self._states.get(scan_id)
            if state:
                if url not in state.scanned_urls:
                    state.scanned_urls.append(url)
                if url in state.pending_urls:
                    state.pending_urls.remove(url)
                state.last_updated = time.time()
                
                # Update progress
                total = len(state.discovered_urls) or 1
                scanned = len(state.scanned_urls)
                state.progress_percent = (scanned / total) * 100
                
                self._save_state(state)
            return state
    
    def add_finding(
        self,
        scan_id: str,
        finding: Dict[str, Any],
    ) -> Optional[ScanState]:
        """Add a vulnerability finding"""
        with self._lock:
            state = self._states.get(scan_id)
            if state:
                state.findings.append(finding)
                state.last_updated = time.time()
                self._save_state(state)
            return state
    
    def add_technology(
        self,
        scan_id: str,
        technology: Dict[str, Any],
    ) -> Optional[ScanState]:
        """Add detected technology"""
        with self._lock:
            state = self._states.get(scan_id)
            if state:
                state.technologies.append(technology)
                state.last_updated = time.time()
            return state
    
    def complete_scan(self, scan_id: str) -> Optional[ScanState]:
        """Mark scan as completed"""
        with self._lock:
            state = self._states.get(scan_id)
            if state:
                state.phase = "completed"
                state.progress_percent = 100.0
                state.last_updated = time.time()
                self._save_state(state)
            return state
    
    def get_resumable_scans(self) -> List[ScanState]:
        """Get list of incomplete scans that can be resumed"""
        with self._lock:
            return [
                s for s in self._states.values()
                if s.phase not in ("completed", "failed")
            ]
    
    def can_resume(self, scan_id: str) -> bool:
        """Check if a scan can be resumed"""
        state = self.get_state(scan_id)
        return state is not None and state.phase not in ("completed", "failed")
    
    def delete_state(self, scan_id: str):
        """Delete scan state"""
        with self._lock:
            if scan_id in self._states:
                del self._states[scan_id]
        
        state_file = self.state_dir / f"{scan_id}.json"
        if state_file.exists():
            state_file.unlink()
    
    def _save_state(self, state: ScanState):
        """Save state to disk"""
        state_file = self.state_dir / f"{state.scan_id}.json"
        try:
            with open(state_file, "w") as f:
                json.dump(state.to_dict(), f, indent=2)
        except Exception:
            pass
    
    def cleanup_old_states(self, max_age_hours: int = 24):
        """Remove old completed scan states"""
        cutoff = time.time() - (max_age_hours * 3600)
        
        for state_file in self.state_dir.glob("*.json"):
            try:
                with open(state_file, "r") as f:
                    data = json.load(f)
                
                if data.get("phase") == "completed":
                    if data.get("last_updated", 0) < cutoff:
                        state_file.unlink()
                        scan_id = data.get("scan_id")
                        with self._lock:
                            if scan_id in self._states:
                                del self._states[scan_id]
            except Exception:
                pass


# Singleton
_manager: Optional[ScanStateManager] = None


def get_state_manager(**kwargs) -> ScanStateManager:
    """Get singleton state manager"""
    global _manager
    if _manager is None:
        _manager = ScanStateManager(**kwargs)
    return _manager
