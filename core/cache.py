"""
Response Cache
Caching layer for HTTP responses to avoid duplicate requests.
"""

import hashlib
import json
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
import threading


@dataclass
class CacheEntry:
    """A cached response entry"""
    url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    content: str
    cached_at: float
    ttl: int = 3600  # Default 1 hour
    
    @property
    def is_expired(self) -> bool:
        return time.time() > (self.cached_at + self.ttl)


class ResponseCache:
    """
    Cache for HTTP responses to avoid duplicate requests.
    
    Supports:
    - In-memory caching
    - SQLite persistence
    - TTL-based expiration
    - Request deduplication
    """
    
    def __init__(
        self,
        enabled: bool = True,
        ttl: int = 3600,
        max_memory_items: int = 1000,
        persist_to_disk: bool = False,
        db_path: Path = None,
    ):
        self.enabled = enabled
        self.default_ttl = ttl
        self.max_memory_items = max_memory_items
        self.persist_to_disk = persist_to_disk
        
        # In-memory cache
        self._memory_cache: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()
        
        # SQLite persistence
        self._db_path = db_path
        self._db_conn: Optional[sqlite3.Connection] = None
        
        if persist_to_disk and db_path:
            self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database"""
        self._db_conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                url TEXT,
                method TEXT,
                status_code INTEGER,
                headers TEXT,
                content TEXT,
                cached_at REAL,
                ttl INTEGER
            )
        """)
        self._db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_url ON cache(url)
        """)
        self._db_conn.commit()
    
    def _make_key(self, url: str, method: str = "GET", params: Dict = None) -> str:
        """Generate cache key from request parameters"""
        key_parts = [method.upper(), url]
        if params:
            key_parts.append(json.dumps(params, sort_keys=True))
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def get(
        self,
        url: str,
        method: str = "GET",
        params: Dict = None,
    ) -> Optional[CacheEntry]:
        """
        Get cached response if available.
        
        Args:
            url: Request URL
            method: HTTP method
            params: Request parameters
        
        Returns:
            CacheEntry if found and not expired, None otherwise
        """
        if not self.enabled:
            return None
        
        key = self._make_key(url, method, params)
        
        # Check memory cache first
        with self._lock:
            if key in self._memory_cache:
                entry = self._memory_cache[key]
                if not entry.is_expired:
                    return entry
                else:
                    del self._memory_cache[key]
        
        # Check disk cache
        if self.persist_to_disk and self._db_conn:
            return self._get_from_db(key)
        
        return None
    
    def _get_from_db(self, key: str) -> Optional[CacheEntry]:
        """Get entry from SQLite cache"""
        cursor = self._db_conn.execute(
            "SELECT url, method, status_code, headers, content, cached_at, ttl FROM cache WHERE key = ?",
            (key,)
        )
        row = cursor.fetchone()
        
        if row:
            entry = CacheEntry(
                url=row[0],
                method=row[1],
                status_code=row[2],
                headers=json.loads(row[3]),
                content=row[4],
                cached_at=row[5],
                ttl=row[6],
            )
            
            if not entry.is_expired:
                return entry
            else:
                # Clean up expired entry
                self._db_conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                self._db_conn.commit()
        
        return None
    
    def set(
        self,
        url: str,
        method: str,
        status_code: int,
        headers: Dict[str, str],
        content: str,
        params: Dict = None,
        ttl: int = None,
    ):
        """
        Cache a response.
        
        Args:
            url: Request URL
            method: HTTP method
            status_code: Response status code
            headers: Response headers
            content: Response body
            params: Request parameters
            ttl: Time to live in seconds
        """
        if not self.enabled:
            return
        
        key = self._make_key(url, method, params)
        
        entry = CacheEntry(
            url=url,
            method=method,
            status_code=status_code,
            headers=headers,
            content=content,
            cached_at=time.time(),
            ttl=ttl or self.default_ttl,
        )
        
        # Store in memory
        with self._lock:
            # Evict if at capacity
            if len(self._memory_cache) >= self.max_memory_items:
                self._evict_oldest()
            
            self._memory_cache[key] = entry
        
        # Store to disk
        if self.persist_to_disk and self._db_conn:
            self._save_to_db(key, entry)
    
    def _save_to_db(self, key: str, entry: CacheEntry):
        """Save entry to SQLite cache"""
        self._db_conn.execute(
            """
            INSERT OR REPLACE INTO cache 
            (key, url, method, status_code, headers, content, cached_at, ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                entry.url,
                entry.method,
                entry.status_code,
                json.dumps(entry.headers),
                entry.content,
                entry.cached_at,
                entry.ttl,
            )
        )
        self._db_conn.commit()
    
    def _evict_oldest(self):
        """Evict oldest entry from memory cache"""
        if not self._memory_cache:
            return
        
        oldest_key = min(
            self._memory_cache.keys(),
            key=lambda k: self._memory_cache[k].cached_at
        )
        del self._memory_cache[oldest_key]
    
    def clear(self):
        """Clear all cached entries"""
        with self._lock:
            self._memory_cache.clear()
        
        if self.persist_to_disk and self._db_conn:
            self._db_conn.execute("DELETE FROM cache")
            self._db_conn.commit()
    
    def cleanup_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        
        with self._lock:
            expired_keys = [
                k for k, v in self._memory_cache.items()
                if v.cached_at + v.ttl < current_time
            ]
            for key in expired_keys:
                del self._memory_cache[key]
        
        if self.persist_to_disk and self._db_conn:
            self._db_conn.execute(
                "DELETE FROM cache WHERE cached_at + ttl < ?",
                (current_time,)
            )
            self._db_conn.commit()
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "memory_entries": len(self._memory_cache),
            "max_memory_items": self.max_memory_items,
            "persist_to_disk": self.persist_to_disk,
            "default_ttl": self.default_ttl,
        }


# Singleton
_cache: Optional[ResponseCache] = None


def get_cache(**kwargs) -> ResponseCache:
    """Get singleton cache instance"""
    global _cache
    if _cache is None:
        _cache = ResponseCache(**kwargs)
    return _cache
