"""
Cloud Storage Scanner - Detect misconfigured cloud storage buckets.
Ported from sif's C3 (Cloud Storage Misconfiguration) scanner.
"""

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests


@dataclass
class CloudStorageResult:
    """Result from cloud storage scan"""
    bucket_name: str
    is_public: bool
    provider: str = "aws"
    url: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket_name": self.bucket_name,
            "is_public": self.is_public,
            "provider": self.provider,
            "url": self.url,
            "error": self.error,
        }


class CloudStorageScanner:
    """
    Cloud Storage Misconfiguration Scanner.
    
    Detects:
    - Public S3 buckets
    - Azure blob storage misconfigurations
    - Google Cloud Storage issues
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: str = None,
    ):
        self.timeout = timeout
        self.user_agent = user_agent or "WebCross-Scanner/3.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
        })

    def _extract_potential_buckets(self, url: str) -> list[str]:
        """Extract potential bucket names from URL"""
        parsed = urlparse(url)
        domain = parsed.netloc or url
        
        # Remove port if present
        domain = domain.split(":")[0]
        
        # Split domain parts
        parts = domain.split(".")
        buckets = []
        
        for i, part in enumerate(parts):
            # Skip common TLDs
            if part in ("com", "net", "org", "io", "co", "www"):
                continue
                
            buckets.append(part)
            buckets.append(f"{part}-s3")
            buckets.append(f"s3-{part}")
            buckets.append(f"{part}-bucket")
            buckets.append(f"{part}-assets")
            buckets.append(f"{part}-static")
            buckets.append(f"{part}-media")
            buckets.append(f"{part}-backup")
            
            if i < len(parts) - 1:
                combined = f"{part}-{parts[i + 1]}"
                buckets.append(combined)
                buckets.append(f"{parts[i + 1]}-{part}")
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for b in buckets:
            if b not in seen:
                seen.add(b)
                unique.append(b)
        
        return unique

    def _check_s3_bucket(self, bucket: str) -> CloudStorageResult:
        """Check if an S3 bucket is publicly accessible"""
        url = f"https://{bucket}.s3.amazonaws.com"
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            
            # If we can access the bucket listing, it's public
            is_public = resp.status_code == 200
            
            return CloudStorageResult(
                bucket_name=bucket,
                is_public=is_public,
                provider="aws",
                url=url,
            )
        except Exception as e:
            return CloudStorageResult(
                bucket_name=bucket,
                is_public=False,
                provider="aws",
                url=url,
                error=str(e),
            )

    def _check_azure_blob(self, container: str) -> CloudStorageResult:
        """Check if an Azure blob container is publicly accessible"""
        # Try common Azure storage account patterns
        url = f"https://{container}.blob.core.windows.net/"
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            is_public = resp.status_code in (200, 400)  # 400 means exists but denied
            
            return CloudStorageResult(
                bucket_name=container,
                is_public=is_public and resp.status_code == 200,
                provider="azure",
                url=url,
            )
        except Exception as e:
            return CloudStorageResult(
                bucket_name=container,
                is_public=False,
                provider="azure",
                url=url,
                error=str(e),
            )

    def _check_gcs_bucket(self, bucket: str) -> CloudStorageResult:
        """Check if a Google Cloud Storage bucket is publicly accessible"""
        url = f"https://storage.googleapis.com/{bucket}"
        
        try:
            resp = self.session.get(url, timeout=self.timeout)
            is_public = resp.status_code == 200
            
            return CloudStorageResult(
                bucket_name=bucket,
                is_public=is_public,
                provider="gcp",
                url=url,
            )
        except Exception as e:
            return CloudStorageResult(
                bucket_name=bucket,
                is_public=False,
                provider="gcp",
                url=url,
                error=str(e),
            )

    def scan_url(self, url: str) -> list[dict[str, Any]]:
        """
        Scan a URL for cloud storage misconfigurations.
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of findings
        """
        findings = []
        potential_buckets = self._extract_potential_buckets(url)
        
        for bucket in potential_buckets:
            # Check S3
            result = self._check_s3_bucket(bucket)
            if result.is_public:
                findings.append({
                    "type": "cloud_storage",
                    "name": "Public S3 Bucket",
                    "severity": "HIGH",
                    "description": f"Public S3 bucket found: {bucket}",
                    "evidence": result.url,
                    "details": result.to_dict(),
                })
            
            # Check GCS
            result = self._check_gcs_bucket(bucket)
            if result.is_public:
                findings.append({
                    "type": "cloud_storage",
                    "name": "Public GCS Bucket",
                    "severity": "HIGH",
                    "description": f"Public Google Cloud Storage bucket found: {bucket}",
                    "evidence": result.url,
                    "details": result.to_dict(),
                })
            
            # Check Azure
            result = self._check_azure_blob(bucket)
            if result.is_public:
                findings.append({
                    "type": "cloud_storage",
                    "name": "Public Azure Blob",
                    "severity": "HIGH",
                    "description": f"Public Azure blob container found: {bucket}",
                    "evidence": result.url,
                    "details": result.to_dict(),
                })
        
        return findings

    def scan_content(self, content: str) -> list[dict[str, Any]]:
        """
        Scan HTML/JS content for cloud storage references.
        
        Args:
            content: HTML or JavaScript content
            
        Returns:
            List of findings
        """
        findings = []
        
        # S3 bucket patterns
        s3_patterns = [
            r'https?://([a-zA-Z0-9.-]+)\.s3\.amazonaws\.com',
            r'https?://s3\.amazonaws\.com/([a-zA-Z0-9.-]+)',
            r'https?://([a-zA-Z0-9.-]+)\.s3-[a-z0-9-]+\.amazonaws\.com',
        ]
        
        for pattern in s3_patterns:
            matches = re.findall(pattern, content)
            for bucket in matches:
                result = self._check_s3_bucket(bucket)
                if result.is_public:
                    findings.append({
                        "type": "cloud_storage",
                        "name": "Referenced Public S3 Bucket",
                        "severity": "MEDIUM",
                        "description": f"Public S3 bucket referenced in content: {bucket}",
                        "evidence": result.url,
                        "details": result.to_dict(),
                    })
        
        # GCS patterns
        gcs_patterns = [
            r'https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)',
            r'https?://storage\.cloud\.google\.com/([a-zA-Z0-9._-]+)',
        ]
        
        for pattern in gcs_patterns:
            matches = re.findall(pattern, content)
            for bucket in matches:
                result = self._check_gcs_bucket(bucket)
                if result.is_public:
                    findings.append({
                        "type": "cloud_storage",
                        "name": "Referenced Public GCS Bucket",
                        "severity": "MEDIUM",
                        "description": f"Public GCS bucket referenced in content: {bucket}",
                        "evidence": result.url,
                        "details": result.to_dict(),
                    })
        
        return findings


def get_scanner(timeout: int = 10, user_agent: str = None) -> CloudStorageScanner:
    """Get a Cloud Storage scanner instance"""
    return CloudStorageScanner(timeout=timeout, user_agent=user_agent)
