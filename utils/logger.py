"""
Web-Cross Logger Module
Enhanced logging with structured output, file rotation, and colored console.
"""

import functools
import json
import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# Try to import rich for colored output
try:
    from rich.console import Console
    from rich.logging import RichHandler
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter"""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "scan_id"):
            log_data["scan_id"] = record.scan_id
        if hasattr(record, "target"):
            log_data["target"] = record.target
        if hasattr(record, "module_name"):
            log_data["module_name"] = record.module_name
        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter (fallback when rich not available)"""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    structured: bool = False,
    console: bool = True,
) -> None:
    """
    Set up logging configuration for Web-Cross.
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        structured: Use JSON structured logging
        console: Enable console output
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    if console:
        if RICH_AVAILABLE and not structured:
            # Use rich for pretty console output
            console_handler = RichHandler(
                console=Console(stderr=True),
                show_time=True,
                show_path=False,
                rich_tracebacks=True,
            )
            console_handler.setFormatter(logging.Formatter("%(message)s"))
        else:
            console_handler = logging.StreamHandler(sys.stderr)
            if structured:
                console_handler.setFormatter(StructuredFormatter())
            else:
                console_handler.setFormatter(ColoredFormatter(
                    "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                    datefmt="%H:%M:%S"
                ))
        root_logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )

        if structured:
            file_handler.setFormatter(StructuredFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            ))
        root_logger.addHandler(file_handler)


def get_logger(
    name: str,
    scan_id: str = None,
    target: str = None,
) -> logging.Logger:
    """
    Get a logger instance with optional context.
    Args:
        name: Logger name (typically module name)
        scan_id: Optional scan ID for context
        target: Optional target URL for context
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Create adapter if context provided
    if scan_id or target:
        extra = {}
        if scan_id:
            extra["scan_id"] = scan_id
        if target:
            extra["target"] = target
        return ScanLoggerAdapter(logger, extra)

    return logger


class ScanLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that adds scan context to log records"""

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple:
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs

    def scan_event(
        self,
        event: str,
        message: str,
        data: dict[str, Any] = None,
        level: int = logging.INFO,
    ) -> None:
        """Log a scan event with structured data"""
        extra = {"event": event}
        if data:
            extra["extra_data"] = data
        self.log(level, f"[{event}] {message}", extra=extra)


def log_scan_start(
    logger: logging.Logger,
    target: str,
    scan_id: str,
    mode: str,
) -> None:
    """Log scan start event"""
    logger.info(
        f"Starting scan: target={target}, scan_id={scan_id}, mode={mode}",
        extra={"scan_id": scan_id, "target": target, "event": "SCAN_START"}
    )


def log_scan_complete(
    logger: logging.Logger,
    scan_id: str,
    duration: float,
    findings_count: int,
) -> None:
    """Log scan completion event"""
    logger.info(
        f"Scan complete: scan_id={scan_id}, duration={duration:.2f}s, findings={findings_count}",
        extra={"scan_id": scan_id, "event": "SCAN_COMPLETE"}
    )


def log_finding(
    logger: logging.Logger,
    scan_id: str,
    vuln_type: str,
    severity: str,
    url: str,
) -> None:
    """Log a vulnerability finding"""
    logger.warning(
        f"Finding: {vuln_type} ({severity}) at {url}",
        extra={
            "scan_id": scan_id,
            "event": "FINDING",
            "extra_data": {
                "type": vuln_type,
                "severity": severity,
                "url": url,
            }
        }
    )


def timed(logger: logging.Logger = None):
    """Decorator to log function execution time"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = datetime.now()
            result = func(*args, **kwargs)
            elapsed = (datetime.now() - start).total_seconds()

            log = logger or get_logger(func.__module__)
            log.debug(f"{func.__name__} completed in {elapsed:.3f}s")

            return result
        return wrapper
    return decorator


def async_timed(logger: logging.Logger = None):
    """Decorator to log async function execution time"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start = datetime.now()
            result = await func(*args, **kwargs)
            elapsed = (datetime.now() - start).total_seconds()

            log = logger or get_logger(func.__module__)
            log.debug(f"{func.__name__} completed in {elapsed:.3f}s")

            return result
        return wrapper
    return decorator
