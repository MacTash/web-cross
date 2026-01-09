"""
Styled Output System - Module-prefixed logging with severity colors.
Ported from sif's Go output package using Rich.
"""

import sys
from typing import TextIO

from rich.console import Console
from rich.style import Style
from rich.text import Text

# Color palette (matching sif)
COLORS = {
    "green": "#22c55e",
    "blue": "#3b82f6",
    "yellow": "#eab308",
    "red": "#ef4444",
    "gray": "#6b7280",
    "white": "#f3f4f6",
    "indigo": "#6366f1",
    "violet": "#8b5cf6",
    "pink": "#ec4899",
    "orange": "#f97316",
    "teal": "#14b8a6",
    "cyan": "#06b6d4",
    "lime": "#84cc16",
    "purple": "#a855f7",
    "rose": "#f43f5e",
    "sky": "#0ea5e9",
}

# Module color palette for distinct prefixes
MODULE_COLORS = [
    COLORS["indigo"],
    COLORS["violet"],
    COLORS["pink"],
    COLORS["orange"],
    COLORS["teal"],
    COLORS["cyan"],
    COLORS["lime"],
    COLORS["purple"],
    COLORS["rose"],
    COLORS["sky"],
]

# Severity styles
SEVERITY_STYLES = {
    "critical": Style(color=COLORS["red"], bold=True),
    "high": Style(color=COLORS["orange"]),
    "medium": Style(color=COLORS["yellow"]),
    "low": Style(color=COLORS["green"]),
    "info": Style(color=COLORS["blue"]),
}

# Global console
_console: Console | None = None
_api_mode = False


def get_console() -> Console:
    """Get the global console instance"""
    global _console
    if _console is None:
        _console = Console(stderr=True)
    return _console


def set_api_mode(enabled: bool) -> None:
    """Enable/disable API mode (suppresses visual output)"""
    global _api_mode
    _api_mode = enabled


def is_tty() -> bool:
    """Check if stdout is a terminal"""
    return sys.stdout.isatty()


def _get_module_color(name: str) -> str:
    """Get consistent color for a module name"""
    hash_val = sum(ord(c) * 31 for c in name)
    return MODULE_COLORS[hash_val % len(MODULE_COLORS)]


def severity_style(severity: str) -> Style:
    """Get Rich style for severity level"""
    return SEVERITY_STYLES.get(severity.lower(), SEVERITY_STYLES["info"])


def info(message: str, *args) -> None:
    """Print info message with [*] prefix"""
    if _api_mode:
        return
    console = get_console()
    msg = message % args if args else message
    console.print(f"[bold {COLORS['blue']}][*][/] {msg}")


def success(message: str, *args) -> None:
    """Print success message with [+] prefix"""
    if _api_mode:
        return
    console = get_console()
    msg = message % args if args else message
    console.print(f"[bold {COLORS['green']}][+][/] {msg}")


def warn(message: str, *args) -> None:
    """Print warning message with [!] prefix"""
    if _api_mode:
        return
    console = get_console()
    msg = message % args if args else message
    console.print(f"[bold {COLORS['yellow']}][!][/] {msg}")


def error(message: str, *args) -> None:
    """Print error message with [-] prefix"""
    if _api_mode:
        return
    console = get_console()
    msg = message % args if args else message
    console.print(f"[bold {COLORS['red']}][-][/] {msg}")


def scan_start(scan_name: str) -> None:
    """Print scan start message"""
    if _api_mode:
        return
    console = get_console()
    console.print(f"[bold {COLORS['blue']}][*][/] starting {scan_name}")


def scan_complete(scan_name: str, result_count: int, result_type: str) -> None:
    """Print scan complete message"""
    if _api_mode:
        return
    console = get_console()
    console.print(
        f"[bold {COLORS['blue']}][*][/] {scan_name} complete "
        f"({result_count} {result_type})"
    )


def highlight(text: str) -> str:
    """Return highlighted text markup"""
    return f"[bold {COLORS['white']}]{text}[/]"


def muted(text: str) -> str:
    """Return muted text markup"""
    return f"[{COLORS['gray']}]{text}[/]"


def status(text: str) -> str:
    """Return status text markup"""
    return f"[bold {COLORS['green']}]{text}[/]"


class ModuleLogger:
    """
    Module-specific logger with styled prefix.
    
    Usage:
        log = ModuleLogger("HEADERS")
        log.start()
        log.success("Found X-Frame-Options header")
        log.complete(5, "headers")
    """

    def __init__(self, name: str):
        self.name = name
        self.color = _get_module_color(name)
        self._console = get_console()

    def _prefix(self) -> str:
        return f"[bold white on {self.color}] {self.name} [/]"

    def info(self, message: str, *args) -> None:
        """Print info message with module prefix"""
        if _api_mode:
            return
        msg = message % args if args else message
        self._console.print(f"{self._prefix()} {msg}")

    def success(self, message: str, *args) -> None:
        """Print success message with module prefix"""
        if _api_mode:
            return
        msg = message % args if args else message
        self._console.print(
            f"{self._prefix()} [bold {COLORS['green']}]✓[/] {msg}"
        )

    def warn(self, message: str, *args) -> None:
        """Print warning message with module prefix"""
        if _api_mode:
            return
        msg = message % args if args else message
        self._console.print(
            f"{self._prefix()} [bold {COLORS['yellow']}]![/] {msg}"
        )

    def error(self, message: str, *args) -> None:
        """Print error message with module prefix"""
        if _api_mode:
            return
        msg = message % args if args else message
        self._console.print(
            f"{self._prefix()} [bold {COLORS['red']}]✗[/] {msg}"
        )

    def start(self) -> None:
        """Print scan start message"""
        if _api_mode:
            return
        self._console.print(f"\n{self._prefix()} starting scan")

    def complete(self, result_count: int, result_type: str) -> None:
        """Print scan complete message"""
        if _api_mode:
            return
        self._console.print(
            f"{self._prefix()} complete ({result_count} {result_type})"
        )


def print_summary(scans: list[str], log_files: list[str] | None = None) -> None:
    """Print scan completion summary"""
    if _api_mode:
        return

    console = get_console()
    console.print()
    console.print(f"[{COLORS['gray']}]{'─' * 60}[/]")
    console.print()
    console.print(f"  [bold white on {COLORS['green']}] SCAN COMPLETE [/]")
    console.print()

    scan_list = ", ".join(scans)
    console.print(f"  [{COLORS['gray']}]Scans:[/] {scan_list}")

    if log_files:
        console.print(f"  [{COLORS['gray']}]Output:[/] {', '.join(log_files)}")

    console.print()
    console.print(f"[{COLORS['gray']}]{'─' * 60}[/]")
    console.print()
