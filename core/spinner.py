"""
Spinner - Animated spinner for indeterminate operations.
Ported from sif's Go spinner component.
"""

import threading
import time
from typing import TextIO

from rich.console import Console
from rich.spinner import Spinner as RichSpinner
from rich.live import Live

_api_mode = False

SPINNER_FRAMES = ["|", "/", "-", "\\"]


def set_api_mode(enabled: bool) -> None:
    """Enable/disable API mode"""
    global _api_mode
    _api_mode = enabled


class Spinner:
    """
    Animated spinner for operations with unknown duration.
    
    Usage:
        spinner = Spinner("Scanning endpoints")
        spinner.start()
        # ... do work ...
        spinner.stop()
    """

    def __init__(
        self,
        message: str,
        console: Console | None = None,
    ):
        self.message = message
        self._console = console or Console(stderr=True)
        self._live: Live | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the spinner animation"""
        if _api_mode:
            return

        with self._lock:
            if self._running:
                return
            self._running = True

            # Use Rich's spinner
            spinner = RichSpinner("dots", text=f"[bold blue]{self.message}")
            self._live = Live(
                spinner,
                console=self._console,
                refresh_per_second=10,
                transient=True,
            )
            self._live.start()

    def stop(self) -> None:
        """Stop the spinner and clear the line"""
        if _api_mode:
            return

        with self._lock:
            if not self._running:
                return
            self._running = False

            if self._live:
                self._live.stop()
                self._live = None

    def update(self, message: str) -> None:
        """Update the spinner message"""
        with self._lock:
            self.message = message
            if self._running and self._live:
                spinner = RichSpinner("dots", text=f"[bold blue]{message}")
                self._live.update(spinner)

    def __enter__(self) -> "Spinner":
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()


class SimpleSpinner:
    """
    Simple ASCII spinner without Rich dependency.
    Useful for minimal environments.
    """

    def __init__(
        self,
        message: str,
        interval: float = 0.1,
        stream: TextIO | None = None,
    ):
        self.message = message
        self.interval = interval
        self._stream = stream
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the spinner"""
        if _api_mode:
            return

        import sys
        stream = self._stream or sys.stderr

        with self._lock:
            if self._running:
                return
            self._running = True

            # Non-TTY: print message once
            if not stream.isatty():
                stream.write(f"    {self.message}...\n")
                stream.flush()
                return

            # TTY: animate
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop the spinner"""
        if _api_mode:
            return

        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._thread:
            self._thread.join(timeout=self.interval * 2)
            self._thread = None

        # Clear line
        import sys
        stream = self._stream or sys.stderr
        if stream.isatty():
            stream.write("\033[2K\r")
            stream.flush()

    def _animate(self) -> None:
        """Animation loop"""
        import sys
        stream = self._stream or sys.stderr
        frame = 0

        while self._running:
            with self._lock:
                msg = self.message
                running = self._running

            if not running:
                break

            char = SPINNER_FRAMES[frame]
            line = f"\r    {char} {msg}"
            stream.write("\033[2K")  # Clear line
            stream.write(line)
            stream.flush()

            frame = (frame + 1) % len(SPINNER_FRAMES)
            time.sleep(self.interval)

    def update(self, message: str) -> None:
        """Update the message"""
        with self._lock:
            self.message = message

    def __enter__(self) -> "SimpleSpinner":
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()
