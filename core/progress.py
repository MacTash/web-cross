"""
Progress Bar - Thread-safe progress tracking with TTY support.
Ported from sif's Go progress package using Rich.
"""

import threading
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

_api_mode = False


def set_api_mode(enabled: bool) -> None:
    """Enable/disable API mode"""
    global _api_mode
    _api_mode = enabled


class ScanProgress:
    """
    Thread-safe progress bar for scan operations.
    
    Features:
    - Atomic increment
    - Current item display
    - Pause/resume support
    - TTY detection
    """

    def __init__(
        self,
        total: int,
        message: str = "Scanning",
        console: Console | None = None,
    ):
        self.total = total
        self.message = message
        self._current = 0
        self._last_item = ""
        self._lock = threading.Lock()
        self._paused = False
        self._console = console or Console(stderr=True)
        
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("{task.fields[item]}"),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        )
        self._task_id: Any = None
        self._started = False

    def start(self) -> None:
        """Start the progress display"""
        if _api_mode:
            return
        if not self._started:
            self._progress.start()
            self._task_id = self._progress.add_task(
                self.message,
                total=self.total,
                item="",
            )
            self._started = True

    def increment(self, item: str = "") -> None:
        """Increment progress by 1"""
        with self._lock:
            self._current += 1
            if item:
                self._last_item = item

            if _api_mode or not self._started:
                return

            if not self._paused:
                self._progress.update(
                    self._task_id,
                    completed=self._current,
                    item=self._truncate_item(self._last_item),
                )

    def set(self, current: int, item: str = "") -> None:
        """Set progress to specific value"""
        with self._lock:
            self._current = current
            if item:
                self._last_item = item

            if _api_mode or not self._started:
                return

            if not self._paused:
                self._progress.update(
                    self._task_id,
                    completed=self._current,
                    item=self._truncate_item(self._last_item),
                )

    def pause(self) -> None:
        """Pause progress display (for printing other output)"""
        with self._lock:
            self._paused = True
            if self._started:
                self._progress.stop()

    def resume(self) -> None:
        """Resume progress display"""
        with self._lock:
            self._paused = False
            if self._started:
                self._progress.start()

    def done(self) -> None:
        """Complete and clean up progress display"""
        if self._started:
            self._progress.stop()
            self._started = False

    def _truncate_item(self, item: str, max_len: int = 30) -> str:
        """Truncate item display"""
        if len(item) > max_len:
            return item[:max_len - 3] + "..."
        return item

    def __enter__(self) -> "ScanProgress":
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.done()


class MultiProgress:
    """
    Manage multiple concurrent progress bars.
    
    Useful for parallel scan modules.
    """

    def __init__(self, console: Console | None = None):
        self._console = console or Console(stderr=True)
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=20),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self._console,
        )
        self._tasks: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._started = False

    def start(self) -> None:
        """Start multi-progress display"""
        if _api_mode:
            return
        if not self._started:
            self._progress.start()
            self._started = True

    def add_task(self, name: str, total: int) -> str:
        """Add a new tracked task"""
        if _api_mode:
            return name
        with self._lock:
            task_id = self._progress.add_task(name, total=total)
            self._tasks[name] = task_id
        return name

    def update(self, name: str, completed: int) -> None:
        """Update a specific task"""
        if _api_mode or not self._started:
            return
        with self._lock:
            if name in self._tasks:
                self._progress.update(self._tasks[name], completed=completed)

    def increment(self, name: str, advance: int = 1) -> None:
        """Increment a specific task"""
        if _api_mode or not self._started:
            return
        with self._lock:
            if name in self._tasks:
                self._progress.advance(self._tasks[name], advance)

    def done(self) -> None:
        """Complete all tasks"""
        if self._started:
            self._progress.stop()
            self._started = False

    def __enter__(self) -> "MultiProgress":
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.done()
