"""File I/O utilities for fbsfilter.

Provides memory-efficient streaming reads of large credential files and
thread-safe writers for each result category.
"""

import os
import threading
from typing import Generator, Tuple, Optional


class CredentialReader:
    """Stream credential pairs from a file without loading it all into memory."""

    def __init__(self, filepath: str, delimiter: str = ":", encoding: str = "utf-8"):
        self.filepath = filepath
        self.delimiter = delimiter
        self.encoding = encoding

    def count_lines(self) -> int:
        """Return the approximate number of non-blank lines (for progress bars)."""
        count = 0
        try:
            with open(self.filepath, "r", encoding=self.encoding, errors="replace") as fh:
                for line in fh:
                    if line.strip():
                        count += 1
        except OSError:
            count = 0
        return count

    def stream(self) -> Generator[Tuple[str, str], None, None]:
        """Yield (username, password) tuples one at a time."""
        with open(self.filepath, "r", encoding=self.encoding, errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(self.delimiter, 1)
                if len(parts) != 2:
                    continue
                username, password = parts[0].strip(), parts[1].strip()
                if username and password:
                    yield username, password


class ResultWriter:
    """Thread-safe writer that appends results to output files on the fly."""

    def __init__(
        self,
        working_file: str = "working.txt",
        invalid_file: str = "invalid.txt",
        locked_file: str = "locked.txt",
        twofa_file: str = "2fa.txt",
    ):
        self.files = {
            "working": working_file,
            "invalid": invalid_file,
            "locked": locked_file,
            "2fa": twofa_file,
        }
        self._lock = threading.Lock()
        self._handles: dict = {}
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        for path in self.files.values():
            d = os.path.dirname(path)
            if d:
                os.makedirs(d, exist_ok=True)

    def _get_handle(self, category: str):
        if category not in self._handles:
            self._handles[category] = open(
                self.files[category], "a", encoding="utf-8", buffering=1
            )
        return self._handles[category]

    def write(self, category: str, username: str, password: str, extra: str = "") -> None:
        """Append a credential to the appropriate output file."""
        line = f"{username}:{password}"
        if extra:
            line += f"  # {extra}"
        line += "\n"
        with self._lock:
            fh = self._get_handle(category)
            fh.write(line)

    def close(self) -> None:
        with self._lock:
            for fh in self._handles.values():
                try:
                    fh.close()
                except OSError:
                    pass
            self._handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class CheckpointManager:
    """Save and restore processing position so a run can be resumed."""

    def __init__(self, checkpoint_file: str = ".fbsfilter_checkpoint"):
        self.checkpoint_file = checkpoint_file
        self._lock = threading.Lock()

    def save(self, processed: int) -> None:
        with self._lock:
            try:
                with open(self.checkpoint_file, "w", encoding="utf-8") as fh:
                    fh.write(str(processed))
            except OSError:
                pass

    def load(self) -> int:
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as fh:
                return max(0, int(fh.read().strip()))
        except (OSError, ValueError):
            return 0

    def clear(self) -> None:
        try:
            os.remove(self.checkpoint_file)
        except OSError:
            pass
