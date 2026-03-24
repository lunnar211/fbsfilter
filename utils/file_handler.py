"""File I/O utilities for fbsfilter.

Provides memory-efficient streaming reads of large credential files and
thread-safe writers for each result category.
"""

import datetime
import os
import threading
from typing import Generator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Delimiter auto-detection
# ---------------------------------------------------------------------------

_CANDIDATE_DELIMITERS = [":", "|", ",", ";", "\t"]


def auto_detect_delimiter(filepath: str, encoding: str = "utf-8", sample_lines: int = 50) -> str:
    """Inspect the first *sample_lines* non-blank lines of *filepath* and return
    the most likely credential delimiter.

    Logic: for each candidate delimiter, count lines that produce exactly two
    non-empty parts (username + password). The delimiter with the highest valid
    split count wins.  Falls back to ":" if nothing scores > 0.

    Notes:
    - Emails contain "@" and dots but NOT "|", ",", ";", or "\\t", so those
      delimiters are unambiguous.
    - The colon ":" is the only tricky case because it appears in URLs.  We
      accept ":" splits only when neither part looks like a bare URL path.
    """
    scores = {d: 0 for d in _CANDIDATE_DELIMITERS}
    try:
        with open(filepath, "r", encoding=encoding, errors="replace") as fh:
            checked = 0
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                for delim in _CANDIDATE_DELIMITERS:
                    parts = line.split(delim, 1)
                    if len(parts) == 2:
                        u, p = parts[0].strip(), parts[1].strip()
                        if u and p and " " not in u:
                            scores[delim] += 1
                checked += 1
                if checked >= sample_lines:
                    break
    except OSError:
        return ":"

    best = max(scores, key=lambda d: scores[d])
    return best if scores[best] > 0 else ":"


# ---------------------------------------------------------------------------
# Credential reader
# ---------------------------------------------------------------------------

class CredentialReader:
    """Stream credential pairs from a file without loading it all into memory.

    If *delimiter* is ``"auto"`` (the default), the delimiter is detected
    automatically by sampling the first 50 lines of the file.
    """

    def __init__(self, filepath: str, delimiter: str = "auto", encoding: str = "utf-8"):
        self.filepath = filepath
        self.encoding = encoding
        if delimiter == "auto":
            self.delimiter = auto_detect_delimiter(filepath, encoding)
        else:
            self.delimiter = delimiter

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
        """Yield (username, password) tuples one at a time.

        Lines that cannot be split into exactly two parts are skipped silently.
        Use :meth:`stream_with_malformed` if you need to capture them.
        """
        for username, password, _ in self.stream_with_malformed():
            if username is not None:
                yield username, password

    def stream_with_malformed(
        self,
    ) -> Generator[Tuple[Optional[str], Optional[str], str], None, None]:
        """Yield ``(username, password, raw_line)`` tuples.

        For valid lines ``username`` and ``password`` are strings.
        For malformed lines ``username`` and ``password`` are ``None`` and
        ``raw_line`` contains the original text.
        """
        with open(self.filepath, "r", encoding=self.encoding, errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(self.delimiter, 1)
                if len(parts) != 2:
                    yield None, None, line
                    continue
                username, password = parts[0].strip(), parts[1].strip()
                if username and password:
                    yield username, password, line
                else:
                    yield None, None, line


# ---------------------------------------------------------------------------
# Result writer
# ---------------------------------------------------------------------------

class ResultWriter:
    """Thread-safe writer that appends results to output files on the fly."""

    def __init__(
        self,
        working_file: str = "working.txt",
        invalid_file: str = "invalid.txt",
        locked_file: str = "locked.txt",
        twofa_file: str = "2fa.txt",
        error_file: str = "error.txt",
        malformed_file: str = "malformed.txt",
    ):
        self.files = {
            "working": working_file,
            "invalid": invalid_file,
            "locked": locked_file,
            "2fa": twofa_file,
            "error": error_file,
            "malformed": malformed_file,
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

    def write_malformed(self, raw_line: str) -> None:
        """Append a malformed (unparseable) line to malformed.txt."""
        with self._lock:
            fh = self._get_handle("malformed")
            fh.write(raw_line + "\n")

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


# ---------------------------------------------------------------------------
# Session-aware result writer (timestamped folders)
# ---------------------------------------------------------------------------

class SessionResultWriter(ResultWriter):
    """ResultWriter that saves all output files inside a timestamped folder.

    The folder is named ``results_YYYY-MM-DD_HH-MM-SS`` and is created
    automatically on first write.
    """

    def __init__(self, base_dir: str = ".", session_name: Optional[str] = None):
        if session_name is None:
            session_name = "results_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.session_dir = os.path.join(base_dir, session_name)
        os.makedirs(self.session_dir, exist_ok=True)

        def _p(name: str) -> str:
            return os.path.join(self.session_dir, name)

        super().__init__(
            working_file=_p("working.txt"),
            invalid_file=_p("invalid.txt"),
            locked_file=_p("locked.txt"),
            twofa_file=_p("2fa.txt"),
            error_file=_p("error.txt"),
            malformed_file=_p("malformed.txt"),
        )


# ---------------------------------------------------------------------------
# Checkpoint manager
# ---------------------------------------------------------------------------

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

