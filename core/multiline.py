"""
Multiline Log Boundary Assembler.
Reassembles split stack traces, exception blocks, and continuation lines into single unified records.
"""

import re
from typing import List, Generator, Optional, Iterable

# Common indicators of a new top-level log entry
ENTRY_HEADER_PATTERNS = [
    # ISO-like date at start: 2026-09-16...
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    # Syslog BSD date at start: Sep 16 17:15:00...
    re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    # Syslog Priority header: <134>...
    re.compile(r"^<\d{1,3}>"),
    # CEF / LEEF headers: CEF:0...
    re.compile(r"^(?:CEF:\d+|LEEF:\d+)"),
    # Bracketed timestamp: [2026-09-16 17:15:00] or [16/Sep/2026:...]
    re.compile(r"^\[(?:\d{4}-\d{2}-\d{2}|\d{1,2}/[A-Za-z]{3}/\d{4})"),
    # JSON start: {"...
    re.compile(r"^\{\s*\""),
    # Linux auditd: type=...
    re.compile(r"^type=[A-Z_]+"),
]

# Explicit continuation line indicators
CONTINUATION_PATTERNS = [
    re.compile(r"^\s+at\s+[a-zA-Z0-9_$./]+\("),           # Java stack trace: at org.example...
    re.compile(r"^\s+Caused by:\s+"),                     # Java Caused by:...
    re.compile(r"^\s+\.\.\.\s+\d+\s+more"),               # Java ... 32 more
    re.compile(r"^\s*Traceback \(most recent call last\):"), # Python traceback
    re.compile(r"^\s+File\s+\".*\",\s+line\s+\d+"),       # Python stack frame
    re.compile(r"^\s{2,}\S"),                             # Indented line with 2+ leading spaces
    re.compile(r"^\t\S"),                                 # Indented line with tab
]


class MultilineAssembler:
    """
    Stateful buffer that aggregates multiline log fragments into cohesive log records.
    """

    def __init__(self, max_buffer_bytes: int = 65536):
        self.max_buffer_bytes = max_buffer_bytes
        self.current_buffer: List[str] = []
        self.current_size = 0

    def is_new_entry_start(self, line: str) -> bool:
        """
        Determines if line marks the start of a distinct new log record.
        """
        stripped = line.strip()
        if not stripped:
            return False

        # First check explicit continuation patterns
        for pattern in CONTINUATION_PATTERNS:
            if pattern.search(line):
                return False

        # Check explicit new entry patterns
        for pattern in ENTRY_HEADER_PATTERNS:
            if pattern.search(stripped):
                return True

        # If it has leading indentation, it's likely a continuation
        if line.startswith(" ") or line.startswith("\t"):
            return False

        # Default heuristic: if not indented and has content, treat as new entry
        return True

    def feed_line(self, line: str) -> Optional[str]:
        """
        Feeds a single line. If this line starts a new entry, flushes and returns the completed entry.
        Otherwise buffers the line and returns None.
        """
        if not line:
            return None

        line_clean = line.rstrip("\r\n")

        if self.is_new_entry_start(line_clean):
            flushed_record = None
            if self.current_buffer:
                flushed_record = "\n".join(self.current_buffer)
            self.current_buffer = [line_clean]
            self.current_size = len(line_clean)
            return flushed_record
        else:
            # Append continuation line
            if not self.current_buffer:
                self.current_buffer = [line_clean]
                self.current_size = len(line_clean)
            else:
                if self.current_size + len(line_clean) < self.max_buffer_bytes:
                    self.current_buffer.append(line_clean)
                    self.current_size += len(line_clean) + 1
            return None

    def flush(self) -> Optional[str]:
        """
        Flushes and returns whatever remains in the buffer.
        """
        if not self.current_buffer:
            return None
        res = "\n".join(self.current_buffer)
        self.current_buffer = []
        self.current_size = 0
        return res

    def process_stream(self, lines: Iterable[str]) -> Generator[str, None, None]:
        """
        Consumes an iterable of lines and yields complete unified log strings.
        """
        for line in lines:
            completed = self.feed_line(line)
            if completed:
                yield completed
        remainder = self.flush()
        if remainder:
            yield remainder

