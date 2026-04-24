"""Base parser interface."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from src.schema import NormalizedLog


class BaseParser(ABC):
    """Abstract base class for log parsers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser identifier."""
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File extensions this parser supports."""
        ...

    @abstractmethod
    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse log content into normalized entries.

        Args:
            content: Raw log content to parse.

        Yields:
            Normalized log entries.
        """
        ...

    def parse_file(self, file_path: Path) -> Iterator[NormalizedLog]:
        """Parse a log file.

        Args:
            file_path: Path to log file.

        Yields:
            Normalized log entries.
        """
        content = file_path.read_text(encoding="utf-8")
        yield from self.parse(content)

    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file."""
        return file_path.suffix.lower() in self.supported_extensions