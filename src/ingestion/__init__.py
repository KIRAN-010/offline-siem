"""Ingestion module for loading log files."""

import logging
from pathlib import Path
from typing import Iterator, Literal

from src.parsers import ParserRegistry
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class LogIngestor:
    """Handles ingestion of log files from various sources."""

    def __init__(self, parser_registry: ParserRegistry | None = None):
        self.parser_registry = parser_registry or ParserRegistry()

    def ingest_content(
        self,
        content: str,
        format: str | None = None,
        filename: str | None = None,
    ) -> Iterator[NormalizedLog]:
        """Ingest log content directly.

        Args:
            content: Raw log content.
            format: Optional format override (json, syslog, text, csv).
            filename: Optional filename for format detection.

        Yields:
            Normalized log entries.
        """
        # Use specified format or auto-detect from filename
        if format:
            parser = self.parser_registry.get_parser(format)
            if parser is None:
                logger.error(f"Unknown format: {format}")
                return
        elif filename:
            # Create a dummy path for detection
            from pathlib import Path
            dummy_path = Path(filename)
            parser = self.parser_registry.get_parser_for_file(dummy_path)
        else:
            # Default to text parser
            parser = self.parser_registry.get_parser("text")

        if parser is None:
            logger.error("No suitable parser found")
            return

        # Parse content
        try:
            yield from parser.parse(content)
        except Exception as e:
            logger.error(f"Error parsing content: {e}")

    def ingest_file(
        self,
        file_path: str | Path,
        format: str | None = None,
    ) -> Iterator[NormalizedLog]:
        """Ingest a single log file.

        Args:
            file_path: Path to log file.
            format: Optional format override (json, syslog, text, csv).
                If not specified, auto-detected from extension.

        Yields:
            Normalized log entries.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return

        logger.info(f"Ingesting file: {file_path}")

        # Use specified format or auto-detect
        if format:
            parser = self.parser_registry.get_parser(format)
            if parser is None:
                logger.error(f"Unknown format: {format}")
                return
        else:
            parser = self.parser_registry.get_parser_for_file(file_path)
            if parser is None:
                logger.warning(f"No parser found for: {file_path}")
                return

        # Parse file
        try:
            yield from parser.parse_file(file_path)
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")

    def ingest_directory(
        self,
        directory: str | Path,
        pattern: str = "*.log*",
        recursive: bool = False,
    ) -> Iterator[NormalizedLog]:
        """Ingest all matching files in a directory.

        Args:
            directory: Directory path.
            pattern: Glob pattern for files to match.
            recursive: Whether to search recursively.

        Yields:
            Normalized log entries from all matching files.
        """
        directory = Path(directory)

        if not directory.is_dir():
            logger.error(f"Directory not found: {directory}")
            return

        # Find matching files
        if recursive:
            files = directory.rglob(pattern)
        else:
            files = directory.glob(pattern)

        # Ingest each file
        for file_path in sorted(files):
            if file_path.is_file():
                yield from self.ingest_file(file_path)

    def ingest_multiple(
        self,
        file_paths: list[str | Path],
    ) -> Iterator[NormalizedLog]:
        """Ingest multiple files.

        Args:
            file_paths: List of file paths.

        Yields:
            Normalized log entries from all files.
        """
        for file_path in file_paths:
            yield from self.ingest_file(file_path)