"""
Abstract Base Classes and Data Transfer Objects for the Parser Plugin System.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple


@dataclass
class IntermediateParseResult:
    """
    Standardized payload produced by any parser plugin before canonical normalization.
    """
    success: bool
    format_name: str
    extracted_fields: Dict[str, Any] = field(default_factory=dict)
    timestamp_raw: Optional[str] = None
    raw_log: str = ""
    warnings: List[str] = field(default_factory=list)
    error_codes: List[str] = field(default_factory=list)
    is_exact_syntax: bool = True
    parser_name: str = "UNKNOWN"


class BaseParser(ABC):
    """
    Abstract interface that all deterministic and dynamic log parsers must implement.
    """
    name: str = "base_parser"
    priority: int = 50  # 1-100 (100 is highest priority)
    supported_formats: List[str] = []

    @abstractmethod
    def can_parse(self, raw_log: str) -> Tuple[bool, float]:
        """
        Syntactic inspection without full parsing.
        Returns (can_parse: bool, confidence: float [0.0 - 1.0]).
        """
        pass

    @abstractmethod
    def parse(self, raw_log: str) -> IntermediateParseResult:
        """
        Executes parsing and field extraction.
        Never throws unhandled exceptions; populates error_codes and partial fields on failure.
        """
        pass

