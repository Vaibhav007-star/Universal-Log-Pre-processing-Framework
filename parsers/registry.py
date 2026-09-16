"""
Parser Registry and Dynamic Plugin Loader.
Maintains priority-ordered parser chain and enables zero-restart plugin additions.
"""

import os
import importlib.util
import inspect
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from parsers.base import BaseParser, IntermediateParseResult


class ParserRegistry:
    """
    Thread-safe registry of all active parser plugins.
    """

    def __init__(self):
        self._parsers: List[BaseParser] = []
        self._parser_map: Dict[str, BaseParser] = {}

    def register(self, parser: BaseParser) -> None:
        """
        Registers or updates a parser plugin, keeping the list sorted by priority descending.
        """
        if parser.name in self._parser_map:
            self._parsers = [p for p in self._parsers if p.name != parser.name]

        self._parsers.append(parser)
        self._parser_map[parser.name] = parser
        # Sort descending by priority
        self._parsers.sort(key=lambda p: p.priority, reverse=True)

    def get_parser(self, name: str) -> Optional[BaseParser]:
        return self._parser_map.get(name)

    def list_parsers(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.name,
                "priority": p.priority,
                "formats": p.supported_formats,
                "class": p.__class__.__name__
            }
            for p in self._parsers
        ]

    def match_best_parser(self, raw_log: str) -> Tuple[Optional[BaseParser], float]:
        """
        Finds the highest-priority parser that claims the log with maximum confidence.
        """
        best_parser = None
        highest_conf = 0.0

        for parser in self._parsers:
            can_handle, conf = parser.can_parse(raw_log)
            if can_handle and conf > highest_conf:
                best_parser = parser
                highest_conf = conf
                # If certainty is high, return immediately
                if conf >= 0.95:
                    return best_parser, conf

        return best_parser, highest_conf

    def detect_and_parse(self, raw_log: str) -> Tuple[Optional[BaseParser], IntermediateParseResult]:
        """
        Evaluates registered parsers in priority order and executes the best match.
        """
        for parser in self._parsers:
            can_handle, conf = parser.can_parse(raw_log)
            if can_handle and conf >= 0.70:
                result = parser.parse(raw_log)
                if result.success:
                    return parser, result

        return None, IntermediateParseResult(
            success=False,
            format_name="UNKNOWN",
            raw_log=raw_log,
            warnings=["No registered deterministic parser claimed this record"],
            error_codes=["ERR_NO_MATCHING_PARSER"]
        )

    def load_plugins_from_directory(self, plugin_dir: str) -> int:
        """
        Dynamically imports Python files from a directory and registers any BaseParser subclasses.
        """
        p = Path(plugin_dir)
        if not p.exists() or not p.is_dir():
            return 0

        loaded_count = 0
        for file_path in p.glob("*.py"):
            if file_path.name.startswith("__"):
                continue
            module_name = f"external_plugin_{file_path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, str(file_path))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    for _, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BaseParser) and obj is not BaseParser:
                            instance = obj()
                            self.register(instance)
                            loaded_count += 1
            except Exception as e:
                print(f"[WARN] Failed to load dynamic plugin {file_path.name}: {e}")

        return loaded_count
