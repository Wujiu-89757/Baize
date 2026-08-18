"""解析器工厂。"""
from __future__ import annotations

from app.analysis.parsing.base import BaseParser, probe_format
from app.analysis.parsing.scapy_parser import ScapyParser

_PARSERS = {"scapy": ScapyParser}


def get_parser(name: str = "scapy") -> BaseParser:
    try:
        return _PARSERS[name]()
    except KeyError as exc:
        raise ValueError(f"未知解析器: {name}") from exc


__all__ = ["BaseParser", "ScapyParser", "get_parser", "probe_format"]
