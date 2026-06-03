"""Shared types and utilities for the APKiD AI-CLI."""

import json
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from apkid.apkid import Options, Scanner
from apkid.rules import RulesManager


class TypingMethod(str, Enum):
    magic = "magic"
    filename = "filename"
    none = "none"


class OutputFormat(str, Enum):
    json = "json"
    text = "text"


def make_scanner(
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    entry_max_scan_size: int = 0,
    include_types: bool = False,
) -> Scanner:
    """Create a Scanner with the given options."""
    rules_mgr = RulesManager()
    rules = rules_mgr.load()
    options = Options(
        timeout=timeout,
        json=True,
        typing=typing,
        scan_depth=scan_depth,
        entry_max_scan_size=entry_max_scan_size,
        include_types=include_types,
    )
    return Scanner(rules=rules, options=options)


def output_result(formatted: str, output: Optional[Path] = None):
    """Write result to file or stdout."""
    if output:
        output.write_text(formatted, encoding="utf-8")
    else:
        typer.echo(formatted)


def error_exit(message: str, detail: str = "", code: int = 1):
    """Print structured error to stderr and exit."""
    error_payload = json.dumps(
        {"error": True, "message": message, "detail": detail},
        ensure_ascii=False,
    )
    typer.echo(error_payload, err=True)
    raise typer.Exit(code=code)