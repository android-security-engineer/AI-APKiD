"""apkid-ai-cli scan — Scan a single file."""

from pathlib import Path
from typing import Optional

import typer

from apkid.ai_output import AIOutputFormatter
from apkid.cli.common import (
    TypingMethod,
    OutputFormat,
    make_scanner,
    output_result,
    error_exit,
)


def scan(
    target: Path = typer.Argument(
        ..., exists=True, help="APK, DEX, or ELF file to scan"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write result to file instead of stdout"
    ),
    fmt: OutputFormat = typer.Option(
        OutputFormat.json, "--format", "-f", help="Output format"
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="YARA scan timeout in seconds"
    ),
    typing: TypingMethod = typer.Option(
        TypingMethod.magic,
        "--typing",
        help="File identification method: magic bytes, filename extension, or scan all",
    ),
    scan_depth: int = typer.Option(
        2, "--scan-depth", help="Max recursion depth for nested ZIP archives"
    ),
    entry_max_scan_size: int = typer.Option(
        0, "--entry-max-scan-size", help="Max ZIP entry size to scan in bytes (0 = no limit)"
    ),
    include_types: bool = typer.Option(
        False, "--include-types", help="Include file_type detections in results"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Log debug messages to stderr"
    ),
):
    """Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers."""
    try:
        scanner = make_scanner(
            timeout=timeout,
            typing=typing.value,
            scan_depth=scan_depth,
            entry_max_scan_size=entry_max_scan_size,
            include_types=include_types,
        )
        results = scanner.scan_file(str(target))
        formatter = AIOutputFormatter()
        formatted = formatter.format(
            results, str(target), fmt=fmt.value, include_types=include_types
        )
        output_result(formatted, output)
    except Exception as e:
        error_exit(str(e), type(e).__name__)