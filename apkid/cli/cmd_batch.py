"""apkid-ai-cli batch — Batch scan files in a directory."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from apkid.ai_output import AIOutputFormatter
from apkid.cli.common import (
    TypingMethod,
    OutputFormat,
    make_scanner,
    output_result,
    error_exit,
)
from apkid.cli.app import console as _console


def batch(
    directory: Path = typer.Argument(
        ..., exists=True, help="Directory containing files to scan"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Scan subdirectories recursively"
    ),
    pattern: str = typer.Option(
        "*.apk", "--pattern", "-p", help="File glob pattern"
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
        TypingMethod.magic, "--typing", help="File identification method"
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
    """Batch scan files in a directory."""
    try:
        scanner = make_scanner(
            timeout=timeout,
            typing=typing.value,
            scan_depth=scan_depth,
            entry_max_scan_size=entry_max_scan_size,
            include_types=include_types,
        )
        formatter = AIOutputFormatter()
        target_path = Path(directory)
        if recursive:
            files = sorted(target_path.rglob(pattern))
        else:
            files = sorted(target_path.glob(pattern))
        if not files:
            result = json.dumps(
                {
                    "error": False,
                    "scanned": 0,
                    "results": [],
                    "message": f"No files matching '{pattern}' found in {directory}",
                },
                ensure_ascii=False,
            )
            output_result(result, output)
            return
        all_results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=_console,
        ) as progress:
            task = progress.add_task(
                f"Scanning {len(files)} files...", total=len(files)
            )
            for f in files:
                results = scanner.scan_file(str(f))
                formatted = formatter.format_dict(
                    results, str(f), include_types=include_types
                )
                all_results.append(formatted)
                progress.advance(task)
        batch_output = json.dumps(
            {
                "error": False,
                "scanned": len(all_results),
                "results": all_results,
            },
            ensure_ascii=False,
            indent=2,
        )
        output_result(batch_output, output)
    except Exception as e:
        error_exit(str(e), type(e).__name__)