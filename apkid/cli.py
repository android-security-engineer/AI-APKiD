"""
 Copyright (C) 2026  RedNaga. https://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.
"""

import json
import sys
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from apkid import __version__
from apkid.apkid import Options, Scanner
from apkid.ai_output import AIOutputFormatter
from apkid.rules import RulesManager

app = typer.Typer(
    name="ai-apkid",
    help="AI-APKiD: Android APK/DEX/ELF identifier for AI agents.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console(stderr=True)


class TypingMethod(str, Enum):
    magic = "magic"
    filename = "filename"
    none = "none"


class OutputFormat(str, Enum):
    json = "json"
    text = "text"


def _make_scanner(
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


def _output_result(formatted: str, output: Optional[Path] = None):
    """Write result to file or stdout."""
    if output:
        output.write_text(formatted, encoding="utf-8")
    else:
        typer.echo(formatted)


def _error_exit(message: str, detail: str = "", code: int = 1):
    """Print structured error to stderr and exit."""
    error_payload = json.dumps(
        {"error": True, "message": message, "detail": detail},
        ensure_ascii=False,
    )
    typer.echo(error_payload, err=True)
    raise typer.Exit(code=code)


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, help="APK, DEX, or ELF file to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write result to file instead of stdout"),
    fmt: OutputFormat = typer.Option(OutputFormat.json, "--format", "-f", help="Output format"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="YARA scan timeout in seconds"),
    typing: TypingMethod = typer.Option(TypingMethod.magic, "--typing", help="File identification method: magic bytes, filename extension, or scan all"),
    scan_depth: int = typer.Option(2, "--scan-depth", help="Max recursion depth for nested ZIP archives"),
    entry_max_scan_size: int = typer.Option(0, "--entry-max-scan-size", help="Max ZIP entry size to scan in bytes (0 = no limit)"),
    include_types: bool = typer.Option(False, "--include-types", help="Include file_type detections in results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log debug messages to stderr"),
):
    """Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers."""
    try:
        scanner = _make_scanner(
            timeout=timeout,
            typing=typing.value,
            scan_depth=scan_depth,
            entry_max_scan_size=entry_max_scan_size,
            include_types=include_types,
        )
        results = scanner.scan_file(str(target))
        formatter = AIOutputFormatter()
        formatted = formatter.format(results, str(target), fmt=fmt.value, include_types=include_types)
        _output_result(formatted, output)
    except Exception as e:
        _error_exit(str(e), type(e).__name__)


@app.command()
def batch(
    directory: Path = typer.Argument(..., exists=True, help="Directory containing files to scan"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Scan subdirectories recursively"),
    pattern: str = typer.Option("*.apk", "--pattern", "-p", help="File glob pattern"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write result to file instead of stdout"),
    fmt: OutputFormat = typer.Option(OutputFormat.json, "--format", "-f", help="Output format"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="YARA scan timeout in seconds"),
    typing: TypingMethod = typer.Option(TypingMethod.magic, "--typing", help="File identification method"),
    scan_depth: int = typer.Option(2, "--scan-depth", help="Max recursion depth for nested ZIP archives"),
    entry_max_scan_size: int = typer.Option(0, "--entry-max-scan-size", help="Max ZIP entry size to scan in bytes (0 = no limit)"),
    include_types: bool = typer.Option(False, "--include-types", help="Include file_type detections in results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log debug messages to stderr"),
):
    """Batch scan files in a directory."""
    try:
        scanner = _make_scanner(
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
            result = json.dumps({
                "error": False,
                "scanned": 0,
                "results": [],
                "message": f"No files matching '{pattern}' found in {directory}",
            }, ensure_ascii=False)
            _output_result(result, output)
            return
        all_results = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Scanning {len(files)} files...", total=len(files))
            for f in files:
                results = scanner.scan_file(str(f))
                formatted = formatter.format_dict(results, str(f), include_types=include_types)
                all_results.append(formatted)
                progress.advance(task)
        batch_output = json.dumps({
            "error": False,
            "scanned": len(all_results),
            "results": all_results,
        }, ensure_ascii=False, indent=2)
        _output_result(batch_output, output)
    except Exception as e:
        _error_exit(str(e), type(e).__name__)


@app.command(name="list-tags")
def list_tags():
    """List all available detection tags and their descriptions."""
    from apkid.ai_output import RULE_DESCRIPTIONS
    tags = []
    for tag, desc in sorted(RULE_DESCRIPTIONS.items()):
        tags.append({"tag": tag, "description": desc})
    typer.echo(json.dumps({"tags": tags}, ensure_ascii=False, indent=2))


@app.command()
def info():
    """Show version, rules hash, and rules count."""
    rules_mgr = RulesManager()
    rules_hash = rules_mgr.hash
    try:
        rules = rules_mgr.load()
        rules_count = len(set(r.identifier for r in rules))
    except Exception:
        rules_count = 0
    result = {
        "version": __version__,
        "rules_sha256": rules_hash,
        "rules_count": rules_count,
    }
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))


@app.command()
def rules(
    action: str = typer.Argument(..., help="Action: 'list' to show rule files, 'compile' to rebuild rules.yarc"),
):
    """Manage YARA rules: list source files or compile to rules.yarc."""
    rules_mgr = RulesManager()
    if action == "list":
        yara_files = rules_mgr._collect_yara_files()
        rule_list = sorted(yara_files.keys())
        typer.echo(json.dumps({"rules": rule_list, "count": len(rule_list)}, ensure_ascii=False, indent=2))
    elif action == "compile":
        try:
            rules_mgr.compile()
            count = rules_mgr.save()
            typer.echo(json.dumps({"compiled": True, "rules_count": count}, ensure_ascii=False, indent=2))
        except Exception as e:
            _error_exit(f"Compilation failed: {e}", type(e).__name__)
    else:
        _error_exit(f"Unknown action '{action}'. Use 'list' or 'compile'.")


def ai_cli():
    """Entry point for ai-apkid command."""
    app()


if __name__ == "__main__":
    app()