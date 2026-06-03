"""apkid-ai-cli diff — Compare scan results between two files."""

import json
from pathlib import Path
from typing import Optional

import typer

from apkid.ai_output import AIOutputFormatter
from apkid.cli.common import (
    TypingMethod,
    make_scanner,
    output_result,
    error_exit,
)


def diff(
    file1: Path = typer.Argument(..., exists=True, help="First file to scan"),
    file2: Path = typer.Argument(..., exists=True, help="Second file to scan"),
    output_path: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write result to file instead of stdout"
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
    include_types: bool = typer.Option(
        False, "--include-types", help="Include file_type detections in results"
    ),
):
    """Compare scan results between two files to find protection differences."""
    try:
        scanner = make_scanner(
            timeout=timeout,
            typing=typing.value,
            scan_depth=scan_depth,
            entry_max_scan_size=0,
            include_types=include_types,
        )
        formatter = AIOutputFormatter()
        results1 = scanner.scan_file(str(file1))
        dict1 = formatter.format_dict(
            results1, str(file1), include_types=include_types
        )
        results2 = scanner.scan_file(str(file2))
        dict2 = formatter.format_dict(
            results2, str(file2), include_types=include_types
        )

        tags1 = {f["tag"] for f in dict1.get("findings", [])}
        tags2 = {f["tag"] for f in dict2.get("findings", [])}

        added_tags = sorted(tags2 - tags1)
        removed_tags = sorted(tags1 - tags2)
        common_tags = sorted(tags1 & tags2)

        findings_added = [
            f for f in dict2.get("findings", []) if f["tag"] in added_tags
        ]
        findings_removed = [
            f for f in dict1.get("findings", []) if f["tag"] in removed_tags
        ]

        diff_result = {
            "error": False,
            "file1": str(file1),
            "file2": str(file2),
            "added": findings_added,
            "removed": findings_removed,
            "common_count": len(common_tags),
            "summary": {
                "total_added": len(added_tags),
                "total_removed": len(removed_tags),
                "total_common": len(common_tags),
            },
        }
        formatted = json.dumps(diff_result, ensure_ascii=False, indent=2)
        output_result(formatted, output_path)
    except Exception as e:
        error_exit(str(e), type(e).__name__)