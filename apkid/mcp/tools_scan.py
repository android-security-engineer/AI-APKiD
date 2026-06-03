"""MCP tool adapters for scanning operations.

These adapters bridge MCP tool calls to APKiD's existing scanner
infrastructure. They use `common.make_scanner()` and
`AIOutputFormatter` — the same code path as the CLI commands.

All functions return Python dicts, not JSON strings. The FastMCP
framework handles serialization to the MCP protocol automatically.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from apkid.ai_output import AIOutputFormatter
from apkid.cli.common import make_scanner
from apkid.apkid import Scanner, SCANNABLE_FILE_MAGICS


def scan_file(
    target: str,
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    include_types: bool = False,
) -> Dict[str, Any]:
    """Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers.

    Args:
        target: Path to the file to scan (APK, DEX, ELF, etc.)
        timeout: YARA scan timeout in seconds
        typing: File identification method: 'magic', 'filename', or 'none'
        scan_depth: Max recursion depth for nested ZIP archives
        include_types: Include file_type detections in results

    Returns:
        Dict with scan results including findings and summary
    """
    if not Path(target).exists():
        return {"error": True, "message": f"File not found: {target}"}
    try:
        scanner = make_scanner(
            timeout=timeout,
            typing=typing,
            scan_depth=scan_depth,
            entry_max_scan_size=0,
            include_types=include_types,
        )
        results = scanner.scan_file(target)
        formatter = AIOutputFormatter()
        result_dict = formatter.format_dict(results, target, include_types=include_types)
        return result_dict
    except Exception as e:
        return {"error": True, "message": str(e), "detail": type(e).__name__}


def batch_scan(
    directory: str,
    recursive: bool = False,
    pattern: str = "*.apk",
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    include_types: bool = False,
) -> Dict[str, Any]:
    """Batch scan files in a directory for packer/signer/compiler/protector identifiers.

    Args:
        directory: Path to directory containing files to scan
        recursive: Scan subdirectories recursively
        pattern: File glob pattern (e.g. '*.apk', '*.dex')
        timeout: YARA scan timeout in seconds
        typing: File identification method: 'magic', 'filename', or 'none'
        scan_depth: Max recursion depth for nested ZIP archives
        include_types: Include file_type detections in results

    Returns:
        Dict with batch scan results
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return {"error": True, "message": f"Directory not found: {directory}"}
    try:
        scanner = make_scanner(
            timeout=timeout,
            typing=typing,
            scan_depth=scan_depth,
            entry_max_scan_size=0,
            include_types=include_types,
        )
        formatter = AIOutputFormatter()
        if recursive:
            files = sorted(dir_path.rglob(pattern))
        else:
            files = sorted(dir_path.glob(pattern))
        if not files:
            return {
                "error": False,
                "scanned": 0,
                "results": [],
                "message": f"No files matching '{pattern}' found in {directory}",
            }
        all_results = []
        for f in files:
            results = scanner.scan_file(str(f))
            result_dict = formatter.format_dict(results, str(f), include_types=include_types)
            all_results.append(result_dict)
        return {
            "error": False,
            "scanned": len(all_results),
            "results": all_results,
        }
    except Exception as e:
        return {"error": True, "message": str(e), "detail": type(e).__name__}


def diff_files(
    file1: str,
    file2: str,
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    include_types: bool = False,
) -> Dict[str, Any]:
    """Compare scan results between two files to find protection differences.

    Args:
        file1: Path to the first file to scan
        file2: Path to the second file to scan
        timeout: YARA scan timeout in seconds
        typing: File identification method: 'magic', 'filename', or 'none'
        scan_depth: Max recursion depth for nested ZIP archives
        include_types: Include file_type detections in results

    Returns:
        Dict with diff results showing added/removed/common protections
    """
    for f, label in [(file1, "file1"), (file2, "file2")]:
        if not Path(f).exists():
            return {"error": True, "message": f"{label} not found: {f}"}
    try:
        scanner = make_scanner(
            timeout=timeout,
            typing=typing,
            scan_depth=scan_depth,
            entry_max_scan_size=0,
            include_types=include_types,
        )
        formatter = AIOutputFormatter()
        results1 = scanner.scan_file(file1)
        dict1 = formatter.format_dict(results1, file1, include_types=include_types)
        results2 = scanner.scan_file(file2)
        dict2 = formatter.format_dict(results2, file2, include_types=include_types)

        tags1 = {f["tag"] for f in dict1.get("findings", [])}
        tags2 = {f["tag"] for f in dict2.get("findings", [])}
        added_tags = sorted(tags2 - tags1)
        removed_tags = sorted(tags1 - tags2)
        common_tags = sorted(tags1 & tags2)
        findings_added = [f for f in dict2.get("findings", []) if f["tag"] in added_tags]
        findings_removed = [f for f in dict1.get("findings", []) if f["tag"] in removed_tags]

        return {
            "error": False,
            "file1": file1,
            "file2": file2,
            "added": findings_added,
            "removed": findings_removed,
            "common_count": len(common_tags),
            "summary": {
                "total_added": len(added_tags),
                "total_removed": len(removed_tags),
                "total_common": len(common_tags),
            },
        }
    except Exception as e:
        return {"error": True, "message": str(e), "detail": type(e).__name__}


def type_file(target: str) -> Dict[str, Any]:
    """Identify the type of a file (APK/DEX/ELF/etc.) via magic bytes.

    Args:
        target: Path to the file to identify

    Returns:
        Dict with file type information
    """
    if not Path(target).exists():
        return {"error": True, "message": f"File not found: {target}"}
    try:
        with open(target, "rb") as f:
            detected = Scanner._type_file(f)
        if detected is None:
            return {
                "error": False,
                "file": target,
                "type": None,
                "message": "Unknown file type — not a recognized Android binary format",
            }
        return {
            "error": False,
            "file": target,
            "type": detected,
            "supported_types": sorted(SCANNABLE_FILE_MAGICS.keys()),
        }
    except Exception as e:
        return {"error": True, "message": str(e), "detail": type(e).__name__}