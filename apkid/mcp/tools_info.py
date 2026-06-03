"""MCP tool adapters for information and metadata operations.

These adapters expose APKiD's metadata capabilities (version info,
tag descriptions, rule management, skill discovery) as MCP tools.

All functions return Python dicts, not JSON strings. The FastMCP
framework handles serialization to the MCP protocol automatically.
"""

from typing import Any, Dict

from apkid import __version__
from apkid.ai_output import RULE_DESCRIPTIONS
from apkid.rules import RulesManager


def info() -> Dict[str, Any]:
    """Show APKiD version, rules hash, and rules count.

    Returns:
        Dict with version and rules metadata
    """
    try:
        rules_mgr = RulesManager()
        rules_hash = rules_mgr.hash
        try:
            rules = rules_mgr.load()
            rules_count = len(set(r.identifier for r in rules))
        except Exception:
            rules_count = 0
        return {
            "error": False,
            "version": __version__,
            "rules_sha256": rules_hash,
            "rules_count": rules_count,
        }
    except Exception as e:
        return {"error": True, "message": str(e), "detail": type(e).__name__}


def list_tags() -> Dict[str, Any]:
    """List all available detection tags and their descriptions.

    Returns:
        Dict with tag list and descriptions
    """
    tags = [{"tag": tag, "description": desc} for tag, desc in sorted(RULE_DESCRIPTIONS.items())]
    return {"error": False, "tags": tags}


def rules(action: str = "list") -> Dict[str, Any]:
    """Manage YARA rules: list source files or compile to rules.yarc.

    Args:
        action: 'list' to show rule files, 'compile' to rebuild rules.yarc

    Returns:
        Dict with rule management results
    """
    try:
        rules_mgr = RulesManager()
        if action == "list":
            yara_files = rules_mgr._collect_yara_files()
            rule_list = sorted(yara_files.keys())
            return {
                "error": False,
                "rules": rule_list,
                "count": len(rule_list),
            }
        elif action == "compile":
            rules_mgr.compile()
            count = rules_mgr.save()
            return {
                "error": False,
                "compiled": True,
                "rules_count": count,
            }
        else:
            return {
                "error": True,
                "message": f"Unknown action '{action}'. Use 'list' or 'compile'.",
            }
    except Exception as e:
        return {"error": True, "message": str(e), "detail": type(e).__name__}


def skills() -> Dict[str, Any]:
    """List all available MCP tools and their descriptions.

    Returns:
        Dict with skill/tool list for self-discovery
    """
    tool_list = [
        {"name": "scan_file", "description": "Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers"},
        {"name": "batch_scan", "description": "Batch scan files in a directory"},
        {"name": "diff_files", "description": "Compare scan results between two files"},
        {"name": "type_file", "description": "Identify file type via magic bytes"},
        {"name": "info", "description": "Show APKiD version and rules info"},
        {"name": "list_tags", "description": "List all detection tags and descriptions"},
        {"name": "rules", "description": "Manage YARA rules (list or compile)"},
        {"name": "skills", "description": "List all available MCP tools"},
    ]
    return {
        "error": False,
        "tools": sorted(tool_list, key=lambda s: s["name"]),
        "total": len(tool_list),
    }