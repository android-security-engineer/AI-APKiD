# MCP Server Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a standalone MCP (Model Context Protocol) server module to AI-APKiD, enabling AI agents to call scan/batch/diff/type/info/tags/rules tools directly via the MCP protocol, without mixing MCP code into existing modules.

**Architecture:** MCP client (Claude Code / any MCP host) → `apkid/mcp/server.py` (FastMCP instance) → `apkid/mcp/tools_*.py` (tool adapters) → `apkid.cli.common` (shared scanner factory) → `apkid.apkid.Scanner` + `apkid.ai_output.AIOutputFormatter` → YARA engine. MCP module is fully isolated: only imports from `apkid.cli.common` and `apkid.ai_output`, never the reverse.

**Tech Stack:** Python 3.8+, mcp>=1.0.0 (FastMCP), yara-python-dex>=1.0.1, typer>=0.12.0, rich>=13.0.0

**Scope:** Medium

**Risk:** Low

**Risks:**
- Task 1: `mcp` SDK is a new dependency → 缓解：放在 `extras_require['mcp']`，不影响核心安装
- Task 2: 工具适配器需与 AIOutputFormatter API 签名匹配 → 缓解：复用 `common.make_scanner()` 和 `AIOutputFormatter.format_dict()`
- Task 3: setup.py 修改影响包分发 → 缓解：`apkid-mcp` 作为可选入口点，mcp 依赖为 optional

**Autonomy Level:** Full

---

### Task 1: Create MCP Package Skeleton and Install Dependency

**Depends on:** None
**Files:**
- Create: `apkid/mcp/__init__.py`
- Modify: `setup.py:49-53`, `setup.py:100-104`, `setup.py:106-112`

- [ ] **Step 1: 创建 `apkid/mcp/__init__.py` — MCP 包入口，导出 server 和 run 函数**

```python
"""APKiD MCP Server — Model Context Protocol integration.

This module provides an MCP server that exposes APKiD's scanning
capabilities as tools callable by AI agents via the MCP protocol.

The MCP module is intentionally isolated from the rest of the codebase.
It only depends on `apkid.cli.common` and `apkid.ai_output` — never
the reverse.
"""

from apkid.mcp.server import mcp, run

__all__ = ["mcp", "run"]
```

- [ ] **Step 2: 修改 `setup.py` 以添加 MCP 可选依赖和入口点**

文件: `setup.py:100-104`（extras_require 区块）

```python
# 替换 setup.py:100-104 的 extras_require
extras_require={
    'dev': dev_requires,
    'test': test_requires,
    'mcp': [
        'mcp>=1.0.0',
    ],
},
```

文件: `setup.py:106-112`（entry_points 区块）

```python
# 替换 setup.py:106-112 的 entry_points
entry_points={
    'console_scripts': [
        'apkid=apkid.main:main',
        'apkid-ai-cli=apkid.cli:ai_cli',
        'apkid-mcp=apkid.mcp:run',
    ],
},
```

- [ ] **Step 3: 验证包结构和依赖配置**
Run: `python3 -c "import ast; ast.parse(open('setup.py').read()); print('setup.py syntax OK')" && python3 -c "import ast; ast.parse(open('apkid/mcp/__init__.py').read()); print('mcp __init__.py syntax OK')"`
Expected:
  - Exit code: 0
  - Output contains: "setup.py syntax OK"
  - Output contains: "mcp __init__.py syntax OK"

- [ ] **Step 4: 质量门禁检查**
Run: `grep -r "TODO\|FIXME\|TBD" apkid/mcp/ 2>/dev/null; echo "check done"`
Expected:
  - No TODO/FIXME/TBD in new files
  - Exit code: 0

- [ ] **Step 5: 提交**
Run: `git add apkid/mcp/__init__.py setup.py && git commit -m "feat(mcp): add MCP package skeleton and optional dependency"`

---

### Task 2: Create MCP Tool Adapters — Scan Operations

**Depends on:** Task 1
**Files:**
- Create: `apkid/mcp/tools_scan.py`

- [ ] **Step 1: 创建 `apkid/mcp/tools_scan.py` — scan / batch / diff / type 工具适配器**

```python
"""MCP tool adapters for scanning operations.

These adapters bridge MCP tool calls to APKiD's existing scanner
infrastructure. They use `common.make_scanner()` and
`AIOutputFormatter` — the same code path as the CLI commands.
"""

import json
from pathlib import Path
from typing import Optional

from apkid.ai_output import AIOutputFormatter
from apkid.cli.common import make_scanner
from apkid.apkid import Scanner, SCANNABLE_FILE_MAGICS


def scan_file(
    target: str,
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    include_types: bool = False,
) -> str:
    """Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers.

    Args:
        target: Path to the file to scan (APK, DEX, ELF, etc.)
        timeout: YARA scan timeout in seconds
        typing: File identification method: 'magic', 'filename', or 'none'
        scan_depth: Max recursion depth for nested ZIP archives
        include_types: Include file_type detections in results

    Returns:
        JSON string with scan results including findings and summary
    """
    if not Path(target).exists():
        return json.dumps({"error": True, "message": f"File not found: {target}"})
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
        return json.dumps(result_dict, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": True, "message": str(e), "detail": type(e).__name__})


def batch_scan(
    directory: str,
    recursive: bool = False,
    pattern: str = "*.apk",
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    include_types: bool = False,
) -> str:
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
        JSON string with batch scan results
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return json.dumps({"error": True, "message": f"Directory not found: {directory}"})
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
            return json.dumps({
                "error": False,
                "scanned": 0,
                "results": [],
                "message": f"No files matching '{pattern}' found in {directory}",
            })
        all_results = []
        for f in files:
            results = scanner.scan_file(str(f))
            result_dict = formatter.format_dict(results, str(f), include_types=include_types)
            all_results.append(result_dict)
        return json.dumps({
            "error": False,
            "scanned": len(all_results),
            "results": all_results,
        }, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": True, "message": str(e), "detail": type(e).__name__})


def diff_files(
    file1: str,
    file2: str,
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    include_types: bool = False,
) -> str:
    """Compare scan results between two files to find protection differences.

    Args:
        file1: Path to the first file to scan
        file2: Path to the second file to scan
        timeout: YARA scan timeout in seconds
        typing: File identification method: 'magic', 'filename', or 'none'
        scan_depth: Max recursion depth for nested ZIP archives
        include_types: Include file_type detections in results

    Returns:
        JSON string with diff results showing added/removed/common protections
    """
    for f, label in [(file1, "file1"), (file2, "file2")]:
        if not Path(f).exists():
            return json.dumps({"error": True, "message": f"{label} not found: {f}"})
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

        return json.dumps({
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
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": True, "message": str(e), "detail": type(e).__name__})


def type_file(target: str) -> str:
    """Identify the type of a file (APK/DEX/ELF/etc.) via magic bytes.

    Args:
        target: Path to the file to identify

    Returns:
        JSON string with file type information
    """
    if not Path(target).exists():
        return json.dumps({"error": True, "message": f"File not found: {target}"})
    try:
        with open(target, "rb") as f:
            detected = Scanner._type_file(f)
        if detected is None:
            return json.dumps({
                "error": False,
                "file": target,
                "type": None,
                "message": "Unknown file type — not a recognized Android binary format",
            })
        return json.dumps({
            "error": False,
            "file": target,
            "type": detected,
            "supported_types": sorted(SCANNABLE_FILE_MAGICS.keys()),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": True, "message": str(e), "detail": type(e).__name__})
```

- [ ] **Step 2: 验证 tools_scan.py 语法**
Run: `python3 -c "import ast; ast.parse(open('apkid/mcp/tools_scan.py').read()); print('tools_scan.py syntax OK')"`
Expected:
  - Exit code: 0
  - Output contains: "tools_scan.py syntax OK"

- [ ] **Step 3: 质量门禁检查**
Run: `grep -r "TODO\|FIXME\|TBD\|console\.log" apkid/mcp/tools_scan.py 2>/dev/null; echo "check done"`
Expected:
  - No TODO/FIXME/TBD/console.log
  - Exit code: 0

- [ ] **Step 4: 提交**
Run: `git add apkid/mcp/tools_scan.py && git commit -m "feat(mcp): add scan/batch/diff/type tool adapters"`

---

### Task 3: Create MCP Tool Adapters — Info Operations and MCP Server

**Depends on:** Task 2
**Files:**
- Create: `apkid/mcp/tools_info.py`
- Create: `apkid/mcp/server.py`

- [ ] **Step 1: 创建 `apkid/mcp/tools_info.py` — info / list_tags / rules / skills 工具适配器**

```python
"""MCP tool adapters for information and metadata operations.

These adapters expose APKiD's metadata capabilities (version info,
tag descriptions, rule management, skill discovery) as MCP tools.
"""

import json

from apkid import __version__
from apkid.ai_output import RULE_DESCRIPTIONS
from apkid.rules import RulesManager


def info() -> str:
    """Show APKiD version, rules hash, and rules count.

    Returns:
        JSON string with version and rules metadata
    """
    try:
        rules_mgr = RulesManager()
        rules_hash = rules_mgr.hash
        try:
            rules = rules_mgr.load()
            rules_count = len(set(r.identifier for r in rules))
        except Exception:
            rules_count = 0
        return json.dumps({
            "error": False,
            "version": __version__,
            "rules_sha256": rules_hash,
            "rules_count": rules_count,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": True, "message": str(e), "detail": type(e).__name__})


def list_tags() -> str:
    """List all available detection tags and their descriptions.

    Returns:
        JSON string with tag list and descriptions
    """
    tags = [{"tag": tag, "description": desc} for tag, desc in sorted(RULE_DESCRIPTIONS.items())]
    return json.dumps({"error": False, "tags": tags}, ensure_ascii=False, indent=2)


def rules(action: str = "list") -> str:
    """Manage YARA rules: list source files or compile to rules.yarc.

    Args:
        action: 'list' to show rule files, 'compile' to rebuild rules.yarc

    Returns:
        JSON string with rule management results
    """
    try:
        rules_mgr = RulesManager()
        if action == "list":
            yara_files = rules_mgr._collect_yara_files()
            rule_list = sorted(yara_files.keys())
            return json.dumps({
                "error": False,
                "rules": rule_list,
                "count": len(rule_list),
            }, ensure_ascii=False, indent=2)
        elif action == "compile":
            rules_mgr.compile()
            count = rules_mgr.save()
            return json.dumps({
                "error": False,
                "compiled": True,
                "rules_count": count,
            }, ensure_ascii=False, indent=2)
        else:
            return json.dumps({
                "error": True,
                "message": f"Unknown action '{action}'. Use 'list' or 'compile'.",
            })
    except Exception as e:
        return json.dumps({"error": True, "message": str(e), "detail": type(e).__name__})


def skills() -> str:
    """List all available MCP tools and their descriptions.

    Returns:
        JSON string with skill/tool list for self-discovery
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
    return json.dumps({
        "error": False,
        "tools": sorted(tool_list, key=lambda s: s["name"]),
        "total": len(tool_list),
    }, ensure_ascii=False, indent=2)
```

- [ ] **Step 2: 创建 `apkid/mcp/server.py` — MCP Server 定义，注册所有工具**

```python
"""APKiD MCP Server — FastMCP server definition and tool registration.

This is the single entry point for the MCP server. It creates a
FastMCP instance, registers all tool functions, and provides the
`run()` entry point for the `apkid-mcp` console script.

Design: The server imports tool adapter functions from tools_*.py
modules and registers them with FastMCP. Each tool function returns
a JSON string — FastMCP wraps this into the MCP protocol response.
"""

from mcp.server.fastmcp import FastMCP

from apkid.mcp.tools_scan import scan_file, batch_scan, diff_files, type_file
from apkid.mcp.tools_info import info, list_tags, rules, skills

MCP_SERVER_NAME = "apkid"
MCP_SERVER_VERSION = "3.1.0"

mcp = FastMCP(MCP_SERVER_NAME)

# --- Register scanning tools ---

mcp.tool()(scan_file)
mcp.tool()(batch_scan)
mcp.tool()(diff_files)
mcp.tool()(type_file)

# --- Register info tools ---

mcp.tool()(info)
mcp.tool(name="list-tags")(list_tags)
mcp.tool()(rules)
mcp.tool()(skills)


def run():
    """Entry point for the apkid-mcp console script."""
    mcp.run()
```

- [ ] **Step 3: 验证 server.py 和 tools_info.py 语法**
Run: `python3 -c "import ast; ast.parse(open('apkid/mcp/server.py').read()); print('server.py OK')" && python3 -c "import ast; ast.parse(open('apkid/mcp/tools_info.py').read()); print('tools_info.py OK')"`
Expected:
  - Exit code: 0
  - Output contains: "server.py OK"
  - Output contains: "tools_info.py OK"

- [ ] **Step 4: 质量门禁检查**
Run: `grep -r "TODO\|FIXME\|TBD" apkid/mcp/ 2>/dev/null; echo "check done"`
Expected:
  - No TODO/FIXME/TBD in any MCP files
  - Exit code: 0

- [ ] **Step 5: 提交**
Run: `git add apkid/mcp/tools_info.py apkid/mcp/server.py && git commit -m "feat(mcp): add info tools, server definition, and tool registration"`

---

### Task 4: Create MCP Server Tests

**Depends on:** Task 3
**Files:**
- Create: `tests/test_mcp_server.py`

- [ ] **Step 1: 创建 `tests/test_mcp_server.py` — MCP Server 单元测试**

```python
"""Tests for the APKiD MCP Server module."""

import json
import pytest
from unittest.mock import patch, MagicMock

from apkid.mcp.tools_info import info, list_tags, rules, skills
from apkid.mcp.tools_scan import type_file, scan_file, batch_scan, diff_files


class TestInfoTools:
    """Test info-type MCP tools that don't require file scanning."""

    def test_list_tags_returns_json_with_tags(self):
        result = list_tags()
        data = json.loads(result)
        assert data["error"] is False
        assert "tags" in data
        assert len(data["tags"]) > 0
        tag_names = [t["tag"] for t in data["tags"]]
        assert "anti_vm" in tag_names
        assert "packer" in tag_names

    def test_list_tags_each_has_description(self):
        result = list_tags()
        data = json.loads(result)
        for tag_entry in data["tags"]:
            assert "tag" in tag_entry
            assert "description" in tag_entry
            assert len(tag_entry["description"]) > 0

    def test_skills_returns_tool_list(self):
        result = skills()
        data = json.loads(result)
        assert data["error"] is False
        assert "tools" in data
        assert data["total"] > 0
        tool_names = [t["name"] for t in data["tools"]]
        assert "scan_file" in tool_names
        assert "batch_scan" in tool_names
        assert "diff_files" in tool_names
        assert "type_file" in tool_names

    def test_rules_list_action(self):
        with patch("apkid.mcp.tools_info.RulesManager") as MockRM:
            mock_mgr = MagicMock()
            mock_mgr._collect_yara_files.return_value = {
                "dex/packers.yara": "path1",
                "elf/obfuscators.yara": "path2",
            }
            MockRM.return_value = mock_mgr
            result = rules("list")
            data = json.loads(result)
            assert data["error"] is False
            assert data["count"] == 2

    def test_rules_invalid_action_returns_error(self):
        result = rules("invalid")
        data = json.loads(result)
        assert data["error"] is True
        assert "Unknown action" in data["message"]


class TestScanTools:
    """Test scan-type MCP tools with file system mocking."""

    def test_scan_file_not_found(self):
        result = scan_file("/nonexistent/path.apk")
        data = json.loads(result)
        assert data["error"] is True
        assert "not found" in data["message"].lower() or "File not found" in data["message"]

    def test_batch_scan_directory_not_found(self):
        result = batch_scan("/nonexistent/dir")
        data = json.loads(result)
        assert data["error"] is True

    def test_diff_files_missing_file1(self):
        result = diff_files("/nonexistent1.apk", "/nonexistent2.apk")
        data = json.loads(result)
        assert data["error"] is True

    def test_type_file_not_found(self):
        result = type_file("/nonexistent/file.apk")
        data = json.loads(result)
        assert data["error"] is True
        assert "not found" in data["message"].lower() or "File not found" in data["message"]

    def test_type_file_unknown_format(self, tmp_path):
        unknown_file = tmp_path / "unknown.bin"
        unknown_file.write_bytes(b"\x00\x00\x00\x00")
        result = type_file(str(unknown_file))
        data = json.loads(result)
        assert data["error"] is False
        assert data["type"] is None

    def test_type_file_dex_format(self, tmp_path):
        dex_file = tmp_path / "test.dex"
        dex_file.write_bytes(b"dex\n\x00\x00\x00")
        result = type_file(str(dex_file))
        data = json.loads(result)
        assert data["error"] is False
        assert data["type"] == "dex"
```

- [ ] **Step 2: 验证测试文件语法**
Run: `python3 -c "import ast; ast.parse(open('tests/test_mcp_server.py').read()); print('test_mcp_server.py syntax OK')"`
Expected:
  - Exit code: 0
  - Output contains: "test_mcp_server.py syntax OK"

- [ ] **Step 3: 质量门禁检查**
Run: `grep -r "TODO\|FIXME\|TBD" tests/test_mcp_server.py 2>/dev/null; echo "check done"`
Expected:
  - No TODO/FIXME/TBD
  - Exit code: 0

- [ ] **Step 4: 提交**
Run: `git add tests/test_mcp_server.py && git commit -m "test(mcp): add MCP server unit tests for info and scan tools"`
