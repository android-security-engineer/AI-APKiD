"""Tests for the APKiD MCP server module.

These tests verify the FastMCP server can be instantiated and that
tool adapter functions return valid JSON strings with expected keys.
"""

import json
import tempfile
import os

import pytest

from apkid.mcp.server import mcp, MCP_SERVER_NAME


# ---------------------------------------------------------------------------
# Server instantiation
# ---------------------------------------------------------------------------

class TestMCPServerInstantiation:
    """Verify the FastMCP server object can be created and configured."""

    def test_server_name(self):
        assert MCP_SERVER_NAME == "apkid"

    def test_mcp_object_exists(self):
        assert mcp is not None

    def test_mcp_has_instructions(self):
        assert mcp.instructions is not None
        assert "APKiD" in mcp.instructions

    def test_mcp_tools_registered(self):
        """All 8 tools are registered with FastMCP."""
        tools = mcp._tool_manager._tools
        expected = {"scan_file", "batch_scan", "diff_files", "type_file",
                     "info", "list-tags", "rules", "skills"}
        actual = set(tools.keys())
        assert expected == actual, f"Missing tools: {expected - actual}, Extra: {actual - expected}"


# ---------------------------------------------------------------------------
# Tool adapter return values (JSON strings)
# ---------------------------------------------------------------------------

class TestMCPToolReturns:
    """Verify tool adapters return valid JSON with expected structure."""

    def test_info_returns_valid_json(self):
        from apkid.mcp.tools_info import info
        result = info()
        data = json.loads(result)
        assert "error" in data
        assert "version" in data

    def test_list_tags_returns_valid_json(self):
        from apkid.mcp.tools_info import list_tags
        result = list_tags()
        data = json.loads(result)
        assert "error" in data
        assert "tags" in data
        assert isinstance(data["tags"], list)

    def test_skills_returns_valid_json(self):
        from apkid.mcp.tools_info import skills
        result = skills()
        data = json.loads(result)
        assert "error" in data
        assert "tools" in data
        assert data["total"] == 8

    def test_rules_list_returns_valid_json(self):
        from apkid.mcp.tools_info import rules
        result = rules("list")
        data = json.loads(result)
        assert "error" in data
        assert "rules" in data

    def test_scan_file_missing_returns_error_json(self):
        from apkid.mcp.tools_scan import scan_file
        result = scan_file("/nonexistent/file.apk")
        data = json.loads(result)
        assert data["error"] is True
        assert "not found" in data["message"].lower() or "File not found" in data["message"]

    def test_type_file_missing_returns_error_json(self):
        from apkid.mcp.tools_scan import type_file
        result = type_file("/nonexistent/file.apk")
        data = json.loads(result)
        assert data["error"] is True

    def test_diff_files_missing_returns_error_json(self):
        from apkid.mcp.tools_scan import diff_files
        result = diff_files("/nonexistent/a.apk", "/nonexistent/b.apk")
        data = json.loads(result)
        assert data["error"] is True

    def test_batch_scan_missing_dir_returns_error_json(self):
        from apkid.mcp.tools_scan import batch_scan
        result = batch_scan("/nonexistent/dir")
        data = json.loads(result)
        assert data["error"] is True

    def test_scan_file_with_dex_returns_json(self):
        """Scan a minimal DEX file — returns valid JSON with findings."""
        from apkid.mcp.tools_scan import scan_file
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
            f.write(b"dex\n035\x00" + b"\x00" * 92)
            tmp = f.name
        try:
            result = scan_file(tmp)
            data = json.loads(result)
            assert "error" in data
            # Even if scan fails (no rules), the JSON structure must be valid
            if not data["error"]:
                assert "findings" in data
        finally:
            os.unlink(tmp)

    def test_type_file_with_dex_returns_json(self):
        """Type a minimal DEX file — returns valid JSON with type info."""
        from apkid.mcp.tools_scan import type_file
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
            f.write(b"dex\n035\x00" + b"\x00" * 92)
            tmp = f.name
        try:
            result = type_file(tmp)
            data = json.loads(result)
            assert "error" in data
            if not data["error"]:
                assert "type" in data
        finally:
            os.unlink(tmp)
