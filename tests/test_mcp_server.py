"""Tests for the APKiD MCP Server module."""

import pytest
from unittest.mock import patch, MagicMock

from apkid.mcp.tools_info import info, list_tags, rules, skills
from apkid.mcp.tools_scan import type_file, scan_file, batch_scan, diff_files


class TestInfoTools:
    """Test info-type MCP tools that don't require file scanning."""

    def test_list_tags_returns_dict_with_tags(self):
        result = list_tags()
        assert result["error"] is False
        assert "tags" in result
        assert len(result["tags"]) > 0
        tag_names = [t["tag"] for t in result["tags"]]
        assert "anti_vm" in tag_names
        assert "packer" in tag_names

    def test_list_tags_each_has_description(self):
        result = list_tags()
        for tag_entry in result["tags"]:
            assert "tag" in tag_entry
            assert "description" in tag_entry
            assert len(tag_entry["description"]) > 0

    def test_skills_returns_tool_list(self):
        result = skills()
        assert result["error"] is False
        assert "tools" in result
        assert result["total"] > 0
        tool_names = [t["name"] for t in result["tools"]]
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
            assert result["error"] is False
            assert result["count"] == 2

    def test_rules_invalid_action_returns_error(self):
        result = rules("invalid")
        assert result["error"] is True
        assert "Unknown action" in result["message"]


class TestScanTools:
    """Test scan-type MCP tools with file system mocking."""

    def test_scan_file_not_found(self):
        result = scan_file("/nonexistent/path.apk")
        assert result["error"] is True
        assert "not found" in result["message"].lower() or "File not found" in result["message"]

    def test_batch_scan_directory_not_found(self):
        result = batch_scan("/nonexistent/dir")
        assert result["error"] is True

    def test_diff_files_missing_file1(self):
        result = diff_files("/nonexistent1.apk", "/nonexistent2.apk")
        assert result["error"] is True

    def test_type_file_not_found(self):
        result = type_file("/nonexistent/file.apk")
        assert result["error"] is True
        assert "not found" in result["message"].lower() or "File not found" in result["message"]

    def test_type_file_unknown_format(self, tmp_path):
        unknown_file = tmp_path / "unknown.bin"
        unknown_file.write_bytes(b"\x00\x00\x00\x00")
        result = type_file(str(unknown_file))
        assert result["error"] is False
        assert result["type"] is None

    def test_type_file_dex_format(self, tmp_path):
        dex_file = tmp_path / "test.dex"
        dex_file.write_bytes(b"dex\n\x00\x00\x00")
        result = type_file(str(dex_file))
        assert result["error"] is False
        assert result["type"] == "dex"

    def test_scan_file_returns_dict_not_string(self):
        """Verify tool returns a dict, not a JSON string."""
        result = scan_file("/nonexistent/path.apk")
        assert isinstance(result, dict)

    def test_type_file_returns_dict_not_string(self, tmp_path):
        """Verify tool returns a dict, not a JSON string."""
        bin_file = tmp_path / "test.bin"
        bin_file.write_bytes(b"\x00\x00\x00\x00")
        result = type_file(str(bin_file))
        assert isinstance(result, dict)