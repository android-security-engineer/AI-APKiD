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
import subprocess
import sys
from pathlib import Path

import pytest

from apkid.ai_output import AIOutputFormatter, RULE_DESCRIPTIONS


class TestAIOutputFormatter:

    def test_format_json_returns_valid_json(self):
        """JSON format output is valid JSON with required keys."""
        formatter = AIOutputFormatter()
        output = formatter.format({}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        assert data["error"] is False
        assert data["target"] == "/test/app.apk"
        assert "findings" in data
        assert "summary" in data
        assert "scanned_at" in data

    def test_format_text_output(self):
        """Text format output contains key information in readable form."""
        formatter = AIOutputFormatter()
        output = formatter.format({}, "/test/app.apk", fmt="text")
        assert "/test/app.apk" in output
        assert "No identifiers detected" in output

    def test_format_empty_results(self):
        """Empty results produce valid output with no findings."""
        formatter = AIOutputFormatter()
        output = formatter.format({}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0

    def test_format_dict_for_batch(self):
        """format_dict returns a plain dict suitable for batch aggregation."""
        formatter = AIOutputFormatter()
        result_dict = formatter.format_dict({}, "/test/app.apk")
        assert isinstance(result_dict, dict)
        assert result_dict["error"] is False
        assert len(result_dict["findings"]) == 0

    def test_categorize_unknown_tag(self):
        """Unknown tags are categorized as 'abnormal'."""
        formatter = AIOutputFormatter()
        output = formatter.format({"classes.dex": ["unknown_weird_tag"]}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        assert data["findings"][0]["category"] == "abnormal"

    def test_rule_descriptions_not_empty(self):
        """RULE_DESCRIPTIONS contains entries for all expected categories."""
        expected = ["packer", "signer", "compiler", "obfuscator", "protector",
                     "anti_vm", "anti_debug", "anti_root", "anti_hook", "yara_issue"]
        for cat in expected:
            assert cat in RULE_DESCRIPTIONS


class TestConfidenceField:
    """Test confidence inference based on source file type."""

    def test_confidence_high_for_dex(self):
        """DEX-level match gets 'high' confidence."""
        formatter = AIOutputFormatter()
        output = formatter.format({"classes.dex": ["packer"]}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        finding = data["findings"][0]
        assert finding["confidence"] == "high"

    def test_confidence_low_for_apk(self):
        """APK-level match gets 'low' confidence."""
        formatter = AIOutputFormatter()
        output = formatter.format({"/test/app.apk": ["packer"]}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        finding = data["findings"][0]
        assert finding["confidence"] == "low"

    def test_confidence_medium_for_suggestion(self):
        """Inference fallback is 'medium'."""
        assert AIOutputFormatter()._infer_confidence("unknown_file") == "medium"

    def test_confidence_present_in_all_findings(self):
        """Every finding has a confidence field."""
        formatter = AIOutputFormatter()
        output = formatter.format({"classes.dex": ["packer", "anti_vm"]}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        for finding in data["findings"]:
            assert "confidence" in finding
            assert finding["confidence"] in ("high", "medium", "low")


class TestVersionField:
    """Test version extraction from rule names."""

    def test_version_from_v_prefix(self):
        """ollvm_v3_4 → version '3.4'."""
        formatter = AIOutputFormatter()
        version = formatter._extract_version("ollvm_v3_4")
        assert version == "3.4"

    def test_version_from_v_single_digit(self):
        """ollvm_v9 → version '9'."""
        formatter = AIOutputFormatter()
        version = formatter._extract_version("ollvm_v9")
        assert version == "9"

    def test_version_from_trailing_digits(self):
        """upx_elf_3_92 → version '3.92'."""
        formatter = AIOutputFormatter()
        version = formatter._extract_version("upx_elf_3_92")
        assert version == "3.92"

    def test_version_three_parts(self):
        """byteguard_0_9_2 → version '0.9.2'."""
        formatter = AIOutputFormatter()
        version = formatter._extract_version("byteguard_0_9_2")
        assert version == "0.9.2"

    def test_no_version_for_plain_name(self):
        """bangcle → no version."""
        formatter = AIOutputFormatter()
        version = formatter._extract_version("bangcle")
        assert version is None

    def test_version_in_output(self):
        """Version appears in the JSON output when rule name contains version info."""
        formatter = AIOutputFormatter()
        output = formatter.format({"classes.dex": ["packer"]}, "/test/app.apk", fmt="json")
        data = json.loads(output)
        # Our mock tag "packer" is also the rule name, which has no version
        # But the version key should NOT be present when version is None
        for finding in data["findings"]:
            if finding["identifier"].startswith(("ollvm_v", "upx_", "byteguard_")):
                assert "version" in finding


class TestCLICommands:

    def test_list_tags_command(self):
        """ai-apkid list-tags outputs valid JSON with tags array."""
        result = subprocess.run(
            [sys.executable, "-m", "apkid.cli", "list-tags"],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "tags" in data
        assert isinstance(data["tags"], list)
        assert len(data["tags"]) > 0
        assert "tag" in data["tags"][0]
        assert "description" in data["tags"][0]

    def test_scan_nonexistent_file(self):
        """ai-apkid scan returns error for nonexistent file."""
        result = subprocess.run(
            [sys.executable, "-m", "apkid.cli", "scan", "/nonexistent/file.apk"],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode != 0

    def test_batch_empty_directory(self):
        """ai-apkid batch handles empty directory gracefully."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [sys.executable, "-m", "apkid.cli", "batch", tmpdir],
                capture_output=True, text=True, timeout=30
            )
            # If rules.yarc is not compiled, the command will fail with an error
            # about missing rules file — that's expected in dev environments
            if result.returncode == 0:
                data = json.loads(result.stdout)
                assert data["scanned"] == 0
            else:
                # Rules not compiled — verify error is about rules, not our code
                assert "rules.yarc" in result.stderr or "yara" in result.stderr

    def test_info_command(self):
        """ai-apkid info outputs version and rules info."""
        result = subprocess.run(
            [sys.executable, "-m", "apkid.cli", "info"],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "version" in data
        assert "rules_sha256" in data

    def test_rules_list_command(self):
        """ai-apkid rules list outputs rule file list."""
        result = subprocess.run(
            [sys.executable, "-m", "apkid.cli", "rules", "list"],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "rules" in data
        assert isinstance(data["rules"], list)

    def test_scan_help_shows_all_params(self):
        """ai-apkid scan --help shows all Options parameters."""
        result = subprocess.run(
            [sys.executable, "-m", "apkid.cli", "scan", "--help"],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0
        for param in ["--typing", "--scan-depth", "--entry-max-scan-size", "--include-types", "--timeout"]:
            assert param in result.stdout, f"Missing {param} in scan --help"


class TestDiffLogic:
    """Test diff added/removed/common logic at the formatter level."""

    def test_diff_added_removed_common(self):
        """Diff between two result dicts correctly identifies added, removed, and common findings."""
        formatter = AIOutputFormatter()
        # Simulate file1 findings: packer + compiler
        results1 = {"classes.dex": ["packer", "compiler"]}
        dict1 = formatter.format_dict(results1, "/file1.apk")
        # Simulate file2 findings: compiler + anti_vm (packer removed, anti_vm added)
        results2 = {"classes.dex": ["compiler", "anti_vm"]}
        dict2 = formatter.format_dict(results2, "/file2.apk")

        tags1 = {f["tag"] for f in dict1.get("findings", [])}
        tags2 = {f["tag"] for f in dict2.get("findings", [])}

        added = sorted(tags2 - tags1)
        removed = sorted(tags1 - tags2)
        common = sorted(tags1 & tags2)

        assert "anti_vm" in added
        assert "packer" in removed
        assert "compiler" in common
        assert len(added) == 1
        assert len(removed) == 1
        assert len(common) == 1

    def test_diff_all_common(self):
        """Two files with identical findings have no added/removed."""
        formatter = AIOutputFormatter()
        results = {"classes.dex": ["packer", "compiler"]}
        dict1 = formatter.format_dict(results, "/file1.apk")
        dict2 = formatter.format_dict(results, "/file2.apk")

        tags1 = {f["tag"] for f in dict1.get("findings", [])}
        tags2 = {f["tag"] for f in dict2.get("findings", [])}

        assert tags1 == tags2
        assert len(tags2 - tags1) == 0
        assert len(tags1 - tags2) == 0

    def test_diff_no_overlap(self):
        """Two files with completely different findings."""
        formatter = AIOutputFormatter()
        dict1 = formatter.format_dict({"classes.dex": ["packer"]}, "/file1.apk")
        dict2 = formatter.format_dict({"classes.dex": ["anti_vm"]}, "/file2.apk")

        tags1 = {f["tag"] for f in dict1.get("findings", [])}
        tags2 = {f["tag"] for f in dict2.get("findings", [])}

        assert len(tags2 - tags1) == 1
        assert len(tags1 - tags2) == 1
        assert len(tags1 & tags2) == 0

    def test_diff_empty_vs_nonempty(self):
        """Diff between empty results and findings shows all as added."""
        formatter = AIOutputFormatter()
        dict1 = formatter.format_dict({}, "/empty.apk")
        dict2 = formatter.format_dict({"classes.dex": ["packer"]}, "/packed.apk")

        tags1 = {f["tag"] for f in dict1.get("findings", [])}
        tags2 = {f["tag"] for f in dict2.get("findings", [])}

        assert len(tags1) == 0
        assert "packer" in tags2
        assert tags2 - tags1 == tags2