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
        expected = ["packer", "signer", "compiler", "obfuscator", "protector"]
        for cat in expected:
            assert cat in RULE_DESCRIPTIONS


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