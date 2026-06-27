"""Tests for Skills package integrity.

Validates that the plugin loader, SKILL.md files on disk, and CLI
commands all stay in sync. If any of these drift (e.g. a skill is
added to .claude/skills/ but not to the plugin JS, or a SKILL.md
references a command that doesn't exist), these tests will catch it.
"""

import json
import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKILLS_DIR = os.path.join(REPO_ROOT, ".claude", "skills")
PLUGIN_JS = os.path.join(REPO_ROOT, ".claude", "plugins", "ai-apkid.js")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_skill_frontmatter(skill_md_path: str) -> dict:
    """Parse YAML frontmatter from a SKILL.md file (simple parser)."""
    with open(skill_md_path, "r", encoding="utf-8") as f:
        content = f.read()
    # Extract content between --- delimiters
    m = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not m:
        return {}
    frontmatter_text = m.group(1)
    result = {}
    for line in frontmatter_text.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            result[key] = value
    return result


def _get_plugin_skills() -> list:
    """Extract skill entries from the plugin JS file."""
    with open(PLUGIN_JS, "r", encoding="utf-8") as f:
        content = f.read()
    # Match name: "apkid-xxx" entries
    names = re.findall(r'name:\s*"((?:apkid)[\w-]+)"', content)
    return sorted(set(names))


def _get_disk_skills() -> list:
    """List skill directory names under .claude/skills/."""
    skills = []
    for entry in sorted(os.listdir(SKILLS_DIR)):
        skill_md = os.path.join(SKILLS_DIR, entry, "SKILL.md")
        if os.path.isdir(os.path.join(SKILLS_DIR, entry)) and os.path.exists(skill_md):
            skills.append(entry)
    return skills


def _get_cli_commands() -> list:
    """Get registered command names from apkid-ai-cli."""
    result = subprocess.run(
        [sys.executable, "-m", "apkid.cli", "skills"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        pytest.skip("apkid-ai-cli not available (rules.yarc may not be compiled)")
    data = json.loads(result.stdout)
    return [s["name"] for s in data.get("skills", [])]


# ---------------------------------------------------------------------------
# Tests: Plugin ↔ Disk consistency
# ---------------------------------------------------------------------------

class TestPluginDiskConsistency:
    """Plugin JS must list exactly the same skills as .claude/skills/ dirs."""

    def test_plugin_lists_all_disk_skills(self):
        """Every skill directory must be registered in the plugin JS."""
        disk = _get_disk_skills()
        plugin = _get_plugin_skills()
        missing = set(disk) - set(plugin)
        assert not missing, (
            f"Skills on disk but NOT in plugin JS: {missing}\n"
            f"Add them to {PLUGIN_JS}"
        )

    def test_plugin_has_no_extra_skills(self):
        """Plugin JS must not reference skills that don't exist on disk."""
        disk = _get_disk_skills()
        plugin = _get_plugin_skills()
        extra = set(plugin) - set(disk)
        assert not extra, (
            f"Skills in plugin JS but NOT on disk: {extra}\n"
            f"Remove them from {PLUGIN_JS} or create the SKILL.md"
        )

    def test_plugin_skill_count_matches_disk(self):
        """Count of skills in plugin must equal count on disk."""
        disk = _get_disk_skills()
        plugin = _get_plugin_skills()
        assert len(plugin) == len(disk), (
            f"Plugin has {len(plugin)} skills, disk has {len(disk)}"
        )


# ---------------------------------------------------------------------------
# Tests: SKILL.md frontmatter validity
# ---------------------------------------------------------------------------

class TestSkillFrontmatter:
    """Each SKILL.md must have valid frontmatter with required fields."""

    @pytest.fixture(params=_get_disk_skills())
    def skill_name(self, request):
        return request.param

    def test_has_name_field(self, skill_name):
        path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
        fm = _parse_skill_frontmatter(path)
        assert "name" in fm, f"{path}: missing 'name' in frontmatter"

    def test_name_matches_directory(self, skill_name):
        path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
        fm = _parse_skill_frontmatter(path)
        assert fm.get("name") == skill_name, (
            f"{path}: frontmatter name={fm.get('name')!r} != directory name {skill_name!r}"
        )

    def test_has_description_field(self, skill_name):
        path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
        fm = _parse_skill_frontmatter(path)
        assert "description" in fm, f"{path}: missing 'description' in frontmatter"
        assert len(fm["description"]) > 10, (
            f"{path}: description too short ({len(fm['description'])} chars)"
        )

    def test_has_allowed_tools_field(self, skill_name):
        path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
        fm = _parse_skill_frontmatter(path)
        assert "allowed-tools" in fm, f"{path}: missing 'allowed-tools' in frontmatter"


# ---------------------------------------------------------------------------
# Tests: Plugin ↔ CLI consistency
# ---------------------------------------------------------------------------

class TestPluginCLIConsistency:
    """Plugin skill names should map to real CLI commands."""

    def test_plugin_skills_have_cli_commands(self):
        """Each plugin skill name should map to a real CLI command."""
        plugin = _get_plugin_skills()
        # Some skill names don't map 1:1 to CLI command names
        skill_to_cmd = {
            "apkid-rule-dev": "rules",  # skill is "rule-dev" but CLI command is "rules"
        }
        try:
            cli_commands = _get_cli_commands()
        except Exception:
            pytest.skip("apkid-ai-cli not available")

        for skill_name in plugin:
            if skill_name in skill_to_cmd:
                cmd_name = skill_to_cmd[skill_name]
            else:
                # apkid-scan -> scan, apkid-list-tags -> list-tags, etc.
                cmd_name = skill_name.removeprefix("apkid-")
            assert cmd_name in cli_commands, (
                f"Skill '{skill_name}' maps to CLI command '{cmd_name}', "
                f"but that command doesn't exist. Available: {cli_commands}"
            )
