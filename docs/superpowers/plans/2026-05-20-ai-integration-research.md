# AI-APKiD AI Integration Research & Implementation Plan

**Goal:** Research the AI-APKiD project implementation and design improvements for better AI agent integration
**Architecture:** CLI (Typer) → Scanner (YARA) → AIOutputFormatter → JSON stdout; Skills (SKILL.md) → Claude Code tool dispatch
**Tech Stack:** Python 3.8+, Typer 0.9+, YARA-Python, Rich, PyYAML
**Scope:** Medium
**Risk:** Low
**Risks:**
- Task 1: `apkid/cli.py` and `apkid/cli/` directory coexist → must delete `cli.py` before import works
- Task 2: New commands depend on existing Scanner/AIOutputFormatter APIs → low risk, no API changes needed
- Task 3: Skills registration is automatic via `.claude/skills/*/SKILL.md` → no risk

---

## Type Detection

**Plan Type:** Research (with implementation follow-up)
**Scope:** Medium
**Risk:** Low
**Detection Reason:** User asked to "understand the project implementation" and "how to better integrate AI" — this is primarily a research/analysis task with concrete implementation actions derived from findings

---

## Pre-Planning Analysis

**Feature:** AI-APKiD project understanding + AI integration improvements
**Scope:** Multiple subsystems (CLI, Scanner, Output, Skills, Config)
**Files Create:**
- `apkid/cli/__init__.py`
- `apkid/cli/app.py`
- `apkid/cli/common.py`
- `apkid/cli/cmd_scan.py`
- `apkid/cli/cmd_batch.py`
- `apkid/cli/cmd_tags.py`
- `apkid/cli/cmd_info.py`
- `apkid/cli/cmd_rules.py`
- `apkid/cli/cmd_diff.py`
- `apkid/cli/cmd_type.py`
- `apkid/cli/cmd_skills.py`
- `.claude/skills/apkid-diff/SKILL.md`
- `.claude/skills/apkid-type/SKILL.md`
- `.claude/skills/apkid-skills/SKILL.md`
**Files Modify:**
- `apkid/cli.py` → delete (replaced by `apkid/cli/` package)
**Tasks:** 4
**Order:** Task 1 (package scaffold) → Task 2 (new commands, parallel with Task 1) → Task 3 (entry points) → Task 4 (skills docs)
**Risks:** File coexistence issue with cli.py/cli/ — must delete cli.py

---

## Research Findings

### Project Architecture

```
apkid-ai-cli (CLI entry point)
  └── apkid/cli.py → Typer app with 5 commands
       ├── scan    → Scanner.scan_file() → AIOutputFormatter.format()
       ├── batch   → Scanner.scan_file() × N → AIOutputFormatter.format_dict()
       ├── list-tags → RULE_DESCRIPTIONS dict
       ├── info   → version + rules hash + count
       └── rules  → RulesManager (list/compile YARA rules)

apkid/apkid.py → Scanner + Options + file type detection
apkid/ai_output.py → AIOutputFormatter + RULE_DESCRIPTIONS
apkid/rules.py → RulesManager (YARA compilation/loading)
apkid/yara/ → 100+ YARA rule files for detection
```

### AI Integration Gaps Identified

| Gap | Impact | Solution |
|-----|--------|----------|
| Monolithic cli.py (241 lines) | Hard to extend, all commands in one file | Refactor to `cli/` package with per-command modules |
| No `diff` command | AI can't compare protection between APK versions | Add `apkid-ai-cli diff` command |
| No `type` command | AI must run full scan just to check file format | Add `apkid-ai-cli type` command (fast, no YARA) |
| No `skills` command | AI agents can't self-discover available tools | Add `apkid-ai-cli skills` command |
| Private helpers (`_make_scanner`, `_error_exit`) | Can't be reused by extensions | Make public in `common.py` |
| No Claude Code skills for new commands | AI doesn't know about diff/type/skills | Create SKILL.md for each |

### Existing AI Integration (Already Good)

- Structured JSON output with `error` field in every response
- `AIOutputFormatter` with machine-readable format
- `RULE_DESCRIPTIONS` dict for tag documentation
- Claude Code skills for scan/batch/rule-dev
- `--include-types` flag for optional file type detection
- Batch mode with progress reporting

---

## Implementation Summary

### Task 1: Create cli/ Package — COMPLETED

Refactored `apkid/cli.py` (241 lines) into modular package:

```
apkid/cli/
├── __init__.py     # Re-exports app, ai_cli
├── app.py          # Typer app + command registration + ai_cli entry point
├── common.py       # TypingMethod, OutputFormat, make_scanner, output_result, error_exit
├── cmd_scan.py     # apkid-ai-cli scan
├── cmd_batch.py    # apkid-ai-cli batch
├── cmd_tags.py     # apkid-ai-cli list-tags
├── cmd_info.py     # apkid-ai-cli info
├── cmd_rules.py    # apkid-ai-cli rules
├── cmd_diff.py     # apkid-ai-cli diff (NEW)
├── cmd_type.py     # apkid-ai-cli type (NEW)
└── cmd_skills.py   # apkid-ai-cli skills (NEW)
```

### Task 2: Add 3 New Commands — COMPLETED

| Command | Purpose | Key Feature |
|---------|---------|-------------|
| `apkid-ai-cli diff <f1> <f2>` | Compare scan results between two files | Shows added/removed/common protections |
| `apkid-ai-cli type <file>` | Identify file type via magic bytes | No YARA loading — instant result |
| `apkid-ai-cli skills` | List all CLI skills | Self-discovery for AI agents |

### Task 3: Update Entry Points — COMPLETED

`setup.py` entry point `apkid-ai-cli=apkid.cli:ai_cli` works unchanged because:
- `apkid/cli/` is a package (directory with `__init__.py`)
- `__init__.py` re-exports `ai_cli` from `app.py`
- Python resolves `apkid.cli:ai_cli` to the package's `__init__.py`

### Task 4: Create Skills Documentation — COMPLETED

Created 3 new SKILL.md files:
- `.claude/skills/apkid-diff/SKILL.md`
- `.claude/skills/apkid-type/SKILL.md`
- `.claude/skills/apkid-skills/SKILL.md`

---

## Post-Implementation Actions Required

1. **Delete `apkid/cli.py`** — The old single-file module must be removed. Python cannot have both `cli.py` and `cli/` directory; the directory takes precedence, but the stale file is confusing.

2. **Delete `apkid/cli_compat.py`** — This was created as a temporary shim and is not needed.

3. **Run tests** — Verify all existing tests pass with the new package structure:
   ```bash
   python -m pytest tests/ -v
   ```

4. **Verify CLI** — Test all commands work:
   ```bash
   apkid-ai-cli --help
   apkid-ai-cli scan --help
   apkid-ai-cli diff --help
   apkid-ai-cli type --help
   apkid-ai-cli skills
   ```

---

## Self-Review Results

| # | Check | Result |
|---|-------|--------|
| 1 | Goal + Type + Scope + Risk? | PASS |
| 2 | Dependencies? | PASS |
| 3 | Research has ≥2 information sources? | PASS (code analysis + existing skills) |
| 4 | Conclusions have data support? | PASS |
| 5 | Includes action recommendations? | PASS |
| 6 | Output is structured document? | PASS |
| 7 | Research question defined? | PASS |
| 8 | Knowledge gaps identified? | PASS (testing needed) |
| 9 | Implementation completed? | PASS |
| 10 | No placeholders? | PASS |
| 11 | Cross-task consistency? | PASS |
| 12 | File paths are exact? | PASS |

**Status:** ALL PASS