# AI-APKiD Skills Repository Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 AI-APKiD 逆向工具的能力封装为 AI 友好的 CLI 入口和 Claude Code Skills，使当前仓库成为可通过 marketplace 直接安装的 Skills 仓库。

**Architecture:** AI 调用 `/apkid-scan` skill → skill 触发 Bash 执行 `ai-apkid` CLI 命令 → CLI 调用 apkid 核心扫描逻辑 → AIOutputFormatter 格式化为结构化 JSON → AI 解析 JSON 结果呈现给用户。三个 skill 分别覆盖：单文件扫描、批量扫描、YARA 规则开发辅助。插件 JS 文件注册 skills 路径，使 Claude Code 能发现和加载。

**Tech Stack:** Python 3.8+, Click 8.x (CLI), YARA-X, Claude Code Skills (SKILL.md frontmatter), Node.js plugin loader

**Risks:**
- Task 1 修改 setup.py 添加新 entry point，可能影响现有 `apkid` 命令 → 缓解：新增独立 `ai-apkid` entry point，不修改原有
- Task 3-4 Skills frontmatter 格式需严格匹配 Claude Code 规范 → 缓解：参照 superpowers-auto 的 SKILL.md 格式
- 插件 JS 文件需正确注册 skills 路径 → 缓解：参照 superpowers-auto 的 .claude/plugins/ 实现
- AI CLI 需在无 TTY 环境下稳定运行 → 缓解：所有输出走 stdout/stderr，无交互式提示

---

### Task 1: AI-Friendly CLI Entry Point

**Depends on:** None
**Files:**
- Create: `apkid/cli.py`
- Modify: `setup.py:104-108`
- Test: `tests/test_cli.py`

- [ ] **Step 1: 创建 AI CLI 模块 — 提供结构化 JSON 输出的命令行入口**

```python
# apkid/cli.py
import json
import sys
from pathlib import Path

import click

from apkid.apkid import Scanner, RulesManager
from apkid.ai_output import AIOutputFormatter


@click.group()
def ai_cli():
    """AI-APKiD: Android APK/DEX/ELF identifier for AI agents."""
    pass


@ai_cli.command(name="scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path (default: stdout)")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="json", help="Output format")
@click.option("--timeout", type=int, default=60, help="Scan timeout in seconds")
def scan_cmd(target, output, fmt, timeout):
    """Scan an APK, DEX, or ELF file for packer/signer/compiler identifiers."""
    try:
        rules_mgr = RulesManager()
        scanner = Scanner(rules_mgr)
        results = scanner.scan(target, timeout=timeout)
        formatter = AIOutputFormatter()
        formatted = formatter.format(results, target, fmt=fmt)
        if output:
            Path(output).write_text(formatted, encoding="utf-8")
        else:
            click.echo(formatted)
    except Exception as e:
        error_payload = json.dumps({
            "error": True,
            "message": str(e),
            "type": type(e).__name__,
            "target": target
        }, ensure_ascii=False)
        click.echo(error_payload, err=True)
        sys.exit(1)


@ai_cli.command(name="batch")
@click.argument("directory", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Scan subdirectories recursively")
@click.option("--pattern", "-p", default="*.apk", help="File glob pattern (default: *.apk)")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="json", help="Output format")
def batch_cmd(directory, recursive, pattern, output, fmt):
    """Batch scan files in a directory."""
    try:
        rules_mgr = RulesManager()
        scanner = Scanner(rules_mgr)
        formatter = AIOutputFormatter()
        target_path = Path(directory)
        if recursive:
            files = sorted(target_path.rglob(pattern))
        else:
            files = sorted(target_path.glob(pattern))
        if not files:
            click.echo(json.dumps({
                "error": False,
                "scanned": 0,
                "results": [],
                "message": f"No files matching '{pattern}' found in {directory}"
            }, ensure_ascii=False))
            return
        all_results = []
        for f in files:
            results = scanner.scan(str(f))
            formatted = formatter.format_dict(results, str(f))
            all_results.append(formatted)
        batch_output = json.dumps({
            "error": False,
            "scanned": len(all_results),
            "results": all_results
        }, ensure_ascii=False, indent=2)
        if output:
            Path(output).write_text(batch_output, encoding="utf-8")
        else:
            click.echo(batch_output)
    except Exception as e:
        error_payload = json.dumps({
            "error": True,
            "message": str(e),
            "type": type(e).__name__
        }, ensure_ascii=False)
        click.echo(error_payload, err=True)
        sys.exit(1)


@ai_cli.command(name="list-tags")
def list_tags_cmd():
    """List all available detection tags and their descriptions."""
    from apkid.rules import RULE_DESCRIPTIONS
    tags = []
    for tag, desc in sorted(RULE_DESCRIPTIONS.items()):
        tags.append({"tag": tag, "description": desc})
    click.echo(json.dumps({"tags": tags}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    ai_cli()
```

- [ ] **Step 2: 修改 setup.py 以注册 ai-apkid CLI entry point**
文件: `setup.py:104-108`（entry_points 区块）

```python
# 替换 setup.py 中的 entry_points 区块
entry_points={
    "console_scripts": [
        "apkid = apkid.main:main",
        "ai-apkid = apkid.cli:ai_cli",
    ],
},
```

- [ ] **Step 3: 创建 CLI 测试**

```python
# tests/test_cli.py
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_apk():
    """Return path to a test APK if available, else skip."""
    test_dir = Path(__file__).parent
    apk_files = list(test_dir.glob("samples/*.apk"))
    if not apk_files:
        pytest.skip("No sample APK files found")
    return str(apk_files[0])


def test_ai_apkid_scan_json_output(sample_apk):
    """ai-apkid scan outputs valid JSON with expected keys."""
    result = subprocess.run(
        [sys.executable, "-m", "apkid.cli", "scan", sample_apk],
        capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "error" in data
    assert data["error"] is False
    assert "target" in data
    assert "findings" in data


def test_ai_apkid_scan_nonexistent_file():
    """ai-apkid scan returns error JSON for nonexistent file."""
    result = subprocess.run(
        [sys.executable, "-m", "apkid.cli", "scan", "/nonexistent/file.apk"],
        capture_output=True, text=True, timeout=30
    )
    assert result.returncode != 0
    error_data = json.loads(result.stderr)
    assert error_data["error"] is True


def test_ai_apkid_list_tags():
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
```

- [ ] **Step 4: 验证 CLI 入口**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && python -m apkid.cli --help`
Expected:
  - Exit code: 0
  - Output contains: "scan" and "batch" and "list-tags"

- [ ] **Step 5: 提交**
Run: `git add apkid/cli.py setup.py tests/test_cli.py && git commit -m "feat(cli): add AI-friendly CLI entry point with JSON output"`

---

### Task 2: AI Output Formatter

**Depends on:** Task 1
**Files:**
- Create: `apkid/ai_output.py`
- Create: `apkid/rules.py` 补充 RULE_DESCRIPTIONS 导出
- Test: `tests/test_ai_output.py`

- [ ] **Step 1: 创建 AIOutputFormatter — 将扫描结果格式化为 AI 可解析的结构化输出**

```python
# apkid/ai_output.py
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


RULE_DESCRIPTIONS = {
    "anti_vm": "Detects anti-VM/anti-emulator techniques",
    "anti_debug": "Detects anti-debugging techniques",
    "packer": "Detects APK packing/obfuscation tools",
    "obfuscator": "Detects code obfuscation tools",
    "protector": "Detects app protection/shielding SDKs",
    "signer": "Detects APK signing certificates and signers",
    "compiler": "Detects compiler or build tool fingerprints",
    "abnormal": "Detects abnormal or suspicious modifications",
    "dropper": "Detects dropper/loader behavior patterns",
    "root": "Detects root detection or root-related libraries",
    "hook": "Detects hooking frameworks (Xposed, Frida, etc.)",
    "ad": "Detects ad SDK fingerprints",
    "tracker": "Detects analytics/tracker SDK fingerprints",
    "network": "Detects network communication libraries",
    "crypto": "Detects cryptographic library usage",
}


class AIOutputFormatter:
    """Formats APKiD scan results for AI agent consumption."""

    def format(self, results: Any, target: str, fmt: str = "json") -> str:
        """Format scan results into the specified output format.

        Args:
            results: Raw scan results from Scanner.scan()
            target: Path to the scanned file
            fmt: Output format - 'json' or 'text'

        Returns:
            Formatted output string
        """
        if fmt == "text":
            return self._format_text(results, target)
        return self._format_json(results, target)

    def format_dict(self, results: Any, target: str) -> Dict:
        """Format scan results into a dictionary for batch aggregation.

        Args:
            results: Raw scan results from Scanner.scan()
            target: Path to the scanned file

        Returns:
            Dictionary with structured scan results
        """
        return self._build_result_dict(results, target)

    def _format_json(self, results: Any, target: str) -> str:
        result_dict = self._build_result_dict(results, target)
        return json.dumps(result_dict, ensure_ascii=False, indent=2)

    def _format_text(self, results: Any, target: str) -> str:
        result_dict = self._build_result_dict(results, target)
        lines = [f"Target: {result_dict['target']}", ""]
        for finding in result_dict.get("findings", []):
            lines.append(f"  [{finding['category']}] {finding['identifier']}")
            if finding.get("description"):
                lines.append(f"    {finding['description']}")
        if not result_dict.get("findings"):
            lines.append("  No identifiers detected")
        lines.append("")
        lines.append(f"Scanned at: {result_dict['scanned_at']}")
        return "\n".join(lines)

    def _build_result_dict(self, results: Any, target: str) -> Dict:
        findings = self._extract_findings(results)
        return {
            "error": False,
            "target": target,
            "findings": findings,
            "summary": self._build_summary(findings),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _extract_findings(self, results: Any) -> List[Dict]:
        findings = []
        if results is None:
            return findings
        if isinstance(results, dict):
            for dex_path, tags in results.items():
                if isinstance(tags, list):
                    for tag in tags:
                        findings.append(self._tag_to_finding(tag, dex_path))
                elif isinstance(tags, str):
                    findings.append(self._tag_to_finding(tags, str(dex_path)))
        elif isinstance(results, list):
            for item in results:
                if isinstance(item, tuple) and len(item) == 2:
                    dex_path, tags = item
                    if isinstance(tags, list):
                        for tag in tags:
                            findings.append(self._tag_to_finding(tag, str(dex_path)))
                    else:
                        findings.append(self._tag_to_finding(str(tags), str(dex_path)))
        return findings

    def _tag_to_finding(self, tag: str, source: str) -> Dict:
        category = self._categorize_tag(tag)
        return {
            "tag": tag,
            "category": category,
            "description": RULE_DESCRIPTIONS.get(category, "Unknown detection category"),
            "source": source,
            "identifier": tag,
        }

    def _categorize_tag(self, tag: str) -> str:
        tag_lower = tag.lower()
        for category in RULE_DESCRIPTIONS:
            if category in tag_lower:
                return category
        return "abnormal"

    def _build_summary(self, findings: List[Dict]) -> Dict:
        categories = {}
        for f in findings:
            cat = f["category"]
            categories[cat] = categories.get(cat, 0) + 1
        return {
            "total_findings": len(findings),
            "categories": categories,
        }
```

- [ ] **Step 2: 创建 AIOutputFormatter 测试**

```python
# tests/test_ai_output.py
import json

from apkid.ai_output import AIOutputFormatter, RULE_DESCRIPTIONS


def test_format_json_returns_valid_json():
    """JSON format output is valid JSON with required keys."""
    formatter = AIOutputFormatter()
    results = {"classes.dex": ["packer::bangcle", "signer::dev"]}
    output = formatter.format(results, "/test/app.apk", fmt="json")
    data = json.loads(output)
    assert data["error"] is False
    assert data["target"] == "/test/app.apk"
    assert "findings" in data
    assert "summary" in data
    assert "scanned_at" in data


def test_format_json_findings_structure():
    """Each finding has tag, category, description, source, identifier."""
    formatter = AIOutputFormatter()
    results = {"classes.dex": ["packer::bangcle"]}
    output = formatter.format(results, "/test/app.apk", fmt="json")
    data = json.loads(output)
    finding = data["findings"][0]
    assert finding["tag"] == "packer::bangcle"
    assert finding["category"] == "packer"
    assert "description" in finding
    assert finding["source"] == "classes.dex"


def test_format_text_output():
    """Text format output contains key information in readable form."""
    formatter = AIOutputFormatter()
    results = {"classes.dex": ["packer::bangcle"]}
    output = formatter.format(results, "/test/app.apk", fmt="text")
    assert "/test/app.apk" in output
    assert "packer" in output


def test_format_empty_results():
    """Empty results produce valid output with no findings."""
    formatter = AIOutputFormatter()
    output = formatter.format({}, "/test/app.apk", fmt="json")
    data = json.loads(output)
    assert data["findings"] == []
    assert data["summary"]["total_findings"] == 0


def test_format_dict_for_batch():
    """format_dict returns a plain dict suitable for batch aggregation."""
    formatter = AIOutputFormatter()
    results = {"classes.dex": ["signer::dev"]}
    result_dict = formatter.format_dict(results, "/test/app.apk")
    assert isinstance(result_dict, dict)
    assert result_dict["error"] is False
    assert len(result_dict["findings"]) == 1


def test_categorize_unknown_tag():
    """Unknown tags are categorized as 'abnormal'."""
    formatter = AIOutputFormatter()
    results = {"classes.dex": ["unknown_weird_tag"]}
    output = formatter.format(results, "/test/app.apk", fmt="json")
    data = json.loads(output)
    assert data["findings"][0]["category"] == "abnormal"


def test_rule_descriptions_not_empty():
    """RULE_DESCRIPTIONS contains entries for all expected categories."""
    expected = ["packer", "signer", "compiler", "obfuscator", "protector"]
    for cat in expected:
        assert cat in RULE_DESCRIPTIONS
```

- [ ] **Step 3: 验证 AIOutputFormatter**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && python -m pytest tests/test_ai_output.py -v --no-header`
Expected:
  - Exit code: 0
  - Output contains: "7 passed"

- [ ] **Step 4: 提交**
Run: `git add apkid/ai_output.py tests/test_ai_output.py && git commit -m "feat(output): add AI output formatter with structured JSON/text output"`

---

### Task 3: APKiD Scan Skill Definition

**Depends on:** Task 2
**Files:**
- Create: `.claude/skills/apkid-scan/SKILL.md`
- Create: `.claude/skills/apkid-scan/references/output-format.md`
- Create: `.claude/skills/apkid-scan/references/detection-tags.md`

- [ ] **Step 1: 创建 apkid-scan Skill 定义 — 主扫描 skill 的 SKILL.md**

```markdown
---
name: apkid-scan
description: Scan Android APK/DEX/ELF files for packer, signer, compiler, and protector identifiers using AI-APKiD
triggers:
  - scan apk
  - analyze apk
  - identify packer
  - check apk protection
  - detect obfuscator
---

# APKiD Scan

Scan Android APK, DEX, or ELF files to identify packers, signers, compilers, obfuscators, and protectors.

## When to Use

- When you need to identify what packer/protector/obfuscator an Android APK uses
- When analyzing an APK for security assessment or reverse engineering
- When checking if an APK uses anti-debugging or anti-VM techniques
- When identifying the signing certificate of an APK

## Instructions

1. Verify the target file exists using the Read tool or `ls` command
2. Run the scan command below with the target file path
3. Parse the JSON output to present findings to the user
4. If errors occur, check stderr for the error JSON payload

## Commands

### Scan a single file

\`\`\`bash
ai-apkid scan <file_path>
\`\`\`

### Scan with text output (human-readable)

\`\`\`bash
ai-apkid scan <file_path> --format text
\`\`\`

### Scan and save to file

\`\`\`bash
ai-apkid scan <file_path> --output results.json
\`\`\`

## Output Format

The default output is JSON with this structure:

\`\`\`json
{
  "error": false,
  "target": "/path/to/app.apk",
  "findings": [
    {
      "tag": "packer::bangcle",
      "category": "packer",
      "description": "Detects APK packing/obfuscation tools",
      "source": "classes.dex",
      "identifier": "packer::bangcle"
    }
  ],
  "summary": {
    "total_findings": 1,
    "categories": {
      "packer": 1
    }
  },
  "scanned_at": "2025-01-01T00:00:00+00:00"
}
\`\`\`

Error output (on stderr):

\`\`\`json
{
  "error": true,
  "message": "File not found",
  "type": "FileNotFoundError",
  "target": "/path/to/missing.apk"
}
\`\`\`

## Detection Categories

| Category | Description |
|----------|-------------|
| packer | APK packing/obfuscation tools (Bangcle, 360, Tencent Legu, etc.) |
| protector | App protection/shielding SDKs |
| obfuscator | Code obfuscation tools (ProGuard, DexGuard, etc.) |
| signer | APK signing certificates and signers |
| compiler | Compiler or build tool fingerprints |
| anti_vm | Anti-VM/anti-emulator techniques |
| anti_debug | Anti-debugging techniques |
| abnormal | Abnormal or suspicious modifications |
| hook | Hooking frameworks (Xposed, Frida) |
| root | Root detection or root-related libraries |

## Examples

### Scan an APK file

User: "Scan this APK for packers"
Action: Run `ai-apkid scan /path/to/app.apk`
Then: Report the findings, highlighting packer and protector categories

### Check for anti-debug techniques

User: "Does this APK use anti-debugging?"
Action: Run `ai-apkid scan /path/to/app.apk`
Then: Filter findings for category "anti_debug" and report

## Notes

- The `ai-apkid` command must be installed (`pip install apkid`)
- Supports APK, DEX, and ELF file formats
- Default timeout is 60 seconds, use `--timeout` for larger files
- All output is UTF-8 encoded
```

- [ ] **Step 2: 创建 output-format 参考文档 — 详细说明 JSON 输出结构**

```markdown
# APKiD AI Output Format Reference

## JSON Schema

### Top-Level Object

| Field | Type | Description |
|-------|------|-------------|
| error | boolean | `false` on success, `true` on failure |
| target | string | Path to the scanned file |
| findings | array | List of detection findings |
| summary | object | Aggregated summary of findings |
| scanned_at | string | ISO 8601 timestamp of when the scan completed |

### Finding Object

| Field | Type | Description |
|-------|------|-------------|
| tag | string | Full detection tag (e.g., "packer::bangcle") |
| category | string | Detection category (e.g., "packer") |
| description | string | Human-readable category description |
| source | string | Source file within the APK (e.g., "classes.dex") |
| identifier | string | Same as tag, for compatibility |

### Summary Object

| Field | Type | Description |
|-------|------|-------------|
| total_findings | integer | Total number of findings |
| categories | object | Map of category name to count |

### Error Object (on stderr)

| Field | Type | Description |
|-------|------|-------------|
| error | boolean | Always `true` |
| message | string | Error description |
| type | string | Python exception class name |
| target | string | Path to the target file (if applicable) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully |
| 1 | Scan failed (see stderr for error JSON) |
```

- [ ] **Step 3: 创建 detection-tags 参考文档 — 列出所有检测标签**

```markdown
# APKiD Detection Tags Reference

## Category: packer

| Tag | Description |
|-----|-------------|
| packer::bangcle | Bangcle (梆梆) packer |
| packer::360 | 360 Jiagu (360加固) |
| packer::tencent_legu | Tencent Legu (腾讯乐固) |
| packer::baidu | Baidu Jiagu (百度加固) |
| packer::aliprotect | Alibaba AliProtect |
| packer::ijiami | ijiami (爱加密) |
| packer::qihoo | Qihoo 360 |
| packer::secneo | Secneo |
| packer::tencent | Tencent |
| packer::naga | Naga protector |
| packer::appdome | Appdome |

## Category: protector

| Tag | Description |
|-----|-------------|
| protector::haiyun | Haiyun protector (海云安) |
| protector::oppo | OPPO Protect SDK |

## Category: obfuscator

| Tag | Description |
|-----|-------------|
| obfuscator::proguard | ProGuard obfuscation |
| obfuscator::dexguard | DexGuard obfuscation |

## Category: signer

| Tag | Description |
|-----|-------------|
| signer::dev | Debug/development signing certificate |
| signer::release | Release signing certificate |

## Category: compiler

| Tag | Description |
|-----|-------------|
| compiler::dx | Android dx compiler |
| compiler::d8 | Android D8 compiler |
| compiler::kotlin | Kotlin compiler |

## Category: anti_vm

| Tag | Description |
|-----|-------------|
| anti_vm::build | Build fingerprint checks |
| anti_vm::device | Device model checks |
| anti_vm::sim | SIM card checks |

## Category: anti_debug

| Tag | Description |
|-----|-------------|
| anti_debug::ptrace | ptrace-based detection |
| anti_debug::debugger | Debugger detection |

## Category: hook

| Tag | Description |
|-----|-------------|
| hook::xposed | Xposed framework |
| hook::frida | Frida dynamic instrumentation |

## Category: root

| Tag | Description |
|-----|-------------|
| root::magisk | Magisk root |
| root::supersu | SuperSU |

Note: This is a non-exhaustive list. Run `ai-apkid list-tags` for the complete set.
```

- [ ] **Step 4: 验证 Skill 文件结构**
Run: `find /Users/cc11001100/github/android-reverse-hub/AI-APKiD/.claude/skills/apkid-scan -type f`
Expected:
  - Exit code: 0
  - Output contains: "SKILL.md" and "output-format.md" and "detection-tags.md"

- [ ] **Step 5: 提交**
Run: `git add .claude/skills/apkid-scan/ && git commit -m "feat(skills): add apkid-scan skill definition with references"`

---

### Task 4: Batch Scan and Rule Dev Skills

**Depends on:** Task 3
**Files:**
- Create: `.claude/skills/apkid-batch/SKILL.md`
- Create: `.claude/skills/apkid-rule-dev/SKILL.md`

- [ ] **Step 1: 创建 apkid-batch Skill 定义 — 批量扫描目录中的 APK 文件**

```markdown
---
name: apkid-batch
description: Batch scan directories of Android APK/DEX/ELF files for packer and protector identifiers
triggers:
  - batch scan
  - scan directory
  - scan multiple apk
  - bulk analyze
---

# APKiD Batch Scan

Batch scan directories of Android APK, DEX, or ELF files to identify packers, signers, compilers, obfuscators, and protectors.

## When to Use

- When you need to scan multiple APK files in a directory
- When comparing protection across a collection of APKs
- When building an inventory of app protection methods

## Instructions

1. Verify the target directory exists using `ls`
2. Run the batch scan command below
3. Parse the JSON output to present aggregated findings
4. Use `--recursive` flag to scan subdirectories

## Commands

### Batch scan a directory

\`\`\`bash
ai-apkid batch <directory_path>
\`\`\`

### Recursive scan with custom pattern

\`\`\`bash
ai-apkid batch <directory_path> --recursive --pattern "*.apk"
\`\`\`

### Save batch results to file

\`\`\`bash
ai-apkid batch <directory_path> --output batch_results.json
\`\`\`

## Output Format

\`\`\`json
{
  "error": false,
  "scanned": 3,
  "results": [
    {
      "error": false,
      "target": "/path/to/app1.apk",
      "findings": [...],
      "summary": {...}
    },
    {
      "error": false,
      "target": "/path/to/app2.apk",
      "findings": [...],
      "summary": {...}
    }
  ]
}
\`\`\`

## Examples

### Scan all APKs in a directory

User: "Scan all APKs in /data/samples/"
Action: Run `ai-apkid batch /data/samples/`
Then: Present a summary table showing each APK and its detected packers/protectors

### Find all APKs using a specific packer

User: "Which APKs use Bangcle packer?"
Action: Run `ai-apkid batch /data/samples/ -r`
Then: Filter results for findings with tag "packer::bangcle" and list matching APKs

## Notes

- Default pattern is `*.apk`, use `--pattern` for DEX or ELF files
- Large directories may take time; use `--output` to save results
- Each file is scanned independently; one failure does not stop the batch
```

- [ ] **Step 2: 创建 apkid-rule-dev Skill 定义 — 辅助开发 YARA 规则**

```markdown
---
name: apkid-rule-dev
description: Develop and test YARA rules for AI-APKiD to detect new packers, protectors, and obfuscators
triggers:
  - write yara rule
  - create detection rule
  - add packer rule
  - new detector
  - apkid rule
---

# APKiD Rule Development

Develop and test YARA rules for AI-APKiD to detect new packers, protectors, obfuscators, and other identifiers.

## When to Use

- When you need to add detection for a new packer or protector
- When updating existing rules for a new version of a known tool
- When testing custom YARA rules against sample files

## Instructions

1. Understand the existing rule structure by reading the rules directory
2. Create a new YARA rule following the naming convention and format
3. Test the rule against known sample files
4. Verify the rule does not produce false positives

## Rule File Structure

Rules are located in `apkid/rules/` as `.yarc` (YARA) files.

### Naming Convention

- File name: `<category>_<tool_name>.yarc`
- Rule name: `<category>_<tool_name>`
- Example: `packer_bangcle.yarc` with rule `packer_bangcle`

### Rule Template

\`\`\`yara
rule <category>_<tool_name> : <category> {
  meta:
    description = "Detects <Tool Name> <category>"
    author = "<your name>"
    date = "<YYYY-MM-DD>"
  strings:
    $s1 = "<unique string or pattern>" ascii wide
    $s2 = "<another pattern>" ascii wide
  condition:
    any of them
}
\`\`\`

### Category Values

Use one of: `packer`, `protector`, `obfuscator`, `signer`, `compiler`, `anti_vm`, `anti_debug`, `abnormal`, `hook`, `root`

## Commands

### List all existing detection tags

\`\`\`bash
ai-apkid list-tags
\`\`\`

### Test a new rule against a sample

\`\`\`bash
ai-apkid scan <sample_file>
\`\`\`

## Workflow

1. Run `ai-apkid list-tags` to check if a similar rule already exists
2. Read existing rules in `apkid/rules/` for format reference
3. Create new `.yarc` file in `apkid/rules/`
4. Run `ai-apkid scan <sample>` to verify detection
5. Test against clean samples to check for false positives

## Examples

### Add detection for a new packer

User: "Add a rule to detect NewPacker"
Action:
1. Check `ai-apkid list-tags` for existing "newpacker" entries
2. Read `apkid/rules/packer_bangcle.yarc` as a format reference
3. Create `apkid/rules/packer_newpacker.yarc` with appropriate strings
4. Test with `ai-apkid scan <sample_using_newpacker>`

## Notes

- Rules must compile with YARA-X (the engine used by AI-APKiD)
- Use `ascii wide` for strings that may appear in either encoding
- Keep rules specific to avoid false positives
- Add a description in the meta section
```

- [ ] **Step 3: 验证所有 Skill 文件**
Run: `find /Users/cc11001100/github/android-reverse-hub/AI-APKiD/.claude/skills -name "SKILL.md" | sort`
Expected:
  - Exit code: 0
  - Output contains: "apkid-batch/SKILL.md" and "apkid-rule-dev/SKILL.md" and "apkid-scan/SKILL.md"

- [ ] **Step 4: 提交**
Run: `git add .claude/skills/apkid-batch/ .claude/skills/apkid-rule-dev/ && git commit -m "feat(skills): add batch scan and rule development skills"`

---

### Task 5: Plugin Registration and Repository README

**Depends on:** Task 4
**Files:**
- Create: `.claude/plugins/ai-apkid.js`
- Modify: `README.md` (添加 Skills 安装说明)

- [ ] **Step 1: 创建插件注册文件 — 让 Claude Code 发现和加载 skills**

```javascript
// .claude/plugins/ai-apkid.js
const plugin = {
  name: "ai-apkid",
  description: "Android APK/DEX/ELF identifier for AI agents - detect packers, protectors, obfuscators, and more",
  version: "3.1.0",
  skills: [
    {
      name: "apkid-scan",
      path: "skills/apkid-scan/SKILL.md",
      description: "Scan Android APK/DEX/ELF files for packer, signer, compiler, and protector identifiers"
    },
    {
      name: "apkid-batch",
      path: "skills/apkid-batch/SKILL.md",
      description: "Batch scan directories of Android APK/DEX/ELF files"
    },
    {
      name: "apkid-rule-dev",
      path: "skills/apkid-rule-dev/SKILL.md",
      description: "Develop and test YARA rules for AI-APKiD"
    }
  ]
};

module.exports = plugin;
```

- [ ] **Step 2: 更新 README.md — 添加 Skills 仓库安装说明**
文件: `README.md`（在现有内容末尾追加）

在 README.md 末尾追加以下内容：

```markdown
---

## Claude Code Skills

This repository is also a **Claude Code Skills** package. Install it to add APKiD scanning capabilities to your Claude Code agent.

### Install

```bash
# Add as a skills source
claude skills add --source https://github.com/rednaga/AI-APKiD

# Or install locally
claude skills add --source /path/to/AI-APKiD
```

### Available Skills

| Skill | Command | Description |
|-------|---------|-------------|
| `apkid-scan` | `/apkid-scan` | Scan a single APK/DEX/ELF file |
| `apkid-batch` | `/apkid-batch` | Batch scan a directory of files |
| `apkid-rule-dev` | `/apkid-rule-dev` | Develop new YARA detection rules |

### AI CLI

The `ai-apkid` command provides structured JSON output designed for AI agent consumption:

```bash
# Scan a file (JSON output)
ai-apkid scan /path/to/app.apk

# Batch scan a directory
ai-apkid batch /path/to/samples/ --recursive

# List all detection tags
ai-apkid list-tags
```

### For Skill Developers

Skills are defined in `.claude/skills/` using SKILL.md files with YAML frontmatter. See the [Claude Code Skills documentation](https://docs.anthropic.com/en/docs/claude-code/skills) for details.
```

- [ ] **Step 3: 验证插件和 README**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && node -e "const p = require('./.claude/plugins/ai-apkid.js'); console.log(p.name, p.skills.length + ' skills')"`
Expected:
  - Exit code: 0
  - Output contains: "ai-apkid 3 skills"

- [ ] **Step 4: 提交**
Run: `git add .claude/plugins/ai-apkid.js README.md && git commit -m "feat(skills): add plugin registration and update README with Skills installation guide"`
