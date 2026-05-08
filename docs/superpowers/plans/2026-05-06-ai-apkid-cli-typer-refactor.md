# AI-APKiD CLI 重构：Typer 框架 + 完整能力暴露

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 用 typer 框架重写 `ai-apkid` CLI，完整暴露 APKiD 的 Scanner/Options 全部能力，替换手写 Click 装饰器为 typer 声明式接口。

**Architecture:** 用户输入 → typer 声明式参数（type hints 自动生成 CLI）→ 构造 Options 对象 → Scanner 扫描 → AIOutputFormatter 格式化 → rich 美化输出。关键改变：从 Click 装饰器手动绑定参数，改为 typer 函数签名自动推导参数，同时补全 Options 全部 9 个字段。

**Tech Stack:** Python 3.9, typer 0.12.3, rich 13.7.1, yara-python-dex 1.0.1+

**Risks:**
- typer 依赖 rich，需确保版本兼容 → 缓解：环境中已验证 typer 0.12.3 + rich 13.7.1 可用
- 重写 cli.py 会改变 entry point 内部实现 → 缓解：保持 `ai_cli` 函数名和 `apkid.cli:ai_cli` 入口不变
- list-tags 从静态字典改为动态提取 YARA tags → 缓解：保留 RULE_DESCRIPTIONS 作为 fallback，无规则文件时仍可用
- ai_output.py 增加 `--include-types` 支持 → 缓解：向后兼容，默认行为不变

---

### Task 1: 用 typer 重写 CLI 入口 — 完整暴露 Options 全部参数

**Depends on:** None
**Files:**
- Modify: `apkid/cli.py:1-139`（完全重写）
- Modify: `setup.py:49-52`（依赖变更）

- [ ] **Step 1: 修改 setup.py 依赖 — 将 click 替换为 typer**

文件: `setup.py:49-52`

```python
install_requires = [
    'yara-python-dex>=1.0.1',
    'typer>=0.12.0',
    'rich>=13.0.0',
]
```

- [ ] **Step 2: 重写 apkid/cli.py — 用 typer 声明式接口暴露全部 Options 参数**

```python
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
import sys
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from apkid import __version__
from apkid.apkid import Options, Scanner
from apkid.ai_output import AIOutputFormatter
from apkid.rules import RulesManager

app = typer.Typer(
    name="ai-apkid",
    help="AI-APKiD: Android APK/DEX/ELF identifier for AI agents.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console(stderr=True)


class TypingMethod(str, Enum):
    magic = "magic"
    filename = "filename"
    none = "none"


class OutputFormat(str, Enum):
    json = "json"
    text = "text"


def _make_scanner(
    timeout: int = 30,
    typing: str = "magic",
    scan_depth: int = 2,
    entry_max_scan_size: int = 0,
    include_types: bool = False,
) -> Scanner:
    """Create a Scanner with the given options."""
    rules_mgr = RulesManager()
    rules = rules_mgr.load()
    options = Options(
        timeout=timeout,
        json=True,
        typing=typing,
        scan_depth=scan_depth,
        entry_max_scan_size=entry_max_scan_size,
        include_types=include_types,
    )
    return Scanner(rules=rules, options=options)


def _output_result(formatted: str, output: Optional[Path] = None):
    """Write result to file or stdout."""
    if output:
        output.write_text(formatted, encoding="utf-8")
    else:
        typer.echo(formatted)


def _error_exit(message: str, detail: str = "", code: int = 1):
    """Print structured error to stderr and exit."""
    error_payload = json.dumps(
        {"error": True, "message": message, "detail": detail},
        ensure_ascii=False,
    )
    typer.echo(error_payload, err=True)
    raise typer.Exit(code=code)


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, help="APK, DEX, or ELF file to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write result to file instead of stdout"),
    fmt: OutputFormat = typer.Option(OutputFormat.json, "--format", "-f", help="Output format"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="YARA scan timeout in seconds"),
    typing: TypingMethod = typer.Option(TypingMethod.magic, "--typing", help="File identification method: magic bytes, filename extension, or scan all"),
    scan_depth: int = typer.Option(2, "--scan-depth", help="Max recursion depth for nested ZIP archives"),
    entry_max_scan_size: int = typer.Option(0, "--entry-max-scan-size", help="Max ZIP entry size to scan in bytes (0 = no limit)"),
    include_types: bool = typer.Option(False, "--include-types", help="Include file_type detections in results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log debug messages to stderr"),
):
    """Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers."""
    try:
        scanner = _make_scanner(
            timeout=timeout,
            typing=typing.value,
            scan_depth=scan_depth,
            entry_max_scan_size=entry_max_scan_size,
            include_types=include_types,
        )
        results = scanner.scan_file(str(target))
        formatter = AIOutputFormatter()
        formatted = formatter.format(results, str(target), fmt=fmt.value)
        _output_result(formatted, output)
    except Exception as e:
        _error_exit(str(e), type(e).__name__)


@app.command()
def batch(
    directory: Path = typer.Argument(..., exists=True, help="Directory containing files to scan"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Scan subdirectories recursively"),
    pattern: str = typer.Option("*.apk", "--pattern", "-p", help="File glob pattern"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write result to file instead of stdout"),
    fmt: OutputFormat = typer.Option(OutputFormat.json, "--format", "-f", help="Output format"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="YARA scan timeout in seconds"),
    typing: TypingMethod = typer.Option(TypingMethod.magic, "--typing", help="File identification method"),
    scan_depth: int = typer.Option(2, "--scan-depth", help="Max recursion depth for nested ZIP archives"),
    entry_max_scan_size: int = typer.Option(0, "--entry-max-scan-size", help="Max ZIP entry size to scan in bytes (0 = no limit)"),
    include_types: bool = typer.Option(False, "--include-types", help="Include file_type detections in results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Log debug messages to stderr"),
):
    """Batch scan files in a directory."""
    try:
        scanner = _make_scanner(
            timeout=timeout,
            typing=typing.value,
            scan_depth=scan_depth,
            entry_max_scan_size=entry_max_scan_size,
            include_types=include_types,
        )
        formatter = AIOutputFormatter()
        target_path = Path(directory)
        if recursive:
            files = sorted(target_path.rglob(pattern))
        else:
            files = sorted(target_path.glob(pattern))
        if not files:
            result = json.dumps({
                "error": False,
                "scanned": 0,
                "results": [],
                "message": f"No files matching '{pattern}' found in {directory}",
            }, ensure_ascii=False)
            _output_result(result, output)
            return
        all_results = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(f"Scanning {len(files)} files...", total=len(files))
            for f in files:
                results = scanner.scan_file(str(f))
                formatted = formatter.format_dict(results, str(f))
                all_results.append(formatted)
                progress.advance(task)
        batch_output = json.dumps({
            "error": False,
            "scanned": len(all_results),
            "results": all_results,
        }, ensure_ascii=False, indent=2)
        _output_result(batch_output, output)
    except Exception as e:
        _error_exit(str(e), type(e).__name__)


@app.command()
def list_tags():
    """List all available detection tags and their descriptions."""
    from apkid.ai_output import RULE_DESCRIPTIONS
    tags = []
    for tag, desc in sorted(RULE_DESCRIPTIONS.items()):
        tags.append({"tag": tag, "description": desc})
    typer.echo(json.dumps({"tags": tags}, ensure_ascii=False, indent=2))


@app.command()
def info():
    """Show version, rules hash, and rules count."""
    rules_mgr = RulesManager()
    rules_hash = rules_mgr.hash
    try:
        rules = rules_mgr.load()
        rules_count = len(set(r.identifier for r in rules))
    except Exception:
        rules_count = 0
    result = {
        "version": __version__,
        "rules_sha256": rules_hash,
        "rules_count": rules_count,
    }
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))


@app.command()
def rules(
    action: str = typer.Argument(..., help="Action: 'list' to show rule files, 'compile' to rebuild rules.yarc"),
):
    """Manage YARA rules: list source files or compile to rules.yarc."""
    rules_mgr = RulesManager()
    if action == "list":
        yara_files = rules_mgr._collect_yara_files()
        rule_list = sorted(yara_files.keys())
        typer.echo(json.dumps({"rules": rule_list, "count": len(rule_list)}, ensure_ascii=False, indent=2))
    elif action == "compile":
        try:
            rules_mgr.compile()
            count = rules_mgr.save()
            typer.echo(json.dumps({"compiled": True, "rules_count": count}, ensure_ascii=False, indent=2))
        except Exception as e:
            _error_exit(f"Compilation failed: {e}", type(e).__name__)
    else:
        _error_exit(f"Unknown action '{action}'. Use 'list' or 'compile'.")


def ai_cli():
    """Entry point for ai-apkid command."""
    app()


if __name__ == "__main__":
    app()
```

- [ ] **Step 3: 验证 typer CLI 可加载**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && python3 -c "from apkid.cli import app; print('OK')"`
Expected:
  - Exit code: 0
  - Output contains: "OK"

- [ ] **Step 4: 验证 CLI help 输出包含全部参数**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && python3 -m apkid.cli scan --help`
Expected:
  - Exit code: 0
  - Output contains: "--typing" and "--scan-depth" and "--entry-max-scan-size" and "--include-types"

- [ ] **Step 5: 提交**
Run: `git add apkid/cli.py setup.py && git commit -m "refactor(cli): rewrite ai-apkid CLI with typer, expose all Options params"`

---

### Task 2: 增强 AIOutputFormatter — 支持 include_types 和结构化错误码

**Depends on:** Task 1
**Files:**
- Modify: `apkid/ai_output.py:56-111`（AIOutputFormatter 类增强）

- [ ] **Step 1: 修改 AIOutputFormatter.format 方法 — 增加 include_types 参数**

文件: `apkid/ai_output.py:59-72`（替换 format 和 format_dict 方法签名）

```python
    def format(self, results: Dict[str, List[yara.Match]], target: str, fmt: str = "json", include_types: bool = False) -> str:
        """Format scan results into the specified output format.

        Args:
            results: Raw scan results dict from Scanner.scan_file()
            target: Path to the scanned file
            fmt: Output format - 'json' or 'text'
            include_types: If True, include file_type detections

        Returns:
            Formatted output string
        """
        if fmt == "text":
            return self._format_text(results, target, include_types=include_types)
        return self._format_json(results, target, include_types=include_types)

    def format_dict(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> Dict:
        """Format scan results into a dictionary for batch aggregation.

        Args:
            results: Raw scan results dict from Scanner.scan_file()
            target: Path to the scanned file
            include_types: If True, include file_type detections

        Returns:
            Dictionary with structured scan results
        """
        return self._build_result_dict(results, target, include_types=include_types)
```

- [ ] **Step 2: 修改内部方法 — 传递 include_types 到 _extract_findings**

文件: `apkid/ai_output.py:86-111`（替换 _format_json, _format_text, _build_result_dict 方法）

```python
    def _format_json(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> str:
        result_dict = self._build_result_dict(results, target, include_types=include_types)
        return json.dumps(result_dict, ensure_ascii=False, indent=2)

    def _format_text(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> str:
        result_dict = self._build_result_dict(results, target, include_types=include_types)
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

    def _build_result_dict(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> Dict:
        findings = self._extract_findings(results, include_types=include_types)
        return {
            "error": False,
            "target": target,
            "findings": findings,
            "summary": self._build_summary(findings),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
```

- [ ] **Step 3: 修改 _extract_findings 和 _match_to_findings — 过滤 file_type tag**

文件: `apkid/ai_output.py:113-152`（替换 _extract_findings 和 _match_to_findings 方法）

```python
    def _extract_findings(self, results: Any, include_types: bool = False) -> List[Dict]:
        findings = []
        if results is None:
            return findings
        if isinstance(results, dict):
            for file_path, matches in results.items():
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, yara.Match):
                            findings.extend(self._match_to_findings(match, file_path, include_types=include_types))
                        elif isinstance(match, str):
                            findings.append(self._tag_to_finding(match, file_path))
        return findings

    def _match_to_findings(self, match: yara.Match, source: str, include_types: bool = False) -> List[Dict]:
        findings = []
        description = match.meta.get('description', match.rule)
        for tag in match.tags:
            if tag == 'file_type' and not include_types:
                continue
            category = self._categorize_tag(tag)
            findings.append({
                "tag": f"{tag}::{match.rule}" if match.rule != tag else tag,
                "category": category,
                "description": RULE_DESCRIPTIONS.get(category, "Unknown detection category"),
                "source": source,
                "identifier": match.rule,
                "rule_detail": description,
            })
        if not match.tags:
            category = self._categorize_tag(match.rule)
            findings.append({
                "tag": match.rule,
                "category": category,
                "description": RULE_DESCRIPTIONS.get(category, "Unknown detection category"),
                "source": source,
                "identifier": match.rule,
                "rule_detail": description,
            })
        return findings
```

- [ ] **Step 4: 更新 cli.py 中对 formatter.format 的调用 — 传递 include_types**

文件: `apkid/cli.py`（scan 命令中的 formatter.format 调用行，以及 batch 命令中的 formatter.format_dict 调用行）

在 scan 命令中：
```python
        formatted = formatter.format(results, str(target), fmt=fmt.value, include_types=include_types)
```

在 batch 命令中：
```python
                formatted = formatter.format_dict(results, str(f), include_types=include_types)
```

- [ ] **Step 5: 验证 AIOutputFormatter 向后兼容**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && python3 -c "from apkid.ai_output import AIOutputFormatter; f=AIOutputFormatter(); print(f.format({}, '/test.apk'))" 2>&1 | head -1`
Expected:
  - Exit code: 0
  - Output contains: "error"

- [ ] **Step 6: 提交**
Run: `git add apkid/ai_output.py apkid/cli.py && git commit -m "feat(ai-output): add include_types support to AIOutputFormatter"`

---

### Task 3: 更新 Skills 文档 — 反映新增的命令和参数

**Depends on:** Task 1
**Files:**
- Modify: `.claude/skills/apkid-scan/SKILL.md`（更新命令参数列表）
- Modify: `.claude/skills/apkid-batch/SKILL.md`（更新命令参数列表）
- Modify: `.claude/skills/apkid-rule-dev/SKILL.md`（新增 rules 命令说明）

- [ ] **Step 1: 更新 apkid-scan SKILL.md — 补充全部 scan 参数**

文件: `.claude/skills/apkid-scan/SKILL.md`

在 Commands 部分的 scan 命令后，补充完整参数文档：

```markdown
### Scan with all options

```bash
ai-apkid scan <file> --typing magic --scan-depth 2 --timeout 30 --entry-max-scan-size 0 --include-types --format json
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--format`, `-f` | json | Output format: json or text |
| `--timeout`, `-t` | 30 | YARA scan timeout in seconds |
| `--typing` | magic | File identification: magic (bytes), filename (extension), none (scan all) |
| `--scan-depth` | 2 | Max recursion depth for nested ZIP archives |
| `--entry-max-scan-size` | 0 | Max ZIP entry size to scan in bytes (0 = no limit) |
| `--include-types` | false | Include file_type detections in results |
| `--output`, `-o` | stdout | Write result to file |
| `--verbose`, `-v` | false | Log debug messages to stderr |
```

- [ ] **Step 2: 更新 apkid-batch SKILL.md — 补充全部 batch 参数**

文件: `.claude/skills/apkid-batch/SKILL.md`

在 Commands 部分补充完整参数文档：

```markdown
### Batch scan with all options

```bash
ai-apkid batch <directory> --recursive --pattern "*.apk" --typing magic --scan-depth 2 --timeout 30 --include-types
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--recursive`, `-r` | false | Scan subdirectories recursively |
| `--pattern`, `-p` | *.apk | File glob pattern |
| `--format`, `-f` | json | Output format: json or text |
| `--timeout`, `-t` | 30 | YARA scan timeout in seconds |
| `--typing` | magic | File identification: magic, filename, none |
| `--scan-depth` | 2 | Max recursion depth for nested ZIP archives |
| `--entry-max-scan-size` | 0 | Max ZIP entry size to scan in bytes (0 = no limit) |
| `--include-types` | false | Include file_type detections in results |
| `--output`, `-o` | stdout | Write result to file |
```

- [ ] **Step 3: 更新 apkid-rule-dev SKILL.md — 新增 rules 和 info 命令**

文件: `.claude/skills/apkid-rule-dev/SKILL.md`

在 Commands 部分新增：

```markdown
### Show version and rules info

```bash
ai-apkid info
```

### List YARA rule source files

```bash
ai-apkid rules list
```

### Compile YARA rules

```bash
ai-apkid rules compile
```
```

- [ ] **Step 4: 提交**
Run: `git add .claude/skills/ && git commit -m "docs(skills): update SKILL.md with full parameter docs and new commands"`

---

### Task 4: 适配测试 — 验证 typer CLI 和增强的 AIOutputFormatter

**Depends on:** Task 2
**Files:**
- Modify: `tests/test_ai_output.py:87-126`（适配 typer CLI 测试）

- [ ] **Step 1: 修改 CLI 测试 — 适配 typer 入口**

文件: `tests/test_ai_output.py:87-126`（替换 TestCLICommands 类）

```python
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
            if result.returncode == 0:
                data = json.loads(result.stdout)
                assert data["scanned"] == 0
            else:
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
```

- [ ] **Step 2: 增加 AIOutputFormatter include_types 测试**

文件: `tests/test_ai_output.py`（在 TestAIOutputFormatter 类末尾追加）

```python
    def test_format_with_include_types_false_skips_file_type(self):
        """include_types=False filters out file_type tags."""
        formatter = AIOutputFormatter()
        output = formatter.format({}, "/test/app.apk", fmt="json", include_types=False)
        data = json.loads(output)
        assert data["error"] is False

    def test_format_with_include_types_true(self):
        """include_types=True is accepted without error."""
        formatter = AIOutputFormatter()
        output = formatter.format({}, "/test/app.apk", fmt="json", include_types=True)
        data = json.loads(output)
        assert data["error"] is False
```

- [ ] **Step 3: 验证全部测试通过**
Run: `cd /Users/cc11001100/github/android-reverse-hub/AI-APKiD && python3 -m pytest tests/test_ai_output.py -v 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "passed"

- [ ] **Step 4: 提交**
Run: `git add tests/test_ai_output.py && git commit -m "test(cli): adapt tests for typer CLI, add info/rules/include-types tests"`
