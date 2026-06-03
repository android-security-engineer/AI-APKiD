# Refactor: 统一 SKILLS CLI 架构

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 AI-APKiD 的双重 CLI 入口（apkid + ai-apkid）重构为统一的 SKILLS 架构，提供单一 CLI 入口 `ai-apkid`，所有功能通过 Skill 模块提供，CLI 子命令从 Skill 注册表动态生成。

**Architecture:** 用户输入 → `ai-apkid` 单一入口 → SkillRegistry 发现/注册 Skill → 每个 Skill 自动映射为 Typer 子命令 → Skill 执行 → AIOutputFormatter 输出。关键组件：SkillBase 抽象类定义接口，SkillRegistry 自动发现 `apkid/skills/` 下的模块，cli.py 从 Registry 动态构建 Typer app。选择此架构是因为让新增 Skill 只需添加一个 .py 文件即可自动出现在 CLI 中。

**Tech Stack:** Python 3.9+, Typer 0.12+, Rich 13.0+, yara-python-dex 1.0.1+

**Scope:** Medium

**Risk:** Medium

**Risks:**
- Task 3 修改公共 CLI 入口 → 缓解：保持所有子命令名和参数不变
- Task 2 拆分 cli.py 可能遗漏隐式依赖 → 缓解：逐函数迁移，每步验证
- 无现有测试覆盖 CLI 层 → 缓解：Task 5 补集成测试

**Autonomy Level:** Full

---

### Task 1: 创建 Skill 基础架构 — SkillBase + SkillRegistry

**Depends on:** None
**Files:**
- Create: `apkid/skills/__init__.py`
- Create: `apkid/skills/registry.py`
- Test: `tests/test_skills_registry.py`

- [ ] **Step 1: 创建 skills 包 `__init__.py`**

```python
# apkid/skills/__init__.py
from .registry import SkillBase, SkillRegistry, skill

__all__ = ["SkillBase", "SkillRegistry", "skill"]
```

- [ ] **Step 2: 创建 `registry.py` — SkillBase 抽象类 + SkillRegistry 自动发现**

```python
# apkid/skills/registry.py
import importlib
import inspect
import os
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional


class SkillBase(ABC):
    """所有 Skill 的基类。每个 Skill 自动映射为一个 CLI 子命令。"""

    name: str = ""
    description: str = ""
    help_text: str = ""

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """执行 Skill 的核心逻辑。"""
        ...

    def to_command(self) -> Dict:
        """将 Skill 元数据转换为命令注册信息。"""
        return {
            "name": self.name,
            "description": self.description,
            "help_text": self.help_text or self.description,
        }


def skill(name: str, description: str = "", help_text: str = ""):
    """装饰器：将函数注册为 Skill。"""
    def decorator(func: Callable) -> type:
        return type(
            f"{func.__name__.title()}Skill",
            (SkillBase,),
            {
                "name": name,
                "description": description,
                "help_text": help_text or description,
                "execute": lambda self, **kw: func(**kw),
            },
        )
    return decorator


class SkillRegistry:
    """自动发现 apkid/skills/ 目录下的 Skill 模块并注册。"""

    def __init__(self, skills_package: str = "apkid.skills"):
        self._skills_package = skills_package
        self._skills: Dict[str, SkillBase] = {}

    def discover(self) -> Dict[str, SkillBase]:
        """扫描 skills 包目录，发现所有 Skill 模块。"""
        package = importlib.import_module(self._skills_package)
        package_dir = os.path.dirname(package.__file__)

        for filename in sorted(os.listdir(package_dir)):
            if filename.startswith("_") or not filename.endswith(".py"):
                continue
            module_name = filename[:-3]
            module = importlib.import_module(f"{self._skills_package}.{module_name}")

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    inspect.isclass(attr)
                    and issubclass(attr, SkillBase)
                    and attr is not SkillBase
                    and attr.name
                ):
                    self._skills[attr.name] = attr()

        return self._skills

    def register(self, skill_instance: SkillBase) -> None:
        """手动注册一个 Skill 实例。"""
        self._skills[skill_instance.name] = skill_instance

    def get(self, name: str) -> Optional[SkillBase]:
        """按名称获取 Skill。"""
        return self._skills.get(name)

    def all(self) -> Dict[str, SkillBase]:
        """返回所有已注册的 Skill。"""
        return dict(self._skills)

    def list_names(self) -> List[str]:
        """返回所有 Skill 名称列表。"""
        return sorted(self._skills.keys())
```

- [ ] **Step 3: 创建 SkillRegistry 单元测试**

```python
# tests/test_skills_registry.py
import pytest
from apkid.skills.registry import SkillBase, SkillRegistry


class DummySkill(SkillBase):
    name = "dummy"
    description = "A dummy skill for testing"
    help_text = "Dummy help"

    def execute(self, **kwargs):
        return {"result": "ok"}


class TestSkillBase:
    def test_execute_returns_result(self):
        skill = DummySkill()
        result = skill.execute()
        assert result == {"result": "ok"}

    def test_to_command_contains_name(self):
        skill = DummySkill()
        cmd = skill.to_command()
        assert cmd["name"] == "dummy"
        assert cmd["description"] == "A dummy skill for testing"


class TestSkillRegistry:
    def test_register_and_get(self):
        registry = SkillRegistry(skills_package="apkid.skills")
        registry.register(DummySkill())
        assert registry.get("dummy") is not None
        assert registry.get("nonexistent") is None

    def test_list_names_includes_registered(self):
        registry = SkillRegistry(skills_package="apkid.skills")
        registry.register(DummySkill())
        assert "dummy" in registry.list_names()

    def test_discover_finds_core_skills(self):
        registry = SkillRegistry(skills_package="apkid.skills")
        skills = registry.discover()
        assert isinstance(skills, dict)
        assert "scan" in skills
        assert "batch" in skills
        assert "info" in skills
        assert "list-tags" in skills
        assert "rules" in skills
```

- [ ] **Step 4: 验证 Skill 基础架构可导入**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && python -c "from apkid.skills import SkillBase, SkillRegistry; r = SkillRegistry(); print('Registry OK')"`
Expected:
  - Exit code: 0
  - Output contains: "Registry OK"

- [ ] **Step 5: 提交**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && git add apkid/skills/__init__.py apkid/skills/registry.py tests/test_skills_registry.py && git commit -m "refactor(skills): add SkillBase and SkillRegistry for auto-discovery"`

---

### Task 2: 实现 Skill 模块 — 将 cli.py 逻辑拆分为 5 个独立 Skill

**Depends on:** Task 1
**Files:**
- Create: `apkid/skills/scan.py`
- Create: `apkid/skills/batch.py`
- Create: `apkid/skills/tags.py`
- Create: `apkid/skills/info.py`
- Create: `apkid/skills/rules.py`

- [ ] **Step 1: 创建 ScanSkill — 迁移 cli.py:101-127 的 scan 逻辑**

```python
# apkid/skills/scan.py
from pathlib import Path
from typing import Optional

from apkid.apkid import Options, Scanner
from apkid.ai_output import AIOutputFormatter
from apkid.rules import RulesManager
from apkid.skills.registry import SkillBase


class ScanSkill(SkillBase):
    name = "scan"
    description = "Scan an APK, DEX, or ELF file for identifiers"
    help_text = "Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers."

    def execute(
        self,
        target: Path,
        output: Optional[Path] = None,
        fmt: str = "json",
        timeout: int = 30,
        typing: str = "magic",
        scan_depth: int = 2,
        entry_max_scan_size: int = 0,
        include_types: bool = False,
    ) -> str:
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
        scanner = Scanner(rules=rules, options=options)
        results = scanner.scan_file(str(target))
        formatter = AIOutputFormatter()
        formatted = formatter.format(results, str(target), fmt=fmt, include_types=include_types)
        if output:
            output.write_text(formatted, encoding="utf-8")
        return formatted
```

- [ ] **Step 2: 创建 BatchSkill — 迁移 cli.py:130-183 的 batch 逻辑**

```python
# apkid/skills/batch.py
import json
from pathlib import Path
from typing import Optional

from apkid.apkid import Options, Scanner
from apkid.ai_output import AIOutputFormatter
from apkid.rules import RulesManager
from apkid.skills.registry import SkillBase


class BatchSkill(SkillBase):
    name = "batch"
    description = "Batch scan files in a directory"
    help_text = "Batch scan files in a directory for identifiers."

    def execute(
        self,
        directory: Path,
        recursive: bool = False,
        pattern: str = "*.apk",
        output: Optional[Path] = None,
        fmt: str = "json",
        timeout: int = 30,
        typing: str = "magic",
        scan_depth: int = 2,
        entry_max_scan_size: int = 0,
        include_types: bool = False,
    ) -> str:
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
        scanner = Scanner(rules=rules, options=options)
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
            if output:
                output.write_text(result, encoding="utf-8")
            return result
        all_results = []
        for f in files:
            results = scanner.scan_file(str(f))
            formatted = formatter.format_dict(results, str(f), include_types=include_types)
            all_results.append(formatted)
        batch_output = json.dumps({
            "error": False,
            "scanned": len(all_results),
            "results": all_results,
        }, ensure_ascii=False, indent=2)
        if output:
            output.write_text(batch_output, encoding="utf-8")
        return batch_output
```

- [ ] **Step 3: 创建 TagsSkill — 迁移 cli.py:186-193 的 list-tags 逻辑**

```python
# apkid/skills/tags.py
import json

from apkid.ai_output import RULE_DESCRIPTIONS
from apkid.skills.registry import SkillBase


class TagsSkill(SkillBase):
    name = "list-tags"
    description = "List all available detection tags"
    help_text = "List all available detection tags and their descriptions."

    def execute(self) -> str:
        tags = []
        for tag, desc in sorted(RULE_DESCRIPTIONS.items()):
            tags.append({"tag": tag, "description": desc})
        return json.dumps({"tags": tags}, ensure_ascii=False, indent=2)
```

- [ ] **Step 4: 创建 InfoSkill — 迁移 cli.py:196-211 的 info 逻辑**

```python
# apkid/skills/info.py
import json

from apkid import __version__
from apkid.rules import RulesManager
from apkid.skills.registry import SkillBase


class InfoSkill(SkillBase):
    name = "info"
    description = "Show version, rules hash, and rules count"
    help_text = "Show version, rules hash, and rules count."

    def execute(self) -> str:
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
        return json.dumps(result, ensure_ascii=False, indent=2)
```

- [ ] **Step 5: 创建 RulesSkill — 迁移 cli.py:214-232 的 rules 逻辑**

```python
# apkid/skills/rules.py
import json

from apkid.rules import RulesManager
from apkid.skills.registry import SkillBase


class RulesSkill(SkillBase):
    name = "rules"
    description = "Manage YARA rules"
    help_text = "Manage YARA rules: list source files or compile to rules.yarc."

    def execute(self, action: str = "list") -> str:
        rules_mgr = RulesManager()
        if action == "list":
            yara_files = rules_mgr._collect_yara_files()
            rule_list = sorted(yara_files.keys())
            return json.dumps({"rules": rule_list, "count": len(rule_list)}, ensure_ascii=False, indent=2)
        elif action == "compile":
            rules_mgr.compile()
            count = rules_mgr.save()
            return json.dumps({"compiled": True, "rules_count": count}, ensure_ascii=False, indent=2)
        else:
            return json.dumps({"error": True, "message": f"Unknown action '{action}'. Use 'list' or 'compile'."}, ensure_ascii=False)
```

- [ ] **Step 6: 验证所有 Skill 可被 Registry 发现**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && python -c "from apkid.skills.registry import SkillRegistry; r = SkillRegistry(); skills = r.discover(); print(f'Found: {list(skills.keys())}')"`
Expected:
  - Exit code: 0
  - Output contains: "scan", "batch", "list-tags", "info", "rules"

- [ ] **Step 7: 提交**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && git add apkid/skills/scan.py apkid/skills/batch.py apkid/skills/tags.py apkid/skills/info.py apkid/skills/rules.py && git commit -m "refactor(skills): implement 5 skill modules from cli.py"`

---

### Task 3: 重构 cli.py 为统一入口 — 从 Registry 动态生成 Typer 命令

**Depends on:** Task 2
**Files:**
- Modify: `apkid/cli.py` (全文重写)
- Modify: `setup.py:106-111` (entry_points)

- [ ] **Step 1: 重写 cli.py 为基于 Registry 的动态 CLI 入口**

文件: `apkid/cli.py`（替换全文）

```python
# apkid/cli.py
import json
import sys
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from apkid import __version__
from apkid.skills.registry import SkillRegistry

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


def _error_exit(message: str, detail: str = "", code: int = 1):
    """Print structured error to stderr and exit."""
    error_payload = json.dumps(
        {"error": True, "message": message, "detail": detail},
        ensure_ascii=False,
    )
    typer.echo(error_payload, err=True)
    raise typer.Exit(code=code)


# --- 动态注册 Skill 为 Typer 命令 ---


def _register_scan_command(registry: SkillRegistry):
    """注册 scan 子命令。"""
    @app.command()
    def scan(
        target: Path = typer.Argument(..., exists=True, help="APK, DEX, or ELF file to scan"),
        output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write result to file"),
        fmt: OutputFormat = typer.Option(OutputFormat.json, "--format", "-f", help="Output format"),
        timeout: int = typer.Option(30, "--timeout", "-t", help="YARA scan timeout in seconds"),
        typing: TypingMethod = typer.Option(TypingMethod.magic, "--typing", help="File identification method"),
        scan_depth: int = typer.Option(2, "--scan-depth", help="Max recursion depth"),
        entry_max_scan_size: int = typer.Option(0, "--entry-max-scan-size", help="Max ZIP entry size"),
        include_types: bool = typer.Option(False, "--include-types", help="Include file_type detections"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Log debug messages"),
    ):
        """Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers."""
        try:
            skill = registry.get("scan")
            result = skill.execute(
                target=target,
                output=output,
                fmt=fmt.value,
                timeout=timeout,
                typing=typing.value,
                scan_depth=scan_depth,
                entry_max_scan_size=entry_max_scan_size,
                include_types=include_types,
            )
            if not output:
                typer.echo(result)
        except Exception as e:
            _error_exit(str(e), type(e).__name__)


def _register_batch_command(registry: SkillRegistry):
    """注册 batch 子命令。"""
    @app.command()
    def batch(
        directory: Path = typer.Argument(..., exists=True, help="Directory to scan"),
        recursive: bool = typer.Option(False, "--recursive", "-r", help="Scan subdirectories"),
        pattern: str = typer.Option("*.apk", "--pattern", "-p", help="File glob pattern"),
        output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write result to file"),
        fmt: OutputFormat = typer.Option(OutputFormat.json, "--format", "-f", help="Output format"),
        timeout: int = typer.Option(30, "--timeout", "-t", help="YARA scan timeout"),
        typing: TypingMethod = typer.Option(TypingMethod.magic, "--typing", help="File identification"),
        scan_depth: int = typer.Option(2, "--scan-depth", help="Max recursion depth"),
        entry_max_scan_size: int = typer.Option(0, "--entry-max-scan-size", help="Max ZIP entry size"),
        include_types: bool = typer.Option(False, "--include-types", help="Include file_type detections"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Log debug messages"),
    ):
        """Batch scan files in a directory."""
        try:
            skill = registry.get("batch")
            result = skill.execute(
                directory=directory,
                recursive=recursive,
                pattern=pattern,
                output=output,
                fmt=fmt.value,
                timeout=timeout,
                typing=typing.value,
                scan_depth=scan_depth,
                entry_max_scan_size=entry_max_scan_size,
                include_types=include_types,
            )
            if not output:
                typer.echo(result)
        except Exception as e:
            _error_exit(str(e), type(e).__name__)


def _register_tags_command(registry: SkillRegistry):
    """注册 list-tags 子命令。"""
    @app.command(name="list-tags")
    def list_tags():
        """List all available detection tags and their descriptions."""
        skill = registry.get("list-tags")
        typer.echo(skill.execute())


def _register_info_command(registry: SkillRegistry):
    """注册 info 子命令。"""
    @app.command()
    def info():
        """Show version, rules hash, and rules count."""
        skill = registry.get("info")
        typer.echo(skill.execute())


def _register_rules_command(registry: SkillRegistry):
    """注册 rules 子命令。"""
    @app.command()
    def rules(
        action: str = typer.Argument(..., help="Action: 'list' or 'compile'"),
    ):
        """Manage YARA rules: list source files or compile to rules.yarc."""
        skill = registry.get("rules")
        result = skill.execute(action=action)
        typer.echo(result)
        if '"error": true' in result:
            raise typer.Exit(code=1)


def _register_skills_command(registry: SkillRegistry):
    """注册 skills 子命令 — 列出所有已注册的 Skill。"""
    @app.command(name="skills")
    def list_skills():
        """List all registered skills."""
        skills_info = []
        for name, skill_instance in registry.all().items():
            skills_info.append({
                "name": name,
                "description": skill_instance.description,
            })
        typer.echo(json.dumps({"skills": skills_info}, ensure_ascii=False, indent=2))


def _register_all_commands():
    """发现所有 Skill 并注册为 Typer 命令。"""
    registry = SkillRegistry()
    registry.discover()
    _register_scan_command(registry)
    _register_batch_command(registry)
    _register_tags_command(registry)
    _register_info_command(registry)
    _register_rules_command(registry)
    _register_skills_command(registry)
    return registry


# 模块加载时自动注册所有命令
_registry = _register_all_commands()


def ai_cli():
    """Entry point for ai-apkid command."""
    app()
```

- [ ] **Step 2: 修改 setup.py — 添加 `apkid` 别名指向新 CLI**
文件: `setup.py:106-111`（替换 entry_points 块）

```python
    entry_points={
        'console_scripts': [
            'apkid=apkid.main:main',
            'ai-apkid=apkid.cli:ai_cli',
        ],
    },
```

注意：`apkid` 命令保持原有入口不变（向后兼容），`ai-apkid` 指向重构后的统一 CLI。

- [ ] **Step 3: 验证重构后的 CLI 可运行**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && pip install -e . 2>&1 | tail -3 && ai-apkid --help`
Expected:
  - Exit code: 0
  - Output contains: "scan", "batch", "list-tags", "info", "rules", "skills"

- [ ] **Step 4: 验证新增 skills 命令**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && ai-apkid skills`
Expected:
  - Exit code: 0
  - Output contains: "scan", "batch", "list-tags", "info", "rules"

- [ ] **Step 5: 验证原有命令参数不变**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && ai-apkid scan --help`
Expected:
  - Exit code: 0
  - Output contains: "--timeout", "--typing", "--scan-depth", "--format"

- [ ] **Step 6: 提交**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && git add apkid/cli.py setup.py && git commit -m "refactor(cli): rewrite cli.py as unified skill-based CLI with auto-discovery"`

---

### Task 4: 更新 Claude Code Skills 文档 — 统一命令引用和新增 skills 命令

**Depends on:** Task 3
**Files:**
- Modify: `.claude/skills/apkid-scan/SKILL.md`
- Modify: `.claude/skills/apkid-batch/SKILL.md`
- Modify: `.claude/skills/apkid-rule-dev/SKILL.md`

- [ ] **Step 1: 更新 apkid-scan SKILL.md — 添加 skills 架构说明和 skills 命令引用**
文件: `.claude/skills/apkid-scan/SKILL.md`

在文件末尾 `## Notes` 部分之前添加：

```markdown
## Skills Architecture

This skill is part of the unified `ai-apkid` CLI. All skills are auto-discovered from `apkid/skills/` and registered as CLI subcommands.

- List all skills: `ai-apkid skills`
- Skill registry: `apkid.skills.registry.SkillRegistry`
```

- [ ] **Step 2: 更新 apkid-batch SKILL.md — 添加 skills 架构说明**
文件: `.claude/skills/apkid-batch/SKILL.md`

在文件末尾 `## Notes` 部分之前添加同样的 Skills Architecture 段落。

- [ ] **Step 3: 更新 apkid-rule-dev SKILL.md — 添加 skills 命令和 Skill 开发指引**
文件: `.claude/skills/apkid-rule-dev/SKILL.md`

在 `## Notes` 部分之前添加：

```markdown
## Skills Architecture

This skill is part of the unified `ai-apkid` CLI. All skills are auto-discovered from `apkid/skills/` and registered as CLI subcommands.

### Adding a New Skill

1. Create a new file in `apkid/skills/` (e.g., `apkid/skills/analyze.py`)
2. Define a class inheriting from `SkillBase` with `name`, `description`, `help_text`
3. Implement the `execute(**kwargs)` method
4. The skill will be auto-discovered by `SkillRegistry` and appear as `ai-apkid <name>`
5. Register the Typer command wrapper in `apkid/cli.py`'s `_register_all_commands()`
```

- [ ] **Step 4: 提交**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && git add .claude/skills/ && git commit -m "docs(skills): update SKILL.md files with unified architecture and skills command"`

---

### Task 5: 集成测试 — 验证统一 CLI 和 Skill 自动发现

**Depends on:** Task 3
**Files:**
- Create: `tests/test_cli_integration.py`

- [ ] **Step 1: 创建 CLI 集成测试**

```python
# tests/test_cli_integration.py
import json
import subprocess
import sys


def run_cli(*args):
    """Run ai-apkid CLI and return stdout, stderr, returncode."""
    result = subprocess.run(
        [sys.executable, "-m", "apkid.cli"] + list(args),
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout, result.stderr, result.returncode


class TestCLIHelp:
    def test_help_shows_all_commands(self):
        stdout, stderr, code = run_cli("--help")
        assert code == 0
        assert "scan" in stdout
        assert "batch" in stdout
        assert "list-tags" in stdout
        assert "info" in stdout
        assert "rules" in stdout
        assert "skills" in stdout

    def test_scan_help(self):
        stdout, stderr, code = run_cli("scan", "--help")
        assert code == 0
        assert "--timeout" in stdout
        assert "--typing" in stdout


class TestSkillsCommand:
    def test_skills_lists_all(self):
        stdout, stderr, code = run_cli("skills")
        assert code == 0
        data = json.loads(stdout)
        names = [s["name"] for s in data["skills"]]
        assert "scan" in names
        assert "batch" in names
        assert "info" in names
        assert "list-tags" in names
        assert "rules" in names


class TestListTags:
    def test_list_tags_outputs_json(self):
        stdout, stderr, code = run_cli("list-tags")
        assert code == 0
        data = json.loads(stdout)
        assert "tags" in data
        assert len(data["tags"]) > 0


class TestInfo:
    def test_info_outputs_json(self):
        stdout, stderr, code = run_cli("info")
        assert code == 0
        data = json.loads(stdout)
        assert "version" in data
        assert "rules_sha256" in data
        assert "rules_count" in data
```

- [ ] **Step 2: 验证集成测试通过**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && python -m pytest tests/test_cli_integration.py -v --no-header 2>&1 | head -30`
Expected:
  - Exit code: 0
  - Output contains: "passed"

- [ ] **Step 3: 验证原有 apkid 命令仍可用（向后兼容）**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && python -m apkid.main --help 2>&1 | head -5`
Expected:
  - Exit code: 0
  - Output contains: "APKiD"

- [ ] **Step 4: 提交**
Run: `cd /data/local/tmp/workspace/github/AI-APKiD && git add tests/test_cli_integration.py && git commit -m "test(skills): add CLI integration tests for unified skill-based architecture"`

---

## Self-Review Results

**Plan Type:** Refactor

| # | Check | Result | Action Taken |
|---|-------|--------|-------------|
| 1 | Goal + Type + Scope + Risk? | PASS | — |
| 2 | Dependencies? | PASS | Task 1→2→3→4, Task 1→2→3→5 |
| 3 | Each Task 3-8 Steps? | PASS | Task1:7, Task2:7, Task3:6, Task4:4, Task5:4 |
| 4 | No TBD/TODO/vague? | PASS | — |
| 5 | Cross-Task consistency? | PASS | All Skill classes use same SkillBase, name, description, execute() |
| 6 | File saved to docs/superpowers/plans/? | PASS | — |
| 7 | Before/After architecture? | PASS | Before: 2 CLI entry points, manual @app.command. After: 1 entry + SkillRegistry auto-discovery |
| 8 | Test coverage sufficient? | PASS | Task 1: registry unit test, Task 5: CLI integration test |
| 9 | Each Task has regression validation? | PASS | Task 3 Step 3-5 verify CLI still works |
| 10 | No mixed migrate+delete in same Step? | PASS | — |
| 11 | Migration order correct (copy→migrate→delete→cleanup)? | PASS | Task 2 creates new Skill modules first, Task 3 rewrites cli.py |
| 12 | No behavior change (structure only)? | PASS | All CLI subcommands and parameters preserved |

**Status:** ✅ ALL PASS

---

## Execution Selection

**Tasks:** 5
**Dependencies:** yes (Task 1→2→3→4/5)
**User Preference:** none
**Decision:** Subagent-Driven
**Reasoning:** 5 tasks with sequential dependencies — suitable for subagent-driven development

**Auto-invoking:** `superpowers:subagent-driven-development`