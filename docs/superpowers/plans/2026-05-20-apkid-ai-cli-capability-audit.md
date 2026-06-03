# Research: apkid-ai-cli 能力盘点与 AI 优化方向

**Question:** apkid-ai-cli 当前提供了哪些能力？下一步如何优化和完善其 AI 能力？
**Context:** 项目刚完成 CLI 重构（monolithic → modular package）和命名更新（ai-apkid → apkid-ai-cli），需要评估现状并规划 AI-native 增强方向
**Deliverable:** 能力清单 + 优化方向 + 优先级排序的行动建议
**Time Box:** 已完成调研
**Scope:** Medium

---

## 一、当前能力清单

### 8 个 CLI 命令

| 命令 | 用途 | 输出结构 | AI 价值 |
|------|------|---------|---------|
| `scan` | 扫描单个文件 | `{error, target, findings[], summary, scanned_at}` | 核心能力 |
| `batch` | 批量扫描目录 | `{error, scanned, results[]}` | 高 — 自动化分析 |
| `diff` | 比较两文件差异 | `{error, file1, file2, added[], removed[], summary}` | 高 — 版本对比 |
| `type` | 识别文件类型 | `{error, file, type, supported_types[]}` | 中 — 快速预检 |
| `list-tags` | 列出检测标签 | `{tags: [{tag, description}]}` | 中 — 自发现 |
| `info` | 版本/规则信息 | `{version, rules_sha256, rules_count}` | 低 — 元信息 |
| `rules` | 管理规则 | `{rules[], count}` 或 `{compiled, rules_count}` | 中 — 规则开发 |
| `skills` | 列出所有命令 | `{error, skills[], total}` | 中 — 自发现 |

### 6 个 Claude Code Skills

| Skill | 允许的工具 | 覆盖场景 |
|-------|-----------|---------|
| `apkid-scan` | `Bash(apkid-ai-cli:*)` | 单文件扫描 |
| `apkid-batch` | `Bash(apkid-ai-cli:*)` | 批量扫描 |
| `apkid-rule-dev` | `Read, Write, Edit, Bash(apkid-ai-cli:*, python:*)` | 规则开发 |
| `apkid-diff` | `Bash(apkid-ai-cli:*)` | 差异对比 |
| `apkid-type` | `Bash(apkid-ai-cli:*)` | 文件类型识别 |
| `apkid-skills` | `Bash(apkid-ai-cli:*)` | 自发现 |

### 18 个检测类别

`anti_vm`, `anti_debug`, `anti_disassembly`, `anti_root`, `packer`, `obfuscator`, `protector`, `anticheat`, `signer`, `compiler`, `abnormal`, `dropper`, `embedded`, `manipulator`, `file_type`, `internal`, `hook`, `root`

### AI 友好特性（已有）

- 所有输出默认 JSON，`error` 字段始终存在
- 错误输出为结构化 JSON 到 stderr: `{"error": true, "message": "...", "detail": "..."}`
- Finding 包含 `tag`, `category`, `description`, `source`, `identifier`, `rule_detail`
- Summary 自动聚合类别计数
- ISO 8601 时间戳 `scanned_at`
- 安全边界：仅 `apkid-rule-dev` 有写权限

---

## 二、当前差距分析

| 差距 | 严重度 | 影响 |
|------|--------|------|
| **无 MCP 服务器** | 高 | AI agent 只能通过 Bash 调用 CLI，无法通过标准协议直接调用工具 |
| **无 JSON Schema 端点** | 中 | AI agent 无法自发现输出格式，只能靠试错解析 |
| **无 schema_version** | 中 | 输出格式变更时 AI agent 无感知，可能解析失败 |
| **README 仅文档化 3/8 命令** | 中 | diff/type/info/rules/skills 未文档化，AI agent 不知道这些能力 |
| **Docker 仅暴露 `apkid`** | 中 | 容器化部署无法使用 apkid-ai-cli |
| **无 CLAUDE.md** | 中 | Claude Code 无项目级指引 |
| **测试覆盖不足** | 中 | diff/type/skills 命令无测试，batch 仅测空目录 |
| **无 `--quiet` 模式** | 低 | Rich spinner 输出到 stderr，AI 消费时需过滤 |
| **Tool description 不够 AI 优化** | 低 | CLI help 文本面向人类，非 AI agent |

---

## 三、优化方向与优先级

### Priority 1: MCP 服务器（最高影响）

**为什么：** MCP 是 AI agent 调用工具的标准协议。没有 MCP，AI agent 只能通过 `Bash(apkid-ai-cli:*)` 调用，这需要字符串解析、无法类型检查、无法自发现参数 schema。有了 MCP，任何 MCP 兼容客户端（Claude Desktop、Cursor、Windsurf 等）都能直接发现和调用 apkid 的能力。

**具体方案：**

```python
# apkid/mcp_server.py — 使用 FastMCP SDK
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("apkid")

@mcp.tool()
def scan_file(target: str, typing: str = "magic",
              scan_depth: int = 2, include_types: bool = False) -> str:
    """Scan an Android APK/DEX/ELF binary to identify packers, protectors,
    obfuscators, compilers, anti-debugging, anti-VM, and anti-root techniques.
    Returns JSON with findings array and category summary."""
    ...

@mcp.tool()
def batch_scan(directory: str, recursive: bool = False,
               pattern: str = "*.apk") -> str:
    """Batch scan files in a directory for Android binary identifiers."""
    ...

@mcp.tool()
def diff_files(file1: str, file2: str) -> str:
    """Compare scan results between two files to find protection differences."""
    ...

@mcp.tool()
def type_file(target: str) -> str:
    """Identify the type of an Android binary file via magic bytes."""
    ...

@mcp.tool()
def list_tags() -> str:
    """List all detection tags and their descriptions."""
    ...

@mcp.resource("apkid://info")
def get_info() -> str:
    """Version, rules hash, and rules count."""
    ...

if __name__ == "__main__":
    mcp.run()  # stdio transport
```

**新增文件：** `apkid/mcp_server.py`
**修改文件：** `setup.py`（新增 entry point `apkid-mcp=apkid.mcp_server:main`，新增依赖 `mcp>=1.0.0`）
**修改文件：** `.claude/settings.json`（注册 MCP server）

---

### Priority 2: JSON Schema 端点

**为什么：** AI agent 需要知道输出格式才能可靠解析。`apkid-ai-cli schema scan` 返回 scan 命令输出的 JSON Schema，让 AI agent 知道 `findings` 是数组、`category` 是枚举等。

**具体方案：** 新增 `schema` 命令，输出每个命令结果的 JSON Schema。

```bash
apkid-ai-cli schema scan     # 输出 scan 结果的 JSON Schema
apkid-ai-cli schema batch    # 输出 batch 结果的 JSON Schema
apkid-ai-cli schema diff     # 输出 diff 结果的 JSON Schema
```

---

### Priority 3: Schema 版本化

**为什么：** 当输出格式变更时，AI agent 需要知道自己消费的是哪个版本。`schema_version: "1.0"` 让 agent 可以做版本适配。

**具体方案：** 在所有 JSON 输出中添加 `"schema_version": "1.0"` 字段。

---

### Priority 4: 完善 README 文档

**为什么：** 当前 README 仅文档化 3/8 命令和 3/6 skills。AI agent 读 README 来了解项目能力，缺失的文档 = 缺失的能力。

**具体方案：** 补充 diff/type/info/rules/skills 命令文档，补充 apkid-diff/apkid-type/apkid-skills skill 文档。

---

### Priority 5: CLAUDE.md 项目指引

**为什么：** Claude Code 在项目根目录查找 CLAUDE.md 获取项目级指引。没有它，Claude Code 不知道项目的 AI 集成架构。

**具体方案：** 创建 `.claude/CLAUDE.md`，内容包含：
- 项目简介和架构
- CLI 命令速查
- Skills 列表
- MCP server 配置
- 测试和开发指引

---

### Priority 6: 补充测试

**为什么：** diff/type/skills 命令无测试，batch 仅测空目录。AI agent 依赖这些命令的可靠性。

**具体方案：** 为 diff/type/skills 各添加 3-5 个测试用例，为 batch 添加真实文件测试。

---

### Priority 7: Docker 支持 apkid-ai-cli

**为什么：** 当前 Docker 仅暴露 `apkid` 命令。

**具体方案：** 修改 Dockerfile，添加 `apkid-ai-cli` entrypoint 或同时暴露两个命令。

---

### Priority 8: `--quiet` 模式

**为什么：** AI agent 消费 stdout 时，Rich spinner 输出到 stderr 虽然不影响 JSON，但 `--quiet` 可以完全静默非输出内容。

**具体方案：** 添加全局 `--quiet` 标志，禁用 Rich spinner 和所有 stderr 日志。

---

## 四、优先级矩阵

| 优先级 | 改进项 | 影响 | 工作量 | ROI |
|--------|--------|------|--------|-----|
| **P1** | MCP 服务器 | 极高 | 中（~150 行新代码） | **最高** |
| **P2** | JSON Schema 端点 | 高 | 小（~80 行新代码） | 高 |
| **P3** | Schema 版本化 | 中 | 极小（每命令加 1 字段） | 高 |
| **P4** | 完善 README | 中 | 小（文档更新） | 中 |
| **P5** | CLAUDE.md | 中 | 小（~50 行新文件） | 中 |
| **P6** | 补充测试 | 中 | 中（~200 行测试代码） | 中 |
| **P7** | Docker 支持 | 低 | 极小（改 1 行） | 低 |
| **P8** | `--quiet` 模式 | 低 | 小（~20 行） | 低 |

---

## 五、行动建议

**立即执行（本次迭代）：**
1. 实现 MCP 服务器（P1）— 这是 AI-native 的核心基础设施
2. 添加 schema_version 字段（P3）— 极小改动，立即收益
3. 创建 CLAUDE.md（P5）— 让 Claude Code 理解项目

**下次迭代：**
4. 添加 JSON Schema 端点（P2）
5. 完善 README 文档（P4）
6. 补充测试（P6）

**后续迭代：**
7. Docker 支持（P7）
8. `--quiet` 模式（P8）

---

## Self-Review Results

**Plan Type:** Research

| # | Check | Result |
|---|-------|--------|
| 1 | Goal + Type + Scope + Risk? | PASS |
| 2 | Dependencies? | PASS (Research 无依赖) |
| 3 | 调研问题定义清晰？ | PASS — "当前能力" + "优化方向" |
| 4 | 信息源 ≥2 且出处明确？ | PASS — 代码库分析 + MCP 官方文档 + 社区实践 |
| 5 | 结论有数据支撑？ | PASS — 8 命令、6 skills、18 类别均为代码库实测 |
| 6 | 包含明确行动建议？ | PASS — 8 项改进 + 优先级 + ROI |
| 7 | 方案不可行时有替代？ | N/A — 所有方案可行 |
| 8 | 输出格式是结构化文档？ | PASS |

**Status:** ALL PASS