# APKiD

[![PyPI](https://img.shields.io/pypi/v/apkid.svg)](https://pypi.org/project/apkid/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/apkid.svg)](https://pypi.org/project/apkid/)
[![PyPI - License](https://img.shields.io/pypi/l/apkid.svg)](https://pypi.org/project/apkid/)

APKiD gives you information about how an APK was made. It identifies many compilers, packers, obfuscators, and other weird stuff. It's [_PEiD_](https://www.aldeid.com/wiki/PEiD) for Android.

![Screen Shot 2019-05-07 at 10 55 00 AM](https://user-images.githubusercontent.com/1356658/57322793-49be9c00-70b9-11e9-84da-1e64d9459a8a.png)

For more information on what this tool can be used for, check out:

* [Android Compiler Fingerprinting](http://hitcon.org/2016/CMT/slide/day1-r0-e-1.pdf)
* [Detecting Pirated and Malicious Android Apps with APKiD](http://rednaga.io/2016/07/31/detecting_pirated_and_malicious_android_apps_with_apkid/)
* [APKiD: PEiD for Android Apps (BlackHat EU/UK Arsenal 2018)](https://github.com/enovella/cve-bio-enovella/blob/master/slides/bheu18-enovella-APKID.pdf)
* [APKiD: Fast Identification of AppShielding Products](https://github.com/enovella/cve-bio-enovella/blob/master/slides/APKiD-NowSecure-Connect19-enovella.pdf)
* [APKiD: Fast Identification of Mobile RASP SDKs (BlackHat USA Arsenal 2023)](https://github.com/enovella/cve-bio-enovella/blob/master/slides/bheu23-enovella-APKID.pdf)

**[简体中文](#简体中文文档)**

---

## Installing

```bash
pip install apkid
```

For MCP server support (optional):

```bash
pip install apkid[mcp]
```

### Docker

You can also run APKiD with [Docker](https://www.docker.com/community-edition):

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD/
docker build . -t rednaga:apkid

# Classic CLI
docker/apkid.sh ~/reverse/targets/android/example/example.apk

# AI CLI (structured JSON output)
docker run --rm -v /path/to/samples:/input:ro rednaga:apkid apkid-ai-cli scan /input/app.apk

# MCP server (stdio transport)
docker run --rm -i rednaga:apkid apkid-mcp
```

## Usage — Classic CLI

```
usage: apkid [-h] [-v] [-t TIMEOUT] [-r] [--scan-depth SCAN_DEPTH]
             [--entry-max-scan-size ENTRY_MAX_SCAN_SIZE] [--typing {magic,filename,none}] [-j]
             [-o DIR]
             [FILE [FILE ...]]

APKiD - Android Application Identifier v3.1.0
```

## Usage — AI CLI (`apkid-ai-cli`)

The `apkid-ai-cli` command provides structured JSON output designed for AI agent consumption. It uses [Typer](https://typer.tiangolo.com/) with rich formatting.

### Commands

| Command | Description |
|---------|-------------|
| `scan <file>` | Scan an APK, DEX, or ELF file for packer/signer/compiler/protector identifiers |
| `batch <dir>` | Batch scan files in a directory |
| `diff <file1> <file2>` | Compare scan results between two files to find protection differences |
| `type <file>` | Identify file type (APK/DEX/ELF) via magic bytes |
| `info` | Show version, rules hash, and rules count |
| `list-tags` | List all available detection tags and their descriptions |
| `rules <action>` | Manage YARA rules: `list` source files or `compile` to rules.yarc |
| `skills` | List all available CLI skills (commands) for self-discovery |

### Examples

```bash
# Scan a file (JSON output, default)
apkid-ai-cli scan /path/to/app.apk

# Scan with text output
apkid-ai-cli scan /path/to/app.apk --format text

# Scan with all options
apkid-ai-cli scan /path/to/app.apk --typing magic --scan-depth 2 --timeout 30 --include-types

# Batch scan a directory recursively
apkid-ai-cli batch /path/to/samples/ --recursive --pattern "*.apk"

# Compare two APK versions
apkid-ai-cli diff app-v1.apk app-v2.apk

# Identify file type (fast, no YARA rules loaded)
apkid-ai-cli type /path/to/file

# Show version and rules info
apkid-ai-cli info

# List all detection tags
apkid-ai-cli list-tags

# List YARA rule source files
apkid-ai-cli rules list

# Compile YARA rules (after editing rules)
apkid-ai-cli rules compile

# Self-discover available commands
apkid-ai-cli skills
```

### Output Format

All commands output structured JSON with a consistent envelope:

```json
{
  "schema_version": "1.0.0",
  "error": false,
  "target": "/path/to/app.apk",
  "findings": [
    {
      "tag": "packer",
      "category": "packer",
      "description": "Detects APK packing/obfuscation tools",
      "source": "classes.dex",
      "identifier": "bangcle",
      "rule_detail": "Bangcle packer"
    }
  ],
  "summary": {
    "total_findings": 1,
    "categories": {
      "packer": 1
    }
  },
  "scanned_at": "2026-01-01T00:00:00+00:00"
}
```

Error output (on stderr):

```json
{
  "error": true,
  "message": "File not found",
  "detail": "FileNotFoundError"
}
```

### Detection Categories

| Category | Description |
|----------|-------------|
| packer | APK packing/obfuscation tools (Bangcle, 360, Tencent Legu, etc.) |
| protector | App protection/shielding SDKs |
| obfuscator | Code obfuscation tools (ProGuard, DexGuard, etc.) |
| signer | APK signing certificates and signers |
| compiler | Compiler or build tool fingerprints |
| anti_vm | Anti-VM/anti-emulator techniques |
| anti_debug | Anti-debugging techniques |
| anti_disassembly | Anti-disassembly techniques |
| anti_root | Anti-root techniques |
| abnormal | Abnormal or suspicious modifications |
| hook | Hooking frameworks (Xposed, Frida, etc.) |
| root | Root detection or root-related libraries |
| anticheat | Anti-cheat SDKs |
| dropper | Dropper/loader behavior patterns |
| embedded | Embedded payloads |
| manipulator | APK manipulation tools |

## MCP Server (`apkid-mcp`)

APKiD includes an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that exposes scanning capabilities as tools callable by AI agents via the standard MCP protocol.

### Install

```bash
pip install apkid[mcp]
```

### Run

```bash
# Stdio transport (default, for Claude Code and other MCP hosts)
apkid-mcp

# Or via Python module
python -m apkid.mcp
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan_file` | Scan an APK, DEX, or ELF file |
| `batch_scan` | Batch scan files in a directory |
| `diff_files` | Compare scan results between two files |
| `type_file` | Identify file type via magic bytes |
| `info` | Show version and rules info |
| `list_tags` | List all detection tags |
| `rules` | Manage YARA rules (list or compile) |
| `skills` | List all available MCP tools |

### Configure in Claude Code

Add to your `.claude/settings.json` or `.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "apkid": {
      "command": "apkid-mcp",
      "args": []
    }
  }
}
```

Or if installed in a virtual environment:

```json
{
  "mcpServers": {
    "apkid": {
      "command": "/path/to/venv/bin/apkid-mcp",
      "args": []
    }
  }
}
```

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
| `apkid-scan` | `/apkid-scan` | Scan a single APK/DEX/ELF file for packers, protectors, obfuscators, and compilers |
| `apkid-batch` | `/apkid-batch` | Batch scan a directory of APK/DEX/ELF files |
| `apkid-diff` | `/apkid-diff` | Compare two files to find added or removed protections |
| `apkid-type` | `/apkid-type` | Quickly identify file type (APK/DEX/ELF) via magic bytes |
| `apkid-rule-dev` | `/apkid-rule-dev` | Develop and test YARA detection rules |
| `apkid-skills` | `/apkid-skills` | Self-discover available apkid-ai-cli commands |

### For Skill Developers

Skills are defined in `.claude/skills/` using SKILL.md files with YAML frontmatter. See the [Claude Code Skills documentation](https://docs.anthropic.com/en/docs/claude-code/skills) for details.

## How It Works

APKiD identifies packers, protectors, and obfuscators using **YARA rule-based multi-layer signature matching**. It scans Android binary files (APK/DEX/ELF) and matches fingerprints left by protection tools across three layers:

| Layer | Scan Target | Matching Content |
|-------|-------------|-----------------|
| APK | APK as a ZIP archive | Native library paths, assets paths, META-INF signatures |
| DEX | classes.dex and other DEX files | Class names, string constants, Dalvik bytecode patterns |
| ELF | .so native libraries | Compiler version strings, symbol names, instruction patterns |

Key detection techniques include:

- **Native library path matching** — Packers ship their engines under predictable paths (e.g., `lib/arm64-v8a/libjiagu.so` for 360 Jiagu)
- **Stub class name matching** — Packers inject stub Application classes with known names (e.g., `Lcom/stub/StubApp;`)
- **Dalvik bytecode sequence matching** — The unpacking logic in `attachBaseContext()` follows predictable instruction patterns
- **Crypto algorithm fingerprinting** — XOR/AES decryption loops in the unpacking stub have characteristic bytecode signatures
- **Compiler fingerprint matching** — OLLVM and its forks embed version strings in the `.comment` ELF section
- **Code obfuscation pattern detection** — Control flow flattening (CFF), bogus control flow (BCF), and prolog breakage leave recognizable instruction patterns

## Submitting New Packers / Compilers / Obfuscators

If you come across an APK or DEX which APKiD does not recognize, please open a GitHub issue and tell us:

* what you think it is -- obfuscated, packed, etc.
* the file hash (either MD5, SHA1, SHA256)

We are open to any type of concept you might have for "something interesting" to detect, so do not limit yourself solely to packers, compilers or obfuscators. If there is an interesting anti-disassembler, anti-vm, anti-* trick, please make an issue.

Pull requests are welcome. If you're submitting a new rule, be sure to include a file hash of the APK / DEX so we can check the rule.

## License

This tool is available under a dual license: a commercial one suitable for closed source projects and a GPL license that can be used in open source software.

Depending on your needs, you must choose one of them and follow its policies. A detail of the policies and agreements for each license type are available in the [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL) and [LICENSE.GPL](LICENSE.GPL) files.

## Hacking

If you want to install the latest version in order to make changes, develop your own rules, and so on, simply clone this repository, compile the rules, and install the package in editable mode:

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD
python prep-release.py
pip install -e .[dev,test]
```

If the above doesn't work, due to permission errors dependent on your local machine and where Python has been installed, try specifying the `--user` flag. This is likely needed if you're not using a virtual environment:

```bash
pip install -e .[dev,test] --user
```

If you update any of the rules, be sure to run `prep-release.py` to recompile them.

If you are using Windows, install Yara 3.11.0 and yara-python-dex before compiling

```bash
pip install yara-python==3.11.0
pip install wheel
pip wheel --wheel-dir=yara-python-dex git+https://github.com/MobSF/yara-python-dex.git
pip install --no-index --find-links=yara-python-dex yara-python-dex
```

## For Package Maintainers

When releasing a new version, make sure the version has been updated in [apkid/__init__.py](apkid/__init__.py).

Update the compiled rules, the readme, build the package and upload to PyPI:

```bash
./prep-release.py readme
rm -f dist/*
python setup.py sdist bdist_wheel
twine upload --repository-url https://upload.pypi.org/legacy/ dist/*
```

For more information see [Packaging Projects](https://packaging.python.org/tutorials/packaging-projects/).

---

# 简体中文文档

**[English](#apkid)**

APKiD 可以告诉你一个 APK 是如何构建的。它能够识别许多编译器、壳（加壳工具）、混淆器以及其他有趣的东西。它就是 Android 平台的 [_PEiD_](https://www.aldeid.com/wiki/PEiD)。

## 安装

```bash
pip install apkid
```

如需 MCP 服务器支持（可选）：

```bash
pip install apkid[mcp]
```

### Docker

也可以使用 [Docker](https://www.docker.com/community-edition) 运行 APKiD：

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD/
docker build . -t rednaga:apkid

# 经典 CLI
docker/apkid.sh ~/reverse/targets/android/example/example.apk

# AI CLI（结构化 JSON 输出）
docker run --rm -v /path/to/samples:/input:ro rednaga:apkid apkid-ai-cli scan /input/app.apk

# MCP 服务器（stdio 传输）
docker run --rm -i rednaga:apkid apkid-mcp
```

## 用法 — 经典 CLI

```
usage: apkid [-h] [-v] [-t TIMEOUT] [-r] [--scan-depth SCAN_DEPTH]
             [--entry-max-scan-size ENTRY_MAX_SCAN_SIZE] [--typing {magic,filename,none}] [-j]
             [-o DIR]
             [FILE [FILE ...]]

APKiD - Android Application Identifier v3.1.0
```

## 用法 — AI CLI (`apkid-ai-cli`)

`apkid-ai-cli` 命令提供专为 AI 代理消费设计的结构化 JSON 输出。它使用 [Typer](https://typer.tiangolo.com/) 框架并提供丰富的格式化。

### 命令

| 命令 | 描述 |
|------|------|
| `scan <file>` | 扫描 APK、DEX 或 ELF 文件，识别壳/签名/编译器/保护器标识 |
| `batch <dir>` | 批量扫描目录中的文件 |
| `diff <file1> <file2>` | 比较两个文件的扫描结果，发现保护差异 |
| `type <file>` | 通过魔数（magic bytes）识别文件类型（APK/DEX/ELF） |
| `info` | 显示版本、规则哈希和规则数量 |
| `list-tags` | 列出所有可用的检测标签及其描述 |
| `rules <action>` | 管理 YARA 规则：`list` 列出源文件或 `compile` 编译为 rules.yarc |
| `skills` | 列出所有可用的 CLI 技能（命令）用于自我发现 |

### 示例

```bash
# 扫描文件（默认 JSON 输出）
apkid-ai-cli scan /path/to/app.apk

# 以文本格式输出
apkid-ai-cli scan /path/to/app.apk --format text

# 使用全部选项扫描
apkid-ai-cli scan /path/to/app.apk --typing magic --scan-depth 2 --timeout 30 --include-types

# 递归批量扫描目录
apkid-ai-cli batch /path/to/samples/ --recursive --pattern "*.apk"

# 比较两个 APK 版本
apkid-ai-cli diff app-v1.apk app-v2.apk

# 识别文件类型（快速，不加载 YARA 规则）
apkid-ai-cli type /path/to/file

# 显示版本和规则信息
apkid-ai-cli info

# 列出所有检测标签
apkid-ai-cli list-tags

# 列出 YARA 规则源文件
apkid-ai-cli rules list

# 编译 YARA 规则（编辑规则后执行）
apkid-ai-cli rules compile

# 自我发现可用命令
apkid-ai-cli skills
```

### 输出格式

所有命令输出结构化 JSON，使用一致的信封格式：

```json
{
  "schema_version": "1.0.0",
  "error": false,
  "target": "/path/to/app.apk",
  "findings": [
    {
      "tag": "packer",
      "category": "packer",
      "description": "检测 APK 加壳/混淆工具",
      "source": "classes.dex",
      "identifier": "bangcle",
      "rule_detail": "Bangcle packer"
    }
  ],
  "summary": {
    "total_findings": 1,
    "categories": {
      "packer": 1
    }
  },
  "scanned_at": "2026-01-01T00:00:00+00:00"
}
```

错误输出（stderr）：

```json
{
  "error": true,
  "message": "文件未找到",
  "detail": "FileNotFoundError"
}
```

### 检测类别

| 类别 | 描述 |
|------|------|
| packer | APK 加壳/混淆工具（梆梆、360加固、腾讯乐固等） |
| protector | 应用保护/防护 SDK |
| obfuscator | 代码混淆工具（ProGuard、DexGuard 等） |
| signer | APK 签名证书和签名者 |
| compiler | 编译器或构建工具指纹 |
| anti_vm | 反虚拟机/反模拟器技术 |
| anti_debug | 反调试技术 |
| anti_disassembly | 反反汇编技术 |
| anti_root | 反 Root 技术 |
| abnormal | 异常或可疑修改 |
| hook | Hook 框架（Xposed、Frida 等） |
| root | Root 检测或 Root 相关库 |
| anticheat | 反作弊 SDK |
| dropper | 释放器/加载器行为模式 |
| embedded | 嵌入式载荷 |
| manipulator | APK 操纵工具 |

## MCP 服务器 (`apkid-mcp`)

APKiD 包含一个 [MCP（模型上下文协议）](https://modelcontextprotocol.io/) 服务器，将扫描能力作为工具暴露给 AI 代理，通过标准 MCP 协议调用。

### 安装

```bash
pip install apkid[mcp]
```

### 运行

```bash
# stdio 传输（默认，用于 Claude Code 和其他 MCP 宿主）
apkid-mcp

# 或通过 Python 模块
python -m apkid.mcp
```

### 可用的 MCP 工具

| 工具 | 描述 |
|------|------|
| `scan_file` | 扫描 APK、DEX 或 ELF 文件 |
| `batch_scan` | 批量扫描目录中的文件 |
| `diff_files` | 比较两个文件的扫描结果 |
| `type_file` | 通过魔数识别文件类型 |
| `info` | 显示版本和规则信息 |
| `list_tags` | 列出所有检测标签 |
| `rules` | 管理 YARA 规则（列出或编译） |
| `skills` | 列出所有可用的 MCP 工具 |

### 在 Claude Code 中配置

添加到你的 `.claude/settings.json` 或 `.claude/settings.local.json`：

```json
{
  "mcpServers": {
    "apkid": {
      "command": "apkid-mcp",
      "args": []
    }
  }
}
```

如果在虚拟环境中安装：

```json
{
  "mcpServers": {
    "apkid": {
      "command": "/path/to/venv/bin/apkid-mcp",
      "args": []
    }
  }
}
```

## Claude Code Skills

本仓库同时也是一个 **Claude Code Skills** 包。安装后可将 APKiD 扫描能力添加到你的 Claude Code 代理中。

### 安装

```bash
# 添加为 skills 源
claude skills add --source https://github.com/rednaga/AI-APKiD

# 或本地安装
claude skills add --source /path/to/AI-APKiD
```

### 可用技能

| 技能 | 命令 | 描述 |
|------|------|------|
| `apkid-scan` | `/apkid-scan` | 扫描单个 APK/DEX/ELF 文件，识别壳、保护器、混淆器和编译器 |
| `apkid-batch` | `/apkid-batch` | 批量扫描 APK/DEX/ELF 文件目录 |
| `apkid-diff` | `/apkid-diff` | 比较两个文件，发现新增或移除的保护措施 |
| `apkid-type` | `/apkid-type` | 通过魔数快速识别文件类型（APK/DEX/ELF） |
| `apkid-rule-dev` | `/apkid-rule-dev` | 开发和测试 YARA 检测规则 |
| `apkid-skills` | `/apkid-skills` | 自我发现 apkid-ai-cli 可用命令 |

### 给技能开发者

技能在 `.claude/skills/` 目录中通过 SKILL.md 文件定义，使用 YAML 前置元数据。详见 [Claude Code Skills 文档](https://docs.anthropic.com/en/docs/claude-code/skills)。

## 工作原理

APKiD 使用**基于 YARA 规则的多层次特征匹配**来识别壳、保护器和混淆器。它扫描 Android 二进制文件（APK/DEX/ELF），在三个层次上匹配保护工具留下的指纹：

| 层次 | 扫描目标 | 匹配内容 |
|------|---------|---------|
| APK 层 | APK 作为 ZIP 归档 | Native library 路径、assets 路径、META-INF 签名 |
| DEX 层 | classes.dex 及其他 DEX 文件 | 类名、字符串常量、Dalvik 字节码模式 |
| ELF 层 | .so 原生库 | 编译器版本字符串、符号名、指令模式 |

关键检测技术包括：

- **Native library 路径匹配** — 加壳工具将解壳引擎放在可预测的路径下（如 360加固的 `lib/arm64-v8a/libjiagu.so`）
- **Stub 类名匹配** — 加壳工具注入已知名称的 stub Application 类（如 `Lcom/stub/StubApp;`）
- **Dalvik 字节码序列匹配** — `attachBaseContext()` 中的解壳逻辑遵循可预测的指令模式
- **加解密算法指纹** — 解壳 stub 中的 XOR/AES 解密循环具有特征性的字节码签名
- **编译器指纹匹配** — OLLVM 及其分支在 ELF 的 `.comment` 段中嵌入版本字符串
- **代码混淆模式检测** — 控制流平坦化（CFF）、虚假控制流（BCF）和函数入口破坏（Prolog breakage）留下可识别的指令模式

## 提交新发现的壳 / 编译器 / 混淆器

如果你发现 APKiD 无法识别的 APK 或 DEX，请提交 GitHub Issue 并告诉我们：

* 你认为它是什么 — 混淆、加壳等
* 文件哈希（MD5、SHA1、SHA256 均可）

我们欢迎任何你认为是"有趣的东西"的检测概念，不要仅限于壳、编译器或混淆器。如果有有趣的反汇编、反虚拟机、反-* 技巧，请提交 Issue。

欢迎提交 Pull Request。如果你提交新规则，请务必包含 APK/DEX 的文件哈希，以便我们验证规则。

## 许可证

本工具采用双许可证：适合闭源项目的商业许可证和可用于开源软件的 GPL 许可证。

根据你的需求，你必须选择其中一种并遵循其政策。每种许可证类型的政策和协议详情请参见 [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL) 和 [LICENSE.GPL](LICENSE.GPL) 文件。

## 开发

如果你想安装最新版本以进行修改、开发自己的规则等，只需克隆本仓库、编译规则并以可编辑模式安装包：

```bash
git clone https://github.com/rednaga/APKiD
cd APKiD
python prep-release.py
pip install -e .[dev,test]
```

如果由于权限错误导致上述命令无法工作（取决于本地机器和 Python 安装位置），请尝试指定 `--user` 标志。如果不使用虚拟环境，很可能需要此标志：

```bash
pip install -e .[dev,test] --user
```

如果你更新了任何规则，请务必运行 `prep-release.py` 重新编译。

如果你使用 Windows，请在编译前安装 Yara 3.11.0 和 yara-python-dex：

```bash
pip install yara-python==3.11.0
pip install wheel
pip wheel --wheel-dir=yara-python-dex git+https://github.com/MobSF/yara-python-dex.git
pip install --no-index --find-links=yara-python-dex yara-python-dex
```

## 给包维护者

发布新版本时，确保 [apkid/__init__.py](apkid/__init__.py) 中的版本号已更新。

更新编译规则、README、构建包并上传到 PyPI：

```bash
./prep-release.py readme
rm -f dist/*
python setup.py sdist bdist_wheel
twine upload --repository-url https://upload.pypi.org/legacy/ dist/*
```

更多信息请参见 [Packaging Projects](https://packaging.python.org/tutorials/packaging-projects/)。
