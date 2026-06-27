# CLAUDE.md — APKiD Skills Repository

## What This Is

APKiD is an Android binary identifier (packers, protectors, obfuscators, compilers). This repo wraps APKiD as a **Claude Code Skills** package with three interfaces:

1. **Classic CLI** — `apkid` (argparse, human-readable output)
2. **AI CLI** — `apkid-ai-cli` (typer, structured JSON for AI agents)
3. **MCP Server** — `apkid-mcp` (FastMCP, standard MCP protocol)

## Architecture

```
Skill (/apkid-scan) → Bash: apkid-ai-cli scan <file>
                        ↓
                apkid/cli/cmd_scan.py → common.make_scanner()
                        ↓
                apkid.apkid.Scanner + apkid.ai_output.AIOutputFormatter
                        ↓
                YARA engine (yara-python-dex) + compiled rules (rules.yarc)

MCP host → apkid-mcp (FastMCP stdio)
              ↓
         apkid/mcp/tools_scan.py / tools_info.py
              ↓
         Same common.make_scanner() + AIOutputFormatter code path
```

Key principle: MCP and CLI share `apkid.cli.common.make_scanner()` and `apkid.ai_output.AIOutputFormatter` — never duplicate scanning logic.

## Key Commands

```bash
# Install for development
python prep-release.py          # compile YARA rules → rules.yarc
pip install -e .[dev,test]

# AI CLI
apkid-ai-cli scan <file>        # scan one file
apkid-ai-cli batch <dir> -r     # batch scan
apkid-ai-cli diff <f1> <f2>     # compare two files
apkid-ai-cli type <file>        # file type via magic bytes
apkid-ai-cli info               # version + rules info
apkid-ai-cli list-tags          # all detection tags
apkid-ai-cli rules list         # YARA source files
apkid-ai-cli rules compile      # recompile rules
apkid-ai-cli skills             # self-discovery

# MCP server
apkid-mcp                       # stdio transport

# Tests
pytest tests/ -q
```

## Adding a New Skill

1. Create `.claude/skills/apkid-<name>/SKILL.md` with YAML frontmatter (name, description, allowed-tools)
2. Add the skill entry to `.claude/plugins/ai-apkid.js`
3. Create `apkid/cli/cmd_<name>.py` with a typer command function
4. Register it in `apkid/cli/app.py` `_register_commands()`
5. If MCP: add tool adapter in `apkid/mcp/tools_*.py` and register in `server.py`
6. Add tests in `tests/`
7. Run `test_skills_package.py` to verify consistency

## Important Files

| Path | Purpose |
|------|---------|
| `apkid/ai_output.py` | `AIOutputFormatter` + `RULE_DESCRIPTIONS` dict |
| `apkid/cli/common.py` | `make_scanner()`, `output_result()`, `error_exit()` |
| `apkid/cli/app.py` | Typer app, command registration, `ai_cli()` entry point |
| `apkid/mcp/server.py` | FastMCP instance + tool registration |
| `apkid/rules/` | YARA rule source files (`.yara`) organized by file type |
| `apkid/rules/rules.yarc` | Compiled rules (gitignored, built by `prep-release.py`) |
| `.claude/plugins/ai-apkid.js` | Plugin loader — must list all skills |
| `.claude/skills/*/SKILL.md` | Skill definitions with frontmatter |

## Conventions

- All AI output includes `"schema_version": "1.0.0"` for format versioning
- Error output goes to stderr as `{"error": true, "message": ..., "detail": ...}`
- Detection categories are defined in `RULE_DESCRIPTIONS` (ai_output.py) — if you add a YARA rule with a new tag, add it there too
- MCP module is isolated: only imports from `apkid.cli.common` and `apkid.ai_output`, never the reverse
- `rules.yarc` is gitignored — always run `python prep-release.py` after editing rules

## Testing

```bash
pytest tests/ -q                                    # all tests
pytest tests/ -q --ignore=tests/test_mcp_server.py  # skip MCP (needs mcp SDK)
pytest tests/test_skills_package.py -q               # plugin↔skills↔CLI consistency
```

Note: `scan` and `batch` tests that hit YARA require `rules.yarc` to exist (run `prep-release.py` first). Tests that only test output formatting or error paths work without it.
