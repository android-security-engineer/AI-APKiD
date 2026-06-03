"""apkid-ai-cli rules — Manage YARA rules."""

import json

import typer

from apkid.rules import RulesManager
from apkid.cli.common import error_exit


def rules(
    action: str = typer.Argument(
        ..., help="Action: 'list' to show rule files, 'compile' to rebuild rules.yarc"
    ),
):
    """Manage YARA rules: list source files or compile to rules.yarc."""
    rules_mgr = RulesManager()
    if action == "list":
        yara_files = rules_mgr._collect_yara_files()
        rule_list = sorted(yara_files.keys())
        typer.echo(
            json.dumps(
                {"rules": rule_list, "count": len(rule_list)},
                ensure_ascii=False,
                indent=2,
            )
        )
    elif action == "compile":
        try:
            rules_mgr.compile()
            count = rules_mgr.save()
            typer.echo(
                json.dumps(
                    {"compiled": True, "rules_count": count},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        except Exception as e:
            error_exit(f"Compilation failed: {e}", type(e).__name__)
    else:
        error_exit(f"Unknown action '{action}'. Use 'list' or 'compile'.")