"""apkid-ai-cli info — Show version and rules info."""

import json

import typer

from apkid import __version__
from apkid.rules import RulesManager


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