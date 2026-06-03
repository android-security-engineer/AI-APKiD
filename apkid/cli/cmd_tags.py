"""apkid-ai-cli list-tags — List all detection tags."""

import json

import typer

from apkid.ai_output import RULE_DESCRIPTIONS


def list_tags():
    """List all available detection tags and their descriptions."""
    tags = []
    for tag, desc in sorted(RULE_DESCRIPTIONS.items()):
        tags.append({"tag": tag, "description": desc})
    typer.echo(json.dumps({"tags": tags}, ensure_ascii=False, indent=2))