"""apkid-ai-cli skills — List all registered CLI skills."""

import json

import typer

from apkid.cli.app import app


def skills():
    """List all available CLI skills (commands) and their descriptions."""
    skill_list = []
    for command in app.registered_commands:
        name = command.name or command.callback.__name__
        help_text = command.help or ""
        if command.callback and command.callback.__doc__:
            help_text = command.callback.__doc__.strip()
        skill_list.append(
            {
                "name": name,
                "description": help_text,
            }
        )
    result = {
        "error": False,
        "skills": sorted(skill_list, key=lambda s: s["name"]),
        "total": len(skill_list),
    }
    typer.echo(json.dumps(result, ensure_ascii=False, indent=2))