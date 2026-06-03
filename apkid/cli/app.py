"""Typer app creation and command registration."""

import typer
from rich.console import Console

app = typer.Typer(
    name="apkid-ai-cli",
    help="APKiD AI-CLI: Android APK/DEX/ELF identifier — AI-native interface.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console(stderr=True)


def _register_commands():
    """Import and register all command modules."""
    from apkid.cli import cmd_scan, cmd_batch, cmd_tags, cmd_info, cmd_rules
    from apkid.cli import cmd_diff, cmd_type, cmd_skills

    app.command()(cmd_scan.scan)
    app.command()(cmd_batch.batch)
    app.command(name="list-tags")(cmd_tags.list_tags)
    app.command()(cmd_info.info)
    app.command()(cmd_rules.rules)
    app.command()(cmd_diff.diff)
    app.command(name="type")(cmd_type.type_file)
    app.command()(cmd_skills.skills)


_register_commands()


def ai_cli():
    """Entry point for apkid-ai-cli command."""
    app()
