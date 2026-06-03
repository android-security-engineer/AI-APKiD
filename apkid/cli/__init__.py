"""
APKiD AI-CLI package — modular command structure.

Each command lives in its own module (cmd_*.py).
The Typer app and shared utilities are in app.py and common.py.
"""

from apkid.cli.app import app, ai_cli

__all__ = ["app", "ai_cli"]