"""Backward-compatibility shim — delegates to the cli package."""

from apkid.cli import app, ai_cli  # noqa: F401

__all__ = ["app", "ai_cli"]