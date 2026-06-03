"""apkid-ai-cli type — Identify file type via magic bytes."""

import json
from pathlib import Path

import typer

from apkid.apkid import Scanner, SCANNABLE_FILE_MAGICS
from apkid.cli.common import error_exit


def type_file(
    target: Path = typer.Argument(
        ..., exists=True, help="File to identify"
    ),
):
    """Identify the type of a file (APK/DEX/ELF/etc.) via magic bytes."""
    try:
        with open(target, "rb") as f:
            detected = Scanner._type_file(f)
        if detected is None:
            result = {
                "error": False,
                "file": str(target),
                "type": None,
                "message": "Unknown file type — not a recognized Android binary format",
            }
        else:
            result = {
                "error": False,
                "file": str(target),
                "type": detected,
                "supported_types": sorted(SCANNABLE_FILE_MAGICS.keys()),
            }
        typer.echo(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        error_exit(str(e), type(e).__name__)