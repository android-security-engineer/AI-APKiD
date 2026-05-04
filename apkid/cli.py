"""
 Copyright (C) 2026  RedNaga. https://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.
"""

import json
import sys
from pathlib import Path

import click

from apkid.apkid import Scanner, Options
from apkid.rules import RulesManager
from apkid.ai_output import AIOutputFormatter


@click.group()
def ai_cli():
    """AI-APKiD: Android APK/DEX/ELF identifier for AI agents."""
    pass


def _make_scanner(timeout: int = 60) -> Scanner:
    """Create a Scanner with default options."""
    rules_mgr = RulesManager()
    rules = rules_mgr.load()
    options = Options(timeout=timeout, json=True)
    return Scanner(rules=rules, options=options)


@ai_cli.command(name="scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path (default: stdout)")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="json", help="Output format")
@click.option("--timeout", type=int, default=60, help="Scan timeout in seconds")
def scan_cmd(target, output, fmt, timeout):
    """Scan an APK, DEX, or ELF file for packer/signer/compiler identifiers."""
    try:
        scanner = _make_scanner(timeout=timeout)
        results = scanner.scan_file(target)
        formatter = AIOutputFormatter()
        formatted = formatter.format(results, target, fmt=fmt)
        if output:
            Path(output).write_text(formatted, encoding="utf-8")
        else:
            click.echo(formatted)
    except Exception as e:
        error_payload = json.dumps({
            "error": True,
            "message": str(e),
            "type": type(e).__name__,
            "target": target
        }, ensure_ascii=False)
        click.echo(error_payload, err=True)
        sys.exit(1)


@ai_cli.command(name="batch")
@click.argument("directory", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Scan subdirectories recursively")
@click.option("--pattern", "-p", default="*.apk", help="File glob pattern (default: *.apk)")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="json", help="Output format")
@click.option("--timeout", type=int, default=60, help="Scan timeout in seconds")
def batch_cmd(directory, recursive, pattern, output, fmt, timeout):
    """Batch scan files in a directory."""
    try:
        scanner = _make_scanner(timeout=timeout)
        formatter = AIOutputFormatter()
        target_path = Path(directory)
        if recursive:
            files = sorted(target_path.rglob(pattern))
        else:
            files = sorted(target_path.glob(pattern))
        if not files:
            click.echo(json.dumps({
                "error": False,
                "scanned": 0,
                "results": [],
                "message": f"No files matching '{pattern}' found in {directory}"
            }, ensure_ascii=False))
            return
        all_results = []
        for f in files:
            results = scanner.scan_file(str(f))
            formatted = formatter.format_dict(results, str(f))
            all_results.append(formatted)
        batch_output = json.dumps({
            "error": False,
            "scanned": len(all_results),
            "results": all_results
        }, ensure_ascii=False, indent=2)
        if output:
            Path(output).write_text(batch_output, encoding="utf-8")
        else:
            click.echo(batch_output)
    except Exception as e:
        error_payload = json.dumps({
            "error": True,
            "message": str(e),
            "type": type(e).__name__
        }, ensure_ascii=False)
        click.echo(error_payload, err=True)
        sys.exit(1)


@ai_cli.command(name="list-tags")
def list_tags_cmd():
    """List all available detection tags and their descriptions."""
    from apkid.ai_output import RULE_DESCRIPTIONS
    tags = []
    for tag, desc in sorted(RULE_DESCRIPTIONS.items()):
        tags.append({"tag": tag, "description": desc})
    click.echo(json.dumps({"tags": tags}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    ai_cli()