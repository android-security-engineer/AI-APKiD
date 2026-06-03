"""APKiD MCP Server — Model Context Protocol integration.

This module provides an MCP server that exposes APKiD's scanning
capabilities as tools callable by AI agents via the MCP protocol.

The MCP module is intentionally isolated from the rest of the codebase.
It only depends on `apkid.cli.common` and `apkid.ai_output` — never
the reverse.
"""

from apkid.mcp.server import mcp, run

__all__ = ["mcp", "run"]
