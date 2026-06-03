"""APKiD MCP Server — FastMCP server definition and tool registration.

Uses the official MCP Python SDK (mcp>=1.0.0) and its FastMCP
high-level API. FastMCP handles protocol serialization, tool schema
generation from type hints and docstrings, and stdio transport
automatically — we don't implement any MCP protocol details ourselves.

Design: Tool adapter functions return Python dicts/lists, not JSON
strings. FastMCP serializes them into MCP protocol responses.
"""

from mcp.server.fastmcp import FastMCP

from apkid.mcp.tools_scan import scan_file, batch_scan, diff_files, type_file
from apkid.mcp.tools_info import info, list_tags, rules, skills

MCP_SERVER_NAME = "apkid"
MCP_SERVER_VERSION = "3.1.0"
MCP_SERVER_INSTRUCTIONS = (
    "APKiD MCP Server — Android APK/DEX/ELF identifier.\n"
    "Use scan_file to detect packers, protectors, obfuscators, and compilers.\n"
    "Use batch_scan for directories, diff_files to compare two files, "
    "type_file for fast file-type identification.\n"
    "Use info/list_tags/rules/skills for metadata and self-discovery."
)

mcp = FastMCP(
    MCP_SERVER_NAME,
    version=MCP_SERVER_VERSION,
    instructions=MCP_SERVER_INSTRUCTIONS,
)

# --- Register scanning tools ---
mcp.tool()(scan_file)
mcp.tool()(batch_scan)
mcp.tool()(diff_files)
mcp.tool()(type_file)

# --- Register info tools ---
mcp.tool()(info)
mcp.tool(name="list-tags")(list_tags)
mcp.tool()(rules)
mcp.tool()(skills)


def run():
    """Entry point for the apkid-mcp console script."""
    mcp.run()