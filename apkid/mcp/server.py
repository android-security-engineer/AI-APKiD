"""APKiD MCP Server — FastMCP server definition and tool registration.

Uses the official MCP Python SDK (mcp>=1.0.0) and its FastMCP
high-level API. FastMCP handles protocol serialization, tool schema
generation from type hints and docstrings, and stdio transport
automatically — we don't implement any MCP protocol details ourselves.

Design: Tool adapter functions return JSON strings. FastMCP wraps each
return value into the MCP protocol response. All tools are registered
with ``structured_output=False`` so the SDK does not attempt to wrap
the return type annotation into a pydantic model (which would fail for
``str`` or ``Dict[str, Any]`` with the current SDK + pydantic v2).

Note: FastMCP removed its ``version=`` constructor kwarg in newer SDK
releases (still within our ``mcp>=1.0.0,<2.0.0`` range). Server version
is surfaced through the package itself (``apkid.__version__``) and the
``info`` tool — do not re-add ``version=`` here.
"""

from mcp.server.fastmcp import FastMCP

from apkid.mcp.tools_scan import scan_file, batch_scan, diff_files, type_file
from apkid.mcp.tools_info import info, list_tags, rules, skills

MCP_SERVER_NAME = "apkid"
MCP_SERVER_INSTRUCTIONS = (
    "APKiD MCP Server — Android APK/DEX/ELF identifier.\n"
    "Use scan_file to detect packers, protectors, obfuscators, and compilers.\n"
    "Use batch_scan for directories, diff_files to compare two files, "
    "type_file for fast file-type identification.\n"
    "Use info/list_tags/rules/skills for metadata and self-discovery."
)

mcp = FastMCP(
    MCP_SERVER_NAME,
    instructions=MCP_SERVER_INSTRUCTIONS,
)

# --- Register scanning tools ---
# All tools use structured_output=False so FastMCP treats the return
# value as plain text content rather than trying to parse it into a
# pydantic model.
mcp.tool(structured_output=False)(scan_file)
mcp.tool(structured_output=False)(batch_scan)
mcp.tool(structured_output=False)(diff_files)
mcp.tool(structured_output=False)(type_file)

# --- Register info tools ---
mcp.tool(structured_output=False)(info)
mcp.tool(name="list-tags", structured_output=False)(list_tags)
mcp.tool(structured_output=False)(rules)
mcp.tool(structured_output=False)(skills)


def run():
    """Entry point for the apkid-mcp console script."""
    mcp.run()