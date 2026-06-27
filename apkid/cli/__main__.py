"""Allow ``python -m apkid.cli`` to invoke the AI-CLI.

Equivalent to the ``apkid-ai-cli`` console script. Needed so the CLI is
runnable without relying solely on the installed entry point (e.g. in
tests and ``python -m`` invocations).
"""

from apkid.cli import ai_cli

if __name__ == "__main__":
    ai_cli()
