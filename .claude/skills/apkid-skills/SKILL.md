---
name: apkid-skills
description: Use when discovering what apkid-ai-cli commands and capabilities are available, or when an AI agent needs to self-discover available tools
allowed-tools:
  - "Bash(apkid-ai-cli:*)"
---

# APKiD Skills Skill

## When to Use

Use this skill when you need to:
- Discover what commands/capabilities are available in apkid-ai-cli
- Get a quick reference of all CLI skills and their descriptions
- Help AI agents self-discover available tools at runtime

## Instructions

1. Run `apkid-ai-cli skills` to list all registered commands
2. Each skill entry includes `name` and `description`
3. Use this for self-discovery in automated analysis pipelines

## Commands

### `apkid-ai-cli skills`

No parameters required.

## Output Format

```json
{
  "error": false,
  "skills": [
    {
      "name": "batch",
      "description": "Batch scan files in a directory."
    },
    {
      "name": "diff",
      "description": "Compare scan results between two files to find protection differences."
    }
  ],
  "total": 8
}
```

## Examples

```bash
# List all available skills
apkid-ai-cli skills

# Use in scripts for self-discovery
apkid-ai-cli skills | jq '.skills[].name'
```

## Notes

- This command requires no YARA rules or file system access
- Output is always sorted alphabetically by skill name
- Useful for AI agents to discover capabilities at runtime
- The `total` field gives the count of available skills