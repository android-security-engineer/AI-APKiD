---
name: apkid-type
description: Use when needing to quickly identify whether a file is an APK, DEX, ELF, or other Android binary format before running a full scan
allowed-tools:
  - "Bash(apkid-ai-cli:*)"
---

# APKiD Type Skill

## When to Use

Use this skill when you need to:
- Quickly identify if a file is an APK, DEX, ELF, or other Android binary format
- Determine file type before deciding whether to run a full scan
- Validate file format as a preprocessing step in analysis pipelines

## Instructions

1. Run `apkid-ai-cli type <file>` to identify the file type
2. Check the `type` field in the output for the identified format
3. If `type` is `null`, the file is not a recognized Android binary format

## Commands

### `apkid-ai-cli type`

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `target` | Yes | — | File to identify |

## Output Format

```json
{
  "error": false,
  "file": "path/to/file",
  "type": "zip",
  "supported_types": ["dex", "dll", "elf", "res", "zip"]
}
```

Unknown file:
```json
{
  "error": false,
  "file": "path/to/file",
  "type": null,
  "message": "Unknown file type — not a recognized Android binary format"
}
```

## Examples

```bash
# Identify an APK file
apkid-ai-cli type suspicious.apk

# Check if a file is a DEX
apkid-ai-cli type classes.dex

# Identify an ELF binary
apkid-ai-cli type libnative.so
```

## Notes

- Uses magic byte detection (first 4 bytes), not filename extension
- This is much faster than a full scan — no YARA rules are loaded
- Supported types: `zip` (APK/JAR), `dex`, `elf` (.so), `res`, `dll`
- APK files are detected as `zip` because they are ZIP archives