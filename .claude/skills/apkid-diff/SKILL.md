---
name: apkid-diff
description: Use when comparing two APK/DEX/ELF files to find added or removed protections, packing, and obfuscation differences
allowed-tools:
  - "Bash(apkid-ai-cli:*)"
---

# APKiD Diff Skill

## When to Use

Use this skill when you need to:
- Compare two versions of the same APK to find protection changes
- Detect differences in packing/obfuscation between original and modified APKs
- Analyze what protections were added or removed between builds

## Instructions

1. Run `apkid-ai-cli diff <file1> <file2>` to compare scan results
2. Review the `added` findings (protections in file2 but not file1)
3. Review the `removed` findings (protections in file1 but not file2)
4. Use `--include-types` flag if file type differences matter

## Commands

### `apkid-ai-cli diff`

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `file1` | Yes | — | First file to scan |
| `file2` | Yes | — | Second file to scan |
| `--output`, `-o` | No | stdout | Write result to file |
| `--timeout`, `-t` | No | 30 | YARA scan timeout in seconds |
| `--typing` | No | magic | File identification method |
| `--scan-depth` | No | 2 | Max recursion depth for nested ZIP archives |
| `--include-types` | No | false | Include file_type detections |

## Output Format

```json
{
  "error": false,
  "file1": "path/to/original.apk",
  "file2": "path/to/modified.apk",
  "added": [],
  "removed": [],
  "common_count": 5,
  "summary": {
    "total_added": 0,
    "total_removed": 0,
    "total_common": 5
  }
}
```

## Examples

```bash
# Compare two APK versions
apkid-ai-cli diff app-v1.apk app-v2.apk

# Compare with file type detection
apkid-ai-cli diff original.apk repacked.apk --include-types

# Save diff output to file
apkid-ai-cli diff base.apk patched.apk -o diff-result.json
```

## Notes

- The diff is based on detection tags, not raw YARA rule matches
- `added` = protections found in file2 but NOT in file1
- `removed` = protections found in file1 but NOT in file2
- Both files are scanned independently, then results are compared