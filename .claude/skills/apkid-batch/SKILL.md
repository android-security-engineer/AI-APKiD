---
name: apkid-batch
description: Batch scan directories of Android APK/DEX/ELF files for packer and protector identifiers
allowed-tools: "Bash(ai-apkid:*)"
---

# APKiD Batch Scan

Batch scan directories of Android APK, DEX, or ELF files to identify packers, signers, compilers, obfuscators, and protectors.

## When to Use

- When you need to scan multiple APK files in a directory
- When comparing protection across a collection of APKs
- When building an inventory of app protection methods

## Instructions

1. Verify the target directory exists using `ls`
2. Run the batch scan command below
3. Parse the JSON output to present aggregated findings
4. Use `--recursive` flag to scan subdirectories

## Commands

### Batch scan a directory

```bash
ai-apkid batch <directory_path>
```

### Recursive scan with custom pattern

```bash
ai-apkid batch <directory_path> --recursive --pattern "*.apk"
```

### Save batch results to file

```bash
ai-apkid batch <directory_path> --output batch_results.json
```

### Batch scan with all options

```bash
ai-apkid batch <directory_path> --recursive --pattern "*.apk" --typing magic --scan-depth 2 --timeout 30 --include-types
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--recursive`, `-r` | false | Scan subdirectories recursively |
| `--pattern`, `-p` | *.apk | File glob pattern |
| `--format`, `-f` | json | Output format: json or text |
| `--timeout`, `-t` | 30 | YARA scan timeout in seconds |
| `--typing` | magic | File identification: magic, filename, none |
| `--scan-depth` | 2 | Max recursion depth for nested ZIP archives |
| `--entry-max-scan-size` | 0 | Max ZIP entry size to scan in bytes (0 = no limit) |
| `--include-types` | false | Include file_type detections in results |
| `--output`, `-o` | stdout | Write result to file |
| `--verbose`, `-v` | false | Log debug messages to stderr |

## Output Format

```json
{
  "error": false,
  "scanned": 3,
  "results": [
    {
      "error": false,
      "target": "/path/to/app1.apk",
      "findings": [],
      "summary": {}
    }
  ]
}
```

## Examples

### Scan all APKs in a directory

User: "Scan all APKs in /data/samples/"
Action: Run `ai-apkid batch /data/samples/`
Then: Present a summary table showing each APK and its detected packers/protectors

### Find all APKs using a specific packer

User: "Which APKs use Bangcle packer?"
Action: Run `ai-apkid batch /data/samples/ -r`
Then: Filter results for findings with identifier "bangcle" and list matching APKs

## Notes

- Default pattern is `*.apk`, use `--pattern` for DEX or ELF files
- Large directories may take time; use `--output` to save results
- Each file is scanned independently; one failure does not stop the batch