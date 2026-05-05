---
name: apkid-scan
description: Scan Android APK/DEX/ELF files for packer, signer, compiler, and protector identifiers using AI-APKiD
allowed-tools: "Bash(ai-apkid:*)"
---

# APKiD Scan

Scan Android APK, DEX, or ELF files to identify packers, signers, compilers, obfuscators, and protectors.

## When to Use

- When you need to identify what packer/protector/obfuscator an Android APK uses
- When analyzing an APK for security assessment or reverse engineering
- When checking if an APK uses anti-debugging or anti-VM techniques
- When identifying the signing certificate of an APK

## Instructions

1. Verify the target file exists using the Read tool or `ls` command
2. Run the scan command below with the target file path
3. Parse the JSON output to present findings to the user
4. If errors occur, check stderr for the error JSON payload

## Commands

### Scan a single file

```bash
ai-apkid scan <file_path>
```

### Scan with text output (human-readable)

```bash
ai-apkid scan <file_path> --format text
```

### Scan and save to file

```bash
ai-apkid scan <file_path> --output results.json
```

### Scan with all options

```bash
ai-apkid scan <file_path> --typing magic --scan-depth 2 --timeout 30 --entry-max-scan-size 0 --include-types --format json
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--format`, `-f` | json | Output format: json or text |
| `--timeout`, `-t` | 30 | YARA scan timeout in seconds |
| `--typing` | magic | File identification: magic (bytes), filename (extension), none (scan all) |
| `--scan-depth` | 2 | Max recursion depth for nested ZIP archives |
| `--entry-max-scan-size` | 0 | Max ZIP entry size to scan in bytes (0 = no limit) |
| `--include-types` | false | Include file_type detections in results |
| `--output`, `-o` | stdout | Write result to file |
| `--verbose`, `-v` | false | Log debug messages to stderr |

## Output Format

The default output is JSON with this structure:

```json
{
  "error": false,
  "target": "/path/to/app.apk",
  "findings": [
    {
      "tag": "packer",
      "category": "packer",
      "description": "Detects APK packing/obfuscation tools",
      "source": "classes.dex",
      "identifier": "bangcle",
      "rule_detail": "Bangcle packer"
    }
  ],
  "summary": {
    "total_findings": 1,
    "categories": {
      "packer": 1
    }
  },
  "scanned_at": "2026-01-01T00:00:00+00:00"
}
```

Error output (on stderr):

```json
{
  "error": true,
  "message": "File not found",
  "type": "FileNotFoundError",
  "target": "/path/to/missing.apk"
}
```

## Detection Categories

| Category | Description |
|----------|-------------|
| packer | APK packing/obfuscation tools (Bangcle, 360, Tencent Legu, etc.) |
| protector | App protection/shielding SDKs |
| obfuscator | Code obfuscation tools (ProGuard, DexGuard, etc.) |
| signer | APK signing certificates and signers |
| compiler | Compiler or build tool fingerprints |
| anti_vm | Anti-VM/anti-emulator techniques |
| anti_debug | Anti-debugging techniques |
| abnormal | Abnormal or suspicious modifications |
| hook | Hooking frameworks (Xposed, Frida) |
| root | Root detection or root-related libraries |

## Examples

### Scan an APK file

User: "Scan this APK for packers"
Action: Run `ai-apkid scan /path/to/app.apk`
Then: Report the findings, highlighting packer and protector categories

### Check for anti-debug techniques

User: "Does this APK use anti-debugging?"
Action: Run `ai-apkid scan /path/to/app.apk`
Then: Filter findings for category "anti_debug" and report

## Notes

- The `ai-apkid` command must be installed (`pip install apkid`)
- Supports APK, DEX, and ELF file formats
- Default timeout is 60 seconds, use `--timeout` for larger files
- All output is UTF-8 encoded