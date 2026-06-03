---
name: apkid-rule-dev
description: Use when developing or testing YARA rules to detect new packers, protectors, obfuscators, or other Android binary identifiers
allowed-tools:
  - "Read"
  - "Write"
  - "Edit"
  - "Bash(apkid-ai-cli:*, python:*)"
---

# APKiD Rule Development

Develop and test YARA rules for AI-APKiD to detect new packers, protectors, obfuscators, and other identifiers.

## When to Use

- When you need to add detection for a new packer or protector
- When updating existing rules for a new version of a known tool
- When testing custom YARA rules against sample files

## Instructions

1. Understand the existing rule structure by reading the rules directory
2. Create a new YARA rule following the naming convention and format
3. Test the rule against known sample files
4. Verify the rule does not produce false positives

## Rule File Structure

Rules are located in `apkid/rules/` organized by file type subdirectories (`apk/`, `dex/`, `elf/`, `dll/`, `res/`) as `.yara` files.

### Naming Convention

- File name: existing convention uses category-based naming (e.g., `packers.yara`, `protectors.yara`)
- Rule name: follows the pattern of the category it belongs to
- Example: rule `bangcle` in `apkid/rules/dex/packers.yara`

### Rule Template

```yara
rule <rule_name> : <category_tag> {
  meta:
    description = "<Tool Name> <category>"
  strings:
    $s1 = "<unique string or pattern>" ascii wide
    $s2 = "<another pattern>" ascii wide
  condition:
    any of them
}
```

### Category Tags

Use one of: `packer`, `protector`, `obfuscator`, `signer`, `compiler`, `anti_vm`, `anti_debug`, `abnormal`, `hook`, `root`, `anticheat`, `dropper`, `embedded`, `manipulator`

## Commands

### List all existing detection tags

```bash
apkid-ai-cli list-tags
```

### Show version and rules info

```bash
apkid-ai-cli info
```

### List YARA rule source files

```bash
apkid-ai-cli rules list
```

### Compile YARA rules

```bash
apkid-ai-cli rules compile
```

### Test a new rule against a sample

```bash
apkid-ai-cli scan <sample_file>
```

## Workflow

1. Run `apkid-ai-cli list-tags` to check if a similar rule already exists
2. Read existing rules in `apkid/rules/` for format reference
3. Add new rule to the appropriate category `.yara` file in `apkid/rules/`
4. Run `python prep-release.py` to compile rules into `rules.yarc`
5. Run `apkid-ai-cli scan <sample>` to verify detection
6. Test against clean samples to check for false positives

## Examples

### Add detection for a new packer

User: "Add a rule to detect NewPacker"
Action:
1. Check `apkid-ai-cli list-tags` for existing "newpacker" entries
2. Read `apkid/rules/dex/packers.yara` as a format reference
3. Add new rule to `apkid/rules/dex/packers.yara` with appropriate strings
4. Run `python prep-release.py` to compile
5. Test with `apkid-ai-cli scan <sample_using_newpacker>`

## Notes

- Rules must compile with yara-python-dex (the engine used by AI-APKiD)
- Use `ascii wide` for strings that may appear in either encoding
- Keep rules specific to avoid false positives
- Add a description in the meta section
- After modifying rules, run `python prep-release.py` to compile them