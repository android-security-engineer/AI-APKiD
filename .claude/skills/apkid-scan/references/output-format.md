# APKiD AI Output Format Reference

## JSON Schema

### Top-Level Object

| Field | Type | Description |
|-------|------|-------------|
| error | boolean | `false` on success, `true` on failure |
| target | string | Path to the scanned file |
| findings | array | List of detection findings |
| summary | object | Aggregated summary of findings |
| scanned_at | string | ISO 8601 timestamp of when the scan completed |

### Finding Object

| Field | Type | Description |
|-------|------|-------------|
| tag | string | Detection tag (e.g., "packer") |
| category | string | Detection category (e.g., "packer") |
| description | string | Human-readable category description |
| source | string | Source file within the APK (e.g., "classes.dex") |
| identifier | string | Specific rule identifier (e.g., "bangcle") |
| rule_detail | string | Detailed description from YARA rule meta |

### Summary Object

| Field | Type | Description |
|-------|------|-------------|
| total_findings | integer | Total number of findings |
| categories | object | Map of category name to count |

### Error Object (on stderr)

| Field | Type | Description |
|-------|------|-------------|
| error | boolean | Always `true` |
| message | string | Error description |
| type | string | Python exception class name |
| target | string | Path to the target file (if applicable) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully |
| 1 | Scan failed (see stderr for error JSON) |