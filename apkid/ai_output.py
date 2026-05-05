"""
 Copyright (C) 2026  RedNaga. https://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yara


RULE_DESCRIPTIONS = {
    "anti_vm": "Detects anti-VM/anti-emulator techniques",
    "anti_debug": "Detects anti-debugging techniques",
    "anti_disassembly": "Detects anti-disassembly techniques",
    "anti_root": "Detects anti-root techniques",
    "packer": "Detects APK packing/obfuscation tools",
    "obfuscator": "Detects code obfuscation tools",
    "protector": "Detects app protection/shielding SDKs",
    "anticheat": "Detects anti-cheat SDKs",
    "signer": "Detects APK signing certificates and signers",
    "compiler": "Detects compiler or build tool fingerprints",
    "abnormal": "Detects abnormal or suspicious modifications",
    "dropper": "Detects dropper/loader behavior patterns",
    "embedded": "Detects embedded payloads",
    "manipulator": "Detects APK manipulation tools",
    "file_type": "Detects file type information",
    "internal": "Detects internal/development artifacts",
    "hook": "Detects hooking frameworks (Xposed, Frida, etc.)",
    "root": "Detects root detection or root-related libraries",
}


class AIOutputFormatter:
    """Formats APKiD scan results for AI agent consumption."""

    def format(self, results: Dict[str, List[yara.Match]], target: str, fmt: str = "json", include_types: bool = False) -> str:
        """Format scan results into the specified output format.

        Args:
            results: Raw scan results dict from Scanner.scan_file()
            target: Path to the scanned file
            fmt: Output format - 'json' or 'text'
            include_types: If True, include file_type detections

        Returns:
            Formatted output string
        """
        if fmt == "text":
            return self._format_text(results, target, include_types=include_types)
        return self._format_json(results, target, include_types=include_types)

    def format_dict(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> Dict:
        """Format scan results into a dictionary for batch aggregation.

        Args:
            results: Raw scan results dict from Scanner.scan_file()
            target: Path to the scanned file
            include_types: If True, include file_type detections

        Returns:
            Dictionary with structured scan results
        """
        return self._build_result_dict(results, target, include_types=include_types)

    def _format_json(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> str:
        result_dict = self._build_result_dict(results, target, include_types=include_types)
        return json.dumps(result_dict, ensure_ascii=False, indent=2)

    def _format_text(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> str:
        result_dict = self._build_result_dict(results, target, include_types=include_types)
        lines = [f"Target: {result_dict['target']}", ""]
        for finding in result_dict.get("findings", []):
            lines.append(f"  [{finding['category']}] {finding['identifier']}")
            if finding.get("description"):
                lines.append(f"    {finding['description']}")
        if not result_dict.get("findings"):
            lines.append("  No identifiers detected")
        lines.append("")
        lines.append(f"Scanned at: {result_dict['scanned_at']}")
        return "\n".join(lines)

    def _build_result_dict(self, results: Dict[str, List[yara.Match]], target: str, include_types: bool = False) -> Dict:
        findings = self._extract_findings(results, include_types=include_types)
        return {
            "error": False,
            "target": target,
            "findings": findings,
            "summary": self._build_summary(findings),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _extract_findings(self, results: Any, include_types: bool = False) -> List[Dict]:
        findings = []
        if results is None:
            return findings
        if isinstance(results, dict):
            for file_path, matches in results.items():
                if isinstance(matches, list):
                    for match in matches:
                        if isinstance(match, yara.Match):
                            findings.extend(self._match_to_findings(match, file_path, include_types=include_types))
                        elif isinstance(match, str):
                            findings.append(self._tag_to_finding(match, file_path))
        return findings

    def _match_to_findings(self, match: yara.Match, source: str, include_types: bool = False) -> List[Dict]:
        findings = []
        description = match.meta.get('description', match.rule)
        for tag in match.tags:
            if tag == 'file_type' and not include_types:
                continue
            category = self._categorize_tag(tag)
            findings.append({
                "tag": f"{tag}::{match.rule}" if match.rule != tag else tag,
                "category": category,
                "description": RULE_DESCRIPTIONS.get(category, "Unknown detection category"),
                "source": source,
                "identifier": match.rule,
                "rule_detail": description,
            })
        if not match.tags:
            category = self._categorize_tag(match.rule)
            findings.append({
                "tag": match.rule,
                "category": category,
                "description": RULE_DESCRIPTIONS.get(category, "Unknown detection category"),
                "source": source,
                "identifier": match.rule,
                "rule_detail": description,
            })
        return findings

    def _tag_to_finding(self, tag: str, source: str) -> Dict:
        category = self._categorize_tag(tag)
        return {
            "tag": tag,
            "category": category,
            "description": RULE_DESCRIPTIONS.get(category, "Unknown detection category"),
            "source": source,
            "identifier": tag,
        }

    def _categorize_tag(self, tag: str) -> str:
        tag_lower = tag.lower()
        for category in RULE_DESCRIPTIONS:
            if category in tag_lower:
                return category
        return "abnormal"

    def _build_summary(self, findings: List[Dict]) -> Dict:
        categories = {}
        for f in findings:
            cat = f["category"]
            categories[cat] = categories.get(cat, 0) + 1
        return {
            "total_findings": len(findings),
            "categories": categories,
        }