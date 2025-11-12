"""Parser for Prowler findings JSON."""

import json
from pathlib import Path

from src.models import Finding


def load_findings(json_path: str | Path) -> list[Finding]:
    """Load and parse Prowler findings from JSON file.

    Args:
        json_path: Path to the Prowler findings JSON file

    Returns:
        List of simplified Finding objects
    """
    with open(json_path) as f:
        data = json.load(f)

    findings = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        metadata = attrs.get("check_metadata", {})
        remediation = metadata.get("remediation", {})

        finding = Finding(
            finding_id=item.get("id", ""),
            check_id=attrs.get("check_id", ""),
            severity=attrs.get("severity", ""),
            problem=attrs.get("status_extended", ""),
            remediation_cli=remediation.get("code", {}).get("cli", ""),
            remediation_text=remediation.get("recommendation", {}).get("text", ""),
            remediation_url=remediation.get("recommendation", {}).get("url", ""),
        )
        findings.append(finding)

    return findings
