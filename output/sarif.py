"""SARIF 2.1.0 output for kafka-stig-audit.

Maps audit CheckResult objects to a SARIF run document suitable for
ingestion by GitHub Code Scanning, GitLab SAST, and compatible tooling.

Status → SARIF level:
  FAIL / ERROR  → "error"
  WARN          → "warning"
  PASS / SKIP   → "none"

Severity → rule defaultConfiguration.level:
  CRITICAL / HIGH → "error"
  MEDIUM          → "warning"
  LOW / INFO      → "note"
"""

import json

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_STATUS_TO_LEVEL = {
    "FAIL": "error",
    "ERROR": "error",
    "WARN": "warning",
    "PASS": "none",
    "SKIP": "none",
}


def _pascal(s: str) -> str:
    return "".join(w.capitalize() for w in s.replace("-", " ").replace("_", " ").split())


def _rule_from_result(r) -> dict:
    tags = list(r.nist_800_53_controls or [])
    if r.fedramp_control:
        tags.append(f"FedRAMP:{r.fedramp_control}")
    if r.benchmark_control_id:
        tags.append(f"benchmark:{r.benchmark_control_id}")
    if r.category:
        tags.append(r.category)

    rule = {
        "id": r.check_id,
        "name": _pascal(r.title),
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.description or r.title},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL.get(r.severity.value, "warning"),
        },
        "properties": {
            "tags": tags,
            "precision": "medium",
            "problem.severity": _SEVERITY_TO_LEVEL.get(r.severity.value, "warning"),
        },
    }
    if r.remediation:
        rule["help"] = {
            "text": r.remediation,
            "markdown": f"**Remediation:** {r.remediation}",
        }
    if r.references:
        rule["helpUri"] = r.references[0]
    return rule


def _result_entry(r, rule_index: int, artifact_uri: str) -> dict:
    level = _STATUS_TO_LEVEL.get(r.status.value, "warning")

    msg_parts = [r.description or r.title]
    if r.actual:
        msg_parts.append(f"Actual: {r.actual}")
    if r.expected:
        msg_parts.append(f"Expected: {r.expected}")

    logical_locations = []
    if r.evidence:
        logical_locations.append({"name": r.evidence[0]["source"], "kind": "module"})

    entry = {
        "ruleId": r.check_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": " | ".join(msg_parts)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "uriBaseId": "KAFKA_TARGET",
                    },
                    "region": {"startLine": 1},
                },
                "logicalLocations": logical_locations,
            }
        ],
        "properties": {
            "status": r.status.value,
            "severity": r.severity.value,
            "category": r.category,
            "evidence_type": r.evidence_type,
            "actual": r.actual,
            "expected": r.expected,
            "benchmark_control_id": r.benchmark_control_id,
            "fedramp_control": r.fedramp_control,
            "nist_800_53_controls": r.nist_800_53_controls or [],
        },
    }
    if r.remediation:
        entry["fixes"] = [
            {
                "description": {"text": r.remediation},
                "artifactChanges": [],
            }
        ]
    return entry


def build_sarif(results, target_info: dict, tool_name: str, tool_version: str) -> dict:
    """Build a SARIF 2.1.0 document from audit results."""
    seen: dict[str, int] = {}
    rules: list[dict] = []
    for r in results:
        if r.check_id not in seen:
            seen[r.check_id] = len(rules)
            rules.append(_rule_from_result(r))

    display = target_info.get("display_name", "kafka://unknown")
    known_schemes = ("kafka://", "http://", "https://", "docker://", "k8s://")
    artifact_uri = display if any(display.startswith(s) for s in known_schemes) else f"kafka://{display}"

    sarif_results = [_result_entry(r, seen[r.check_id], artifact_uri) for r in results]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/audit-forge/kafka-stig-audit",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "KAFKA_TARGET": {
                        "description": {
                            "text": "Kafka target (container, pod, or host:port) being assessed."
                        }
                    }
                },
                "results": sarif_results,
                "properties": {"target": target_info},
            }
        ],
    }


def write_sarif(path: str, results, target_info: dict, tool_name: str, tool_version: str) -> None:
    doc = build_sarif(results, target_info, tool_name, tool_version)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
