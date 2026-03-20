"""Evidence bundle output for kafka-stig-audit.

Produces a zip archive containing:
  manifest.json   — bundle metadata (tool, target, generated_at, contents list)
  results.json    — full JSON findings document
  results.sarif   — SARIF 2.1.0 rendition of all findings
  snapshot.json   — isolated runtime snapshot
  summary.txt     — human-readable plain-text report
  evidence/       — per-check evidence JSON (one file per check_id)
"""

import io
import json
import zipfile
from datetime import datetime, timezone

from output.sarif import build_sarif


def _summary_text(results, target_info: dict, summary: dict) -> str:
    lines = [
        "kafka-stig-audit — evidence bundle",
        f"Target : {target_info.get('display_name', 'unknown')}",
        f"Mode   : {target_info.get('mode', 'unknown')}",
        f"Time   : {target_info.get('timestamp', '')}",
        "",
        "Executive summary:",
        f"  Risk posture       : {summary.get('risk_posture', 'UNKNOWN')}",
        f"  Actionable findings: {summary.get('actionable_findings', 0)}",
    ]
    sc = summary.get("status_counts", {})
    lines.append(
        f"  PASS {sc.get('PASS', 0)} | FAIL {sc.get('FAIL', 0)} | "
        f"WARN {sc.get('WARN', 0)} | ERROR {sc.get('ERROR', 0)} | SKIP {sc.get('SKIP', 0)}"
    )
    sev = summary.get("severity_counts", {})
    lines.append(
        f"  CRITICAL {sev.get('CRITICAL', 0)} | HIGH {sev.get('HIGH', 0)} | "
        f"MEDIUM {sev.get('MEDIUM', 0)} | LOW {sev.get('LOW', 0)} | INFO {sev.get('INFO', 0)}"
    )
    lines += ["", "Findings:"]
    for r in results:
        lines.append(f"  [{r.status.value}/{r.severity.value}] {r.check_id} — {r.title}")
        if r.actual:
            lines.append(f"    Actual   : {r.actual}")
        if r.remediation and r.status.value not in ("PASS", "SKIP"):
            lines.append(f"    Fix      : {r.remediation}")
    return "\n".join(lines) + "\n"


def build_bundle(
    document: dict,
    results,
    target_info: dict,
    summary: dict,
    snapshot: dict,
    tool_name: str,
    tool_version: str,
) -> bytes:
    sarif_doc = build_sarif(results, target_info, tool_name, tool_version)
    evidence_paths = [f"evidence/{r.check_id}.json" for r in results]

    manifest = {
        "bundle_version": "1",
        "tool": {"name": tool_name, "version": tool_version},
        "target": target_info,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contents": [
            "manifest.json",
            "results.json",
            "results.sarif",
            "snapshot.json",
            "summary.txt",
        ] + evidence_paths,
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("results.json", json.dumps(document, indent=2))
        zf.writestr("results.sarif", json.dumps(sarif_doc, indent=2))
        zf.writestr("snapshot.json", json.dumps(snapshot, indent=2))
        zf.writestr("summary.txt", _summary_text(results, target_info, summary))
        for r in results:
            ev_doc = {
                "check_id": r.check_id,
                "title": r.title,
                "status": r.status.value,
                "severity": r.severity.value,
                "benchmark_control_id": r.benchmark_control_id,
                "nist_800_53_controls": r.nist_800_53_controls,
                "fedramp_control": r.fedramp_control,
                "actual": r.actual,
                "expected": r.expected,
                "evidence": r.evidence,
            }
            zf.writestr(f"evidence/{r.check_id}.json", json.dumps(ev_doc, indent=2))
    return buf.getvalue()


def write_bundle(
    path: str,
    document: dict,
    results,
    target_info: dict,
    summary: dict,
    snapshot: dict,
    tool_name: str,
    tool_version: str,
) -> None:
    data = build_bundle(document, results, target_info, summary, snapshot, tool_name, tool_version)
    with open(path, "wb") as f:
        f.write(data)
