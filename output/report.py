from collections import Counter

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
STATUS_RANK = {"FAIL": 0, "ERROR": 1, "WARN": 2, "PASS": 3, "SKIP": 4}


def _top_findings(results, limit=5):
    actionable = [r for r in results if r.status.value in {"FAIL", "ERROR", "WARN"}]
    return sorted(
        actionable,
        key=lambda r: (STATUS_RANK.get(r.status.value, 9), SEVERITY_RANK.get(r.severity.value, 9), r.check_id),
    )[:limit]


def render(results, target_info, summary=None):
    summary = summary or {}
    print("kafka-stig-audit — assessment report")
    print(f"Target: {target_info.get('display_name', 'unknown')}")
    print(
        f"Mode: {target_info.get('mode')} | Connected: {target_info.get('connected')} | "
        f"Generated: {target_info.get('timestamp')}"
    )
    print()

    status_counts = summary.get("status_counts") or Counter(r.status.value for r in results)
    sev_counts = summary.get("severity_counts") or Counter(r.severity.value for r in results)
    print("Executive summary:")
    print(
        f"  PASS {status_counts.get('PASS', 0)} | FAIL {status_counts.get('FAIL', 0)} | "
        f"WARN {status_counts.get('WARN', 0)} | ERROR {status_counts.get('ERROR', 0)} | SKIP {status_counts.get('SKIP', 0)}"
    )
    print(
        f"  CRITICAL {sev_counts.get('CRITICAL', 0)} | HIGH {sev_counts.get('HIGH', 0)} | "
        f"MEDIUM {sev_counts.get('MEDIUM', 0)} | LOW {sev_counts.get('LOW', 0)} | INFO {sev_counts.get('INFO', 0)}"
    )
    if summary:
        print(
            f"  Risk posture: {summary.get('risk_posture', 'UNKNOWN')} | "
            f"Actionable findings: {summary.get('actionable_findings', 0)}"
        )
    print()

    top = _top_findings(results)
    if top:
        print("Top findings:")
        for r in top:
            print(f"  - [{r.status.value}/{r.severity.value}] {r.check_id} ({r.benchmark_control_id or '-'}) {r.title}")
        print()

    print("Detailed findings:")
    for r in sorted(results, key=lambda r: (STATUS_RANK.get(r.status.value, 9), SEVERITY_RANK.get(r.severity.value, 9), r.check_id)):
        print(f"[{r.status.value}] {r.check_id} ({r.benchmark_control_id or '-'}) {r.title}")
        print(f"  Severity: {r.severity.value} | Category: {r.category} | Evidence: {r.evidence_type}")
        if r.actual:
            print(f"  Actual: {r.actual}")
        if r.expected:
            print(f"  Expected: {r.expected}")
        if r.remediation:
            print(f"  Remediation: {r.remediation}")
        if r.fedramp_control or r.nist_800_53_controls:
            print(
                f"  Control mapping: fedramp={r.fedramp_control or '-'} | "
                f"nist={', '.join(r.nist_800_53_controls) if r.nist_800_53_controls else '-'}"
            )
        if r.evidence:
            print(f"  Evidence captured: {len(r.evidence)} item(s)")
        print()
