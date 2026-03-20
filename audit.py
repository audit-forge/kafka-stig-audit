#!/usr/bin/env python3
"""kafka-stig-audit — Apache Kafka container security audit tool."""
import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

from runner import KafkaRunner
from checks import ALL_CHECKERS
from mappings.frameworks import enrich_all
from output import report
from output.sarif import write_sarif
from output.bundle import write_bundle

TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "2026-03-19"


def parse_args():
    p = argparse.ArgumentParser(description="Apache Kafka CIS-style container security audit")
    p.add_argument("--mode", choices=["docker", "kubectl", "direct"], default="docker")
    p.add_argument("--container", help="Docker container name/ID (docker mode)")
    p.add_argument("--pod", help="Kubernetes pod name (kubectl mode)")
    p.add_argument("--namespace", default="default", help="Kubernetes namespace (kubectl mode)")
    p.add_argument("--host", default="127.0.0.1", help="Kafka broker host (direct mode)")
    p.add_argument("--port", type=int, default=9092, help="Kafka broker port (direct mode)")
    p.add_argument("--broker-id", default="0", help="Broker entity name for kafka-configs (default: 0)")
    p.add_argument("--command-prefix", default="", help="Path prefix for kafka scripts (e.g. /opt/kafka/bin)")
    p.add_argument("--json", metavar="FILE", help="Write raw results to FILE")
    p.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 results to FILE")
    p.add_argument("--bundle", metavar="FILE", help="Write evidence bundle (zip) to FILE")
    p.add_argument(
        "--csv", metavar="FILE",
        help="Write CSV results to FILE (includes NIST 800-171, CMMC, MITRE columns)"
    )
    p.add_argument("--quiet", action="store_true", help="Suppress terminal output")
    p.add_argument("--verbose", action="store_true", help="Show runner commands")
    p.add_argument(
        "--skip-cve", action="store_true",
        help="Skip CVE/KEV vulnerability scan (faster, compliance-only)"
    )
    return p.parse_args()


def build_target_info(args, runner, timestamp: str) -> dict:
    return {
        "mode": args.mode,
        "namespace": args.namespace if args.mode == "kubectl" else None,
        "container": args.container,
        "pod": args.pod,
        "host": args.host if args.mode == "direct" else None,
        "port": args.port if args.mode == "direct" else None,
        "display_name": args.container or args.pod or f"{args.host}:{args.port}",
        "timestamp": timestamp,
        "connected": runner.test_connection(),
        "last_error": runner.last_error,
    }


def summarize(results) -> dict:
    status_counts = Counter(r.status.value for r in results)
    severity_counts = Counter(r.severity.value for r in results)
    actionable = sum(status_counts.get(k, 0) for k in ("FAIL", "WARN", "ERROR"))
    if status_counts.get("FAIL", 0) or status_counts.get("ERROR", 0):
        risk_posture = "HIGH RISK"
    elif status_counts.get("WARN", 0):
        risk_posture = "REVIEW REQUIRED"
    else:
        risk_posture = "BASELINE ACCEPTABLE"
    return {
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "actionable_findings": actionable,
        "risk_posture": risk_posture,
    }


def write_csv(filepath: str, results: list, target_info: dict) -> None:
    """Write audit results to a 21-column CSV file."""
    fieldnames = [
        "Control_ID",
        "Title",
        "Severity",
        "Result",
        "Category",
        "Actual",
        "Expected",
        "Description",
        "Rationale",
        "CIS_Control",
        "NIST_800_53",
        "NIST_800_171",
        "CMMC_Level",
        "MITRE_ATTACK",
        "MITRE_D3FEND",
        "Remediation",
        "References",
        "CVE_ID",
        "KEV_Score",
        "CVE_Remediation",
        "Local_Path",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "Control_ID": r.check_id,
                "Title": r.title,
                "Severity": r.severity.value,
                "Result": r.status.value,
                "Category": r.category,
                "Actual": r.actual,
                "Expected": r.expected,
                "Description": r.description,
                "Rationale": r.rationale,
                "CIS_Control": r.cis_id or "",
                "NIST_800_53": "; ".join(r.nist_800_53_controls),
                "NIST_800_171": "; ".join(r.nist_800_171),
                "CMMC_Level": str(r.cmmc_level) if r.cmmc_level is not None else "",
                "MITRE_ATTACK": "; ".join(r.mitre_attack),
                "MITRE_D3FEND": "; ".join(r.mitre_d3fend),
                "Remediation": r.remediation,
                "References": "; ".join(r.references),
                "CVE_ID": "; ".join(r.cve_ids) if r.cve_ids else "",
                "KEV_Score": r.kev_score or "",
                "CVE_Remediation": r.cve_remediation or "",
                "Local_Path": r.local_path or "",
            })


def main():
    args = parse_args()
    timestamp = datetime.now(timezone.utc).isoformat()
    runner = KafkaRunner(
        mode=args.mode,
        container=args.container,
        pod=args.pod,
        namespace=args.namespace,
        host=args.host,
        port=args.port,
        broker_id=args.broker_id,
        command_prefix=args.command_prefix,
        verbose=args.verbose,
    )

    results = []
    for checker_cls in ALL_CHECKERS:
        results.extend(checker_cls(runner).run())

    # Enrich results with NIST 800-171, CMMC, and MITRE framework mappings
    enrich_all(results)

    # CVE/KEV vulnerability scan
    if not args.skip_cve:
        from checks.cve_scanner import detect_kafka_version, fetch_cve_data, load_kev_catalog, cve_to_check_result
        cache_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(cache_dir, exist_ok=True)

        version = detect_kafka_version(runner)
        if version:
            print(f"[cve] Detected Kafka version: {version}")
            kev = load_kev_catalog(cache_dir)
            cves = fetch_cve_data("apache kafka", version, cache_dir)
            local_path = "/opt/kafka/bin/kafka-server-start.sh"
            cve_result = cve_to_check_result(cves, kev, "apache kafka", version, local_path)
            results.append(cve_result)
        else:
            print("[cve] Could not detect Kafka version, skipping CVE scan")

    results = sorted(results, key=lambda r: (r.status.value, r.severity.value, r.check_id))
    target_info = build_target_info(args, runner, timestamp)
    summary = summarize(results)

    if not args.quiet:
        report.render(results, target_info, summary)

    if args.json or args.sarif or args.bundle:
        snapshot = runner.snapshot()
        document = {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": "kafka-stig-audit",
                "version": TOOL_VERSION,
            },
            "target": target_info,
            "summary": summary,
            "snapshot": snapshot,
            "results": [r.to_dict() for r in results],
        }

        if args.json:
            with open(args.json, "w") as f:
                json.dump(document, f, indent=2)
            print(f"[json]   Written to {args.json}")

        if args.sarif:
            write_sarif(args.sarif, results, target_info, "kafka-stig-audit", TOOL_VERSION)
            print(f"[sarif]  Written to {args.sarif}")

        if args.bundle:
            write_bundle(
                args.bundle,
                document,
                results,
                target_info,
                summary,
                snapshot,
                "kafka-stig-audit",
                TOOL_VERSION,
            )
            print(f"[bundle] Written to {args.bundle}")

    if args.csv:
        write_csv(args.csv, results, target_info)
        print(f"[csv]    Written to {args.csv}")


if __name__ == "__main__":
    main()
