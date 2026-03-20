from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: Status
    severity: Severity
    benchmark_control_id: Optional[str] = None
    cis_id: Optional[str] = None
    fedramp_control: Optional[str] = None
    nist_800_53_controls: list[str] = field(default_factory=list)
    # CMMC 2.0 / NIST 800-171 Rev 2 mappings
    nist_800_171: list[str] = field(default_factory=list)
    cmmc_level: Optional[int] = None
    # MITRE framework mappings
    mitre_attack: list[str] = field(default_factory=list)
    mitre_d3fend: list[str] = field(default_factory=list)
    description: str = ""
    actual: str = ""
    expected: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    category: str = ""
    evidence_type: str = "runtime-config"
    evidence: list[dict] = field(default_factory=list)
    rationale: str = ""
    # CVE/KEV vulnerability fields
    cve_ids: list[str] = field(default_factory=list)
    kev_score: str = ""
    cve_remediation: str = ""
    local_path: str = ""

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "benchmark_control_id": self.benchmark_control_id,
            "cis_id": self.cis_id,
            "fedramp_control": self.fedramp_control,
            "nist_800_53_controls": self.nist_800_53_controls,
            "nist_800_171": self.nist_800_171,
            "cmmc_level": self.cmmc_level,
            "mitre_attack": self.mitre_attack,
            "mitre_d3fend": self.mitre_d3fend,
            "description": self.description,
            "rationale": self.rationale,
            "actual": self.actual,
            "expected": self.expected,
            "remediation": self.remediation,
            "references": self.references,
            "category": self.category,
            "evidence_type": self.evidence_type,
            "evidence": self.evidence,
            "cve_ids": self.cve_ids,
            "kev_score": self.kev_score,
            "cve_remediation": self.cve_remediation,
            "local_path": self.local_path,
        }


class BaseChecker:
    def __init__(self, runner):
        self.runner = runner

    def run(self) -> list[CheckResult]:
        raise NotImplementedError

    def evidence(self, source: str, value, command: str | None = None) -> dict:
        item = {"source": source, "value": value}
        if command:
            item["command"] = command
        return item
