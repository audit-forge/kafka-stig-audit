# Contributing to kafka-stig-audit

Thank you for your interest in improving Kafka security tooling.

## Ways to Contribute

- **New controls** — Add checks for uncovered security areas
- **Improved detection** — Better heuristics for existing checks
- **Bug fixes** — Fix incorrect assessments or runner failures
- **Documentation** — Improve benchmark guidance and remediation steps
- **Framework mappings** — Corrections to NIST/CMMC/MITRE mappings
- **Testing** — Add test cases for edge conditions

## Development Setup

```bash
git clone https://github.com/audit-forge/kafka-stig-audit
cd kafka-stig-audit
python -m pytest test/
```

No third-party packages required for runtime. Testing:
```bash
pip install pytest
```

## Adding a New Check

1. Choose a check category (`auth`, `encryption`, `authz`, `network`, `logging`, `zookeeper`, `container`)
2. Add the check to the appropriate `checks/` file
3. Use the `KF-CATEGORY-NNN` naming convention
4. Add a framework mapping entry in `mappings/frameworks.py`
5. Add the check title to `checks/container.py` `_CONT_CHECKS` if it's a container check
6. Write a test in `test/`

### Check Template

```python
def _check_example(self, props: dict) -> list[CheckResult]:
    """KF-CAT-NNN: Brief description."""
    value = props.get("kafka.config.key", "default")
    status = Status.PASS if value == "expected" else Status.FAIL
    return [CheckResult(
        check_id="KF-CAT-NNN",
        title="Human-readable control title",
        status=status,
        severity=Severity.HIGH,
        benchmark_control_id="N.M",
        cis_id="cis-kafka-1.0-N.M",
        fedramp_control="XX-N",
        nist_800_53_controls=["XX-N", "XX-M"],
        description="What this control checks and why.",
        rationale="Security justification for this control.",
        actual=f"kafka.config.key={value!r}",
        expected="expected value",
        remediation="How to fix this if failed.",
        references=[
            "CIS Apache Kafka Container Benchmark v1.0 §N.M",
            "https://kafka.apache.org/documentation/#...",
            "NIST SP 800-53 Rev 5 XX-N",
        ],
        category="CategoryName",
        evidence_type="runtime-config",
        evidence=[self.evidence("server.properties.config.key", f"value={value!r}", "cat /etc/kafka/server.properties")],
    )]
```

### Framework Mapping Template

```python
"KF-CAT-NNN": {
    # Brief rationale comment
    # 800-53: XX-N → 800-171: 3.X.Y (explanation)
    # CMMC Level N
    "nist_800_171": ["3.X.Y"],
    "cmmc_level": N,
    # T1234: Technique Name — why this technique is relevant
    "mitre_attack": ["T1234"],
    # D3-XYZ: D3FEND Technique
    "mitre_d3fend": ["D3-XYZ"],
},
```

## Benchmark Control Format

When adding controls to `benchmarks/CIS_Apache_Kafka_Container_Benchmark_v1.0.md`:

- **Profile**: Level 1 (baseline) or Level 2 (enhanced)
- **Severity**: CRITICAL/HIGH/MEDIUM/LOW
- Include a brief **Description**, **Rationale**, **Assessment**, and **Remediation**
- Map to framework controls in a **Framework Mappings** line

## Testing

Tests live in `test/`. Run with:
```bash
python -m pytest test/ -v
```

Each checker module should have a corresponding test file that uses a mock runner
to test PASS, FAIL, and WARN conditions without requiring a live Kafka cluster.

## Code Style

- Standard Python 3.9+
- No third-party runtime dependencies
- Type hints where they add clarity
- Docstrings on public functions
- Check IDs must follow `KF-CATEGORY-NNN` pattern

## Pull Request Process

1. Fork the repository
2. Create a branch: `git checkout -b feat/add-kf-auth-006`
3. Make changes, add tests
4. Run: `python -m pytest test/ -v`
5. Open a PR with a clear description of what the check detects and why

## Reporting Security Issues

See SECURITY.md for vulnerability reporting guidelines.

## Code of Conduct

Be respectful. Security tooling is a sensitive domain — focus on improving
the tool, not attacking contributors.
