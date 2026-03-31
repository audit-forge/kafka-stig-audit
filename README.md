# kafka-stig-audit

Apache Kafka container security audit tool. Automated checks against the
CIS Apache Kafka Container Benchmark v1.0 with NIST 800-53, NIST 800-171,
CMMC 2.0, and MITRE ATT&CK/D3FEND framework mappings.

> **Draft / Pre-release.** This tool is published for evaluation and community
> feedback. Controls, scoring, and remediation guidance may change.

## Features

- **32 automated checks** across Authentication, Encryption, Authorization,
  Network, Logging, ZooKeeper, and Container Runtime security domains
- **Three assessment modes**: Docker container, Kubernetes pod, or direct broker connection
- **Full framework mappings**: NIST 800-53, NIST 800-171 Rev 2, CMMC 2.0, MITRE ATT&CK, D3FEND
- **CVE/KEV integration**: NVD API v2 + CISA KEV catalog with 24-hour caching
- **Multiple output formats**: terminal, JSON, SARIF 2.1.0, CSV (21 columns), evidence ZIP bundle
- **KRaft-aware**: ZooKeeper checks automatically skipped in KRaft mode

## Quick Start

```bash
# Clone the repository
git clone https://github.com/audit-forge/kafka-stig-audit
cd kafka-stig-audit

# Run against a Docker container
python3 audit.py --mode docker --container my-kafka

# Run against a Kubernetes pod
python3 audit.py --mode kubectl --pod kafka-0 --namespace kafka

# Run against a broker directly
python3 audit.py --mode direct --host kafka.internal --port 9093

# Save all output formats
python3 audit.py --mode docker --container my-kafka \
  --json results.json \
  --sarif results.sarif \
  --csv results.csv \
  --bundle audit-bundle.zip
```

## Requirements

- Python 3.10+
- No third-party runtime dependencies (standard library only)
- `docker` CLI (docker mode) or `kubectl` (kubectl mode)
- Kafka CLI tools in PATH (or specify `--command-prefix`):
  - `kafka-broker-api-versions`
  - `kafka-configs`
  - `kafka-acls`
  - `kafka-topics`

## Command-Line Options

```
usage: audit.py [-h] [--mode {docker,kubectl,direct}] [--container CONTAINER]
                [--pod POD] [--namespace NAMESPACE] [--host HOST] [--port PORT]
                [--broker-id BROKER_ID] [--command-prefix COMMAND_PREFIX]
                [--json FILE] [--sarif FILE] [--bundle FILE] [--csv FILE]
                [--quiet] [--verbose] [--skip-cve]

Options:
  --mode            Assessment mode: docker (default), kubectl, or direct
  --container       Docker container name/ID (docker mode)
  --pod             Kubernetes pod name (kubectl mode)
  --namespace       Kubernetes namespace (default: default)
  --host            Kafka broker host (direct mode, default: 127.0.0.1)
  --port            Kafka broker port (direct mode, default: 9092)
  --broker-id       Broker entity ID for kafka-configs (default: 0)
  --command-prefix  Path prefix for kafka scripts (e.g. /opt/kafka/bin)
  --json FILE       Write JSON results to FILE
  --sarif FILE      Write SARIF 2.1.0 results to FILE
  --bundle FILE     Write evidence bundle ZIP to FILE
  --csv FILE        Write 21-column CSV to FILE
  --quiet           Suppress terminal output
  --verbose         Show runner commands
  --skip-cve        Skip CVE/KEV scan (faster)
```

## Controls Assessed

| Category | Controls | Check IDs |
|----------|----------|-----------|
| Authentication | 5 | KF-AUTH-001 through KF-AUTH-005 |
| Encryption | 5 | KF-ENC-001 through KF-ENC-005 |
| Authorization | 5 | KF-AUTHZ-001 through KF-AUTHZ-005 |
| Network | 4 | KF-NET-001 through KF-NET-004 |
| Logging | 3 | KF-LOG-001 through KF-LOG-003 |
| ZooKeeper | 3 | KF-ZK-001 through KF-ZK-003 |
| Container | 6 | KF-CONT-001 through KF-CONT-006 |
| Vulnerability | 1 | KF-VER-001 |
| **Total** | **32** | |

## Assessment Modes

### Docker Mode (Recommended)

Connects to a running Kafka container via `docker exec`. Reads `server.properties`
and runs Kafka CLI tools directly inside the container.

```bash
python3 audit.py --mode docker --container kafka-broker
```

### Kubernetes Mode

Connects to a Kafka pod via `kubectl exec`.

```bash
python3 audit.py --mode kubectl --pod kafka-0 --namespace kafka
```

### Direct Mode

Connects to the Kafka broker via network. Container-level checks (KF-CONT-*)
are skipped; log4j-based checks may be limited.

```bash
python3 audit.py --mode direct --host 192.168.1.100 --port 9093
```

## Output Formats

### Terminal (Default)

Color-coded executive summary + detailed findings with remediation guidance.

### JSON

Full structured results with framework mappings, evidence, and snapshot data.

```bash
python3 audit.py --mode docker --container kafka --json results.json
```

### SARIF 2.1.0

GitHub Code Scanning and GitLab SAST compatible format.

```bash
python3 audit.py --mode docker --container kafka --sarif results.sarif
```

### CSV (21 Columns)

Spreadsheet-ready with all framework mappings and CVE data.

```
Control_ID, Title, Severity, Result, Category, Actual, Expected,
Description, Rationale, CIS_Control, NIST_800_53, NIST_800_171,
CMMC_Level, MITRE_ATTACK, MITRE_D3FEND, Remediation, References,
CVE_ID, KEV_Score, CVE_Remediation, Local_Path
```

### Evidence Bundle (ZIP)

```bash
python3 audit.py --mode docker --container kafka --bundle audit-bundle.zip
```

Contents:
- `manifest.json` — bundle metadata
- `results.json` — full findings
- `results.sarif` — SARIF rendition
- `snapshot.json` — broker configuration snapshot
- `summary.txt` — plain-text report
- `evidence/KF-*.json` — per-check evidence files

## CVE/KEV Scanning

The tool detects the Kafka version via `kafka-broker-api-versions` and queries:

- **NVD API v2** for known CVEs matching "apache kafka \<version\>"
- **CISA KEV Catalog** for actively exploited vulnerabilities

Results are cached in `data/cve_cache.json` (24-hour TTL).

Set `NVD_API_KEY=<your-key>` for higher rate limits. See `docs/CVE_SCANNING.md`.

## Framework Mappings

Each control is mapped to:
- **NIST SP 800-53 Rev 5** — Federal security controls
- **NIST SP 800-171 Rev 2** — CUI protection requirements
- **CMMC 2.0** — Level 1 or 2 practices
- **MITRE ATT&CK** — Adversary techniques mitigated
- **MITRE D3FEND** — Defensive countermeasures implemented

CSV and JSON output include all mappings. See `mappings/frameworks.py` and
`mappings/CMMC-compliance-matrix.csv`.

## Project Structure

```
kafka-stig-audit/
├── audit.py                          # Main entry point
├── runner.py                         # KafkaRunner (docker/kubectl/direct)
├── checks/
│   ├── base.py                       # CheckResult, Status, Severity
│   ├── auth.py                       # KF-AUTH-* (5 controls)
│   ├── encryption.py                 # KF-ENC-* (5 controls)
│   ├── authz.py                      # KF-AUTHZ-* (5 controls)
│   ├── network.py                    # KF-NET-* (4 controls)
│   ├── logging_checks.py             # KF-LOG-* (3 controls)
│   ├── zookeeper.py                  # KF-ZK-* (3 controls)
│   ├── container.py                  # KF-CONT-* (6 controls)
│   └── cve_scanner.py                # CVE/KEV integration
├── mappings/
│   ├── frameworks.py                 # NIST/CMMC/MITRE data
│   ├── CMMC-compliance-matrix.csv    # CMMC 2.0 control matrix
│   └── MITRE-mappings.csv            # ATT&CK/D3FEND mappings
├── output/
│   ├── report.py                     # Terminal output
│   ├── sarif.py                      # SARIF 2.1.0
│   └── bundle.py                     # Evidence ZIP
├── benchmarks/
│   └── CIS_Apache_Kafka_Container_Benchmark_v1.0.md
├── docs/
│   ├── RUN_BENCHMARK.md
│   └── CVE_SCANNING.md
└── test/
    ├── test_auth.py
    ├── test_authz.py
    ├── test_encryption.py
    ├── test_logging.py
    ├── test_network.py
    ├── test_runner.py
    └── test_zookeeper.py
```

## Disclaimer

This tool is provided for security assessment and compliance purposes in authorized
environments only. Always obtain proper authorization before running security assessments.
See DISCLAIMER.md for full details.

## Contributing

Contributions welcome. See CONTRIBUTING.md for guidelines.

## License

Apache 2.0. See LICENSE.
