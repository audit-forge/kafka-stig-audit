# Running the Kafka Security Benchmark

This guide covers detailed usage of `kafka-stig-audit` including environment
setup, assessment modes, output formats, and interpreting results.

## Prerequisites

### Python

Python 3.9 or later required. No third-party packages needed.

```bash
python3 --version
```

### Kafka CLI Tools

The tool uses standard Kafka CLI tools. These must be available either in the
container (docker/kubectl modes) or in your PATH (direct mode):

- `kafka-broker-api-versions` — version detection and connectivity test
- `kafka-configs` — broker configuration enumeration
- `kafka-acls` — ACL enumeration
- `kafka-topics` — topic enumeration

If Kafka CLI tools are not in PATH, use `--command-prefix`:

```bash
python audit.py --mode direct --host kafka.internal \
  --command-prefix /opt/kafka/bin
```

## Assessment Modes

### Docker Mode

The default mode. Connects to a running Kafka Docker container via `docker exec`.

```bash
python audit.py --mode docker --container <container-name-or-id>
```

The tool:
1. Reads `server.properties` from common locations inside the container
2. Runs Kafka CLI tools via `docker exec`
3. Runs `docker inspect` for container security checks

**Requirements:**
- Docker CLI installed and in PATH
- Permission to `docker exec` into the container
- Kafka CLI tools available inside the container

### Kubernetes Mode

Connects to a Kafka pod via `kubectl exec`.

```bash
python audit.py --mode kubectl \
  --pod kafka-0 \
  --namespace kafka
```

The tool finds the Kafka container by name (contains "kafka"). If multiple
containers match, the first one is used.

**Requirements:**
- `kubectl` installed and configured with cluster access
- Permission to `exec` into the pod
- Kafka CLI tools available inside the pod

### Direct Mode

Connects to Kafka broker via network. Use when container access is not available.

```bash
python audit.py --mode direct \
  --host kafka.internal \
  --port 9093
```

**Limitations in direct mode:**
- `server.properties` cannot be read (some checks will WARN)
- Container runtime checks (KF-CONT-*) are SKIP
- Log4j checks require file access (will WARN)

## Output Formats

### Terminal Output (Default)

```
kafka-stig-audit — assessment report
Target: my-kafka-container
Mode: docker | Connected: True | Generated: 2026-03-19T18:00:00Z

Executive summary:
  PASS 12 | FAIL 8 | WARN 5 | ERROR 0 | SKIP 7
  CRITICAL 3 | HIGH 8 | MEDIUM 5 | LOW 2 | INFO 1
  Risk posture: HIGH RISK | Actionable findings: 13

Top findings:
  - [FAIL/CRITICAL] KF-AUTH-001 (2.1) SASL authentication enabled on client-facing listeners
  - [FAIL/CRITICAL] KF-AUTHZ-003 (4.3) Default deny policy enforced (allow.everyone.if.no.acl.found=false)
  ...
```

Use `--quiet` to suppress terminal output when only file outputs are needed.

### JSON Output

```bash
python audit.py --mode docker --container kafka --json results.json
```

JSON schema:
```json
{
  "schema_version": "2026-03-19",
  "tool": { "name": "kafka-stig-audit", "version": "0.1.0" },
  "target": {
    "mode": "docker",
    "container": "my-kafka",
    "display_name": "my-kafka",
    "timestamp": "...",
    "connected": true
  },
  "summary": {
    "status_counts": { "PASS": 12, "FAIL": 8, ... },
    "severity_counts": { "CRITICAL": 3, ... },
    "actionable_findings": 13,
    "risk_posture": "HIGH RISK"
  },
  "snapshot": { ... },
  "results": [ { ... } ]
}
```

### SARIF 2.1.0

Compatible with GitHub Code Scanning and GitLab SAST.

```bash
python audit.py --mode docker --container kafka --sarif results.sarif
```

Upload to GitHub:
```yaml
# .github/workflows/kafka-audit.yml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
    category: kafka-stig-audit
```

### CSV Output (21 Columns)

```bash
python audit.py --mode docker --container kafka --csv results.csv
```

Columns:
```
Control_ID    — KF-AUTH-001, etc.
Title         — Human-readable control title
Severity      — CRITICAL/HIGH/MEDIUM/LOW/INFO
Result        — PASS/FAIL/WARN/ERROR/SKIP
Category      — Authentication/Encryption/etc.
Actual        — What was observed
Expected      — What should be present
Description   — Control description
Rationale     — Why this matters
CIS_Control   — CIS benchmark control reference
NIST_800_53   — NIST 800-53 Rev 5 controls (semicolon-separated)
NIST_800_171  — NIST 800-171 Rev 2 practices
CMMC_Level    — CMMC 2.0 level (1 or 2)
MITRE_ATTACK  — ATT&CK technique IDs
MITRE_D3FEND  — D3FEND technique IDs
Remediation   — Remediation guidance
References    — Reference documents
CVE_ID        — CVE identifiers (KF-VER-001 only)
KEV_Score     — CISA KEV status
CVE_Remediation — CVE-specific remediation
Local_Path    — Binary/file path assessed
```

### Evidence Bundle (ZIP)

```bash
python audit.py --mode docker --container kafka --bundle audit-bundle.zip
```

Bundle contents:
```
audit-bundle.zip
├── manifest.json       # Bundle metadata and contents index
├── results.json        # Full findings document
├── results.sarif       # SARIF 2.1.0 format
├── snapshot.json       # Broker configuration snapshot
├── summary.txt         # Human-readable plain-text report
└── evidence/
    ├── KF-AUTH-001.json
    ├── KF-AUTH-002.json
    └── ...              # One JSON file per check
```

## Interpreting Results

### Risk Posture

| Posture | Condition |
|---------|-----------|
| HIGH RISK | Any FAIL or ERROR findings |
| REVIEW REQUIRED | Only WARN findings (no FAIL/ERROR) |
| BASELINE ACCEPTABLE | All checks PASS or SKIP |

### Severity Levels

| Severity | Meaning |
|----------|---------|
| CRITICAL | Direct, immediate exploitation path |
| HIGH | Significant security weakness |
| MEDIUM | Security weakness requiring attention |
| LOW | Best practice gap |
| INFO | Informational — no security impact |

### Result States

| Result | Meaning |
|--------|---------|
| PASS | Control is properly implemented |
| FAIL | Control is not implemented or misconfigured |
| WARN | Partial implementation or could not determine |
| ERROR | Check could not run (connectivity/permission issue) |
| SKIP | Check not applicable (e.g., KRaft mode skips ZK checks) |

## Prioritizing Remediations

1. Fix all **CRITICAL** findings first — these represent direct attack paths
2. Address **FAIL** findings in severity order (HIGH → MEDIUM → LOW)
3. Review **WARN** findings and determine if action is needed
4. Document accepted risks for findings that cannot be immediately remediated

### Critical Controls (Start Here)

These controls, if failed, indicate fundamental security gaps:

- `KF-AUTH-001` — No authentication on any listener
- `KF-AUTH-003` — PLAINTEXT listeners in use
- `KF-AUTHZ-001` — No ACL authorizer configured
- `KF-AUTHZ-003` — Default allow policy (all resources open)
- `KF-CONT-002` — Container running in privileged mode

## CI/CD Integration

### GitHub Actions

```yaml
name: Kafka Security Audit

on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday
  pull_request:
    paths: ['k8s/kafka/**', 'docker/kafka/**']

jobs:
  audit:
    runs-on: ubuntu-latest
    services:
      kafka:
        image: confluentinc/cp-kafka:7.5.0
        env:
          KAFKA_BROKER_ID: 0
          KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
        ports:
          - 9092:9092

    steps:
      - uses: actions/checkout@v4

      - name: Run Kafka security audit
        run: |
          python audit.py \
            --mode direct \
            --host localhost --port 9092 \
            --skip-cve \
            --sarif kafka-audit.sarif \
            --json kafka-audit.json

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: kafka-audit.sarif
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key for higher rate limits |
| `KUBECONFIG` | Kubernetes config file path |
| `DOCKER_HOST` | Docker daemon socket (default: unix:///var/run/docker.sock) |

## Troubleshooting

### "kafka-configs: command not found"

Specify the command prefix:
```bash
python audit.py --mode docker --container kafka \
  --command-prefix /opt/kafka/bin
```

Or for Bitnami images:
```bash
  --command-prefix /opt/bitnami/kafka/bin
```

### "Could not read server.properties"

The tool tries these paths:
- `/opt/kafka/config/server.properties`
- `/etc/kafka/server.properties`
- `/kafka/config/server.properties`
- `/opt/bitnami/kafka/config/server.properties`

If your Kafka uses a different path, mount it to one of these locations
or use `--mode direct` to bypass the file read.

### Connection Timeout

For direct mode:
```bash
python audit.py --mode direct --host kafka.internal --port 9092 --skip-cve --verbose
```

The `--verbose` flag shows all commands being run. Check firewall rules if
`kafka-broker-api-versions` fails.

### KRaft Mode

If your Kafka cluster uses KRaft (no ZooKeeper), ZooKeeper checks
(KF-ZK-001, KF-ZK-002, KF-ZK-003) will automatically be SKIP when
`process.roles` is detected in `server.properties`.
