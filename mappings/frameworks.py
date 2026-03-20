"""
Framework mapping data for kafka-stig-audit.

Provides NIST SP 800-171 Rev 2, CMMC 2.0, MITRE ATT&CK, and MITRE D3FEND
mappings for each Kafka audit control (keyed by check_id).

Mapping rationale
-----------------
NIST 800-171 Rev 2 (110 controls / 14 families) — derived from the NIST
  SP 800-171 Rev 2 Appendix D cross-reference to NIST SP 800-53 Rev 4/5.

CMMC 2.0 levels:
  Level 1 — 17 "basic safeguarding" practices (subset of FAR 52.204-21 + 800-171)
  Level 2 — all 110 NIST SP 800-171 Rev 2 practices
  Level 3 — NIST SP 800-172 additions (24+ enhanced practices)

MITRE ATT&CK — Enterprise / Containers matrix; techniques with direct
  defensive relationship to the control are listed.

MITRE D3FEND — Defensive countermeasure knowledge graph (d3fend.mitre.org);
  D3FEND techniques the control actively implements.

Key 800-53 → 800-171 cross-references used:
  AC-2, AC-3, AC-6  → 3.1.1, 3.1.2, 3.1.5, 3.1.6
  AU-2, AU-3, AU-12 → 3.3.1, 3.3.2
  CM-2, CM-3, CM-6, CM-7 → 3.4.1, 3.4.2, 3.4.3, 3.4.6, 3.4.7
  IA-2, IA-3, IA-5  → 3.5.1, 3.5.2, 3.5.3, 3.5.7, 3.5.10
  SC-7, SC-8         → 3.13.1, 3.13.5, 3.13.8
  SI-2               → 3.14.1
"""

FRAMEWORK_MAP: dict[str, dict] = {

    # ------------------------------------------------------------------ #
    # Authentication (auth.py)
    # ------------------------------------------------------------------ #

    "KF-AUTH-001": {
        # SASL authentication enabled on client-facing listeners
        # 800-53: IA-2, AC-3 → 800-171: 3.5.1, 3.5.2, 3.1.1
        # CMMC L1: 3.5.1 (identify information system users) is Level 1
        "nist_800_171": ["3.5.1", "3.5.2", "3.1.1"],
        "cmmc_level": 1,
        # T1133: External Remote Services — unauthenticated Kafka accessible externally
        # T1078: Valid Accounts — absence of auth means no credentials needed
        "mitre_attack": ["T1133", "T1078"],
        # D3-UAP: User Account Permissions — authentication gates access
        # D3-MFA: Multi-Factor Authentication (SASL with SCRAM)
        "mitre_d3fend": ["D3-UAP", "D3-NI"],
    },

    "KF-AUTH-002": {
        # SASL mechanism SCRAM-SHA-256/512 or GSSAPI
        # 800-53: IA-5 → 800-171: 3.5.3, 3.5.7, 3.5.10
        # CMMC L2: IA-5 controls → 3.5.7/3.5.10 (password complexity/change)
        "nist_800_171": ["3.5.3", "3.5.7", "3.5.10"],
        "cmmc_level": 2,
        # T1110: Brute Force — PLAIN passwords base64-decodable from captures
        # T1040: Network Sniffing — PLAIN credentials visible in capture
        "mitre_attack": ["T1110", "T1040"],
        # D3-SPP: Strong Password Policy
        # D3-MH: Message Hardening — SCRAM prevents credential exposure
        "mitre_d3fend": ["D3-SPP", "D3-MH"],
    },

    "KF-AUTH-003": {
        # No PLAINTEXT protocol listeners
        # 800-53: SC-8 → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8", "3.5.1"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — PLAINTEXT allows complete traffic capture
        # T1557: Adversary-in-the-Middle — PLAINTEXT enables active interception
        "mitre_attack": ["T1040", "T1557"],
        # D3-ET: Encrypted Tunnels — eliminate plaintext listeners
        # D3-NI: Network Isolation
        "mitre_d3fend": ["D3-ET", "D3-NI"],
    },

    "KF-AUTH-004": {
        # Inter-broker authentication enabled
        # 800-53: SC-8, IA-3 → 800-171: 3.13.8, 3.5.2
        # CMMC L2
        "nist_800_171": ["3.13.8", "3.5.2"],
        "cmmc_level": 2,
        # T1557: Adversary-in-the-Middle — rogue broker joins without auth
        # T1040: Network Sniffing — unencrypted replication traffic
        "mitre_attack": ["T1557", "T1040"],
        # D3-ET: Encrypted Tunnels — SASL_SSL for inter-broker
        # D3-MH: Message Hardening
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "KF-AUTH-005": {
        # ZooKeeper authentication enabled
        # 800-53: AC-3, IA-2 → 800-171: 3.1.1, 3.5.1
        # CMMC L1
        "nist_800_171": ["3.1.1", "3.5.1"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — unauthenticated ZK allows cluster manipulation
        # T1484: Domain Policy Modification (ZK stores cluster policies)
        "mitre_attack": ["T1078", "T1484"],
        # D3-UAP: User Account Permissions
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-UAP", "D3-ACH"],
    },

    # ------------------------------------------------------------------ #
    # Encryption (encryption.py)
    # ------------------------------------------------------------------ #

    "KF-ENC-001": {
        # TLS enabled for client connections
        # 800-53: SC-8, SC-8(1) → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — TLS prevents credential/data interception
        # T1557: Adversary-in-the-Middle
        "mitre_attack": ["T1040", "T1557"],
        # D3-ET: Encrypted Tunnels
        # D3-MH: Message Hardening
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "KF-ENC-002": {
        # TLS for inter-broker communication
        # 800-53: SC-8 → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — replication traffic exposed
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — inter-broker TLS
        "mitre_d3fend": ["D3-ET"],
    },

    "KF-ENC-003": {
        # Strong TLS cipher suites
        # 800-53: SC-8, CM-6 → 800-171: 3.13.8, 3.4.2
        # CMMC L2
        "nist_800_171": ["3.13.8", "3.4.2"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — weak ciphers may be broken post-capture
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — strong cipher configuration
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ET", "D3-ACH"],
    },

    "KF-ENC-004": {
        # TLS client certificate validation
        # 800-53: SC-17, IA-5 → 800-171: 3.5.3, 3.13.8
        # CMMC L2
        "nist_800_171": ["3.5.3", "3.13.8"],
        "cmmc_level": 2,
        # T1078: Valid Accounts — client certs add layer beyond SASL
        "mitre_attack": ["T1078"],
        # D3-MFA: Multi-Factor Authentication (TLS cert + SASL = two factors)
        # D3-ET: Encrypted Tunnels
        "mitre_d3fend": ["D3-MFA", "D3-ET"],
    },

    "KF-ENC-005": {
        # ZooKeeper TLS
        # 800-53: SC-8 → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — ZooKeeper metadata exposed
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — ZooKeeper TLS
        "mitre_d3fend": ["D3-ET"],
    },

    # ------------------------------------------------------------------ #
    # Authorization (authz.py)
    # ------------------------------------------------------------------ #

    "KF-AUTHZ-001": {
        # ACL authorizer enabled
        # 800-53: AC-3, AC-6 → 800-171: 3.1.1, 3.1.2, 3.1.5
        # CMMC L1
        "nist_800_171": ["3.1.1", "3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — auth without authz allows full topic access
        # T1530: Data from Cloud Storage Object (Kafka as event store)
        "mitre_attack": ["T1078", "T1530"],
        # D3-RBAC: Role-Based Access Control
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-RBAC", "D3-UAP"],
    },

    "KF-AUTHZ-002": {
        # Super users restricted
        # 800-53: AC-6, AC-6(5) → 800-171: 3.1.5, 3.1.6
        # CMMC L1: 3.1.5 least privilege
        "nist_800_171": ["3.1.5", "3.1.6"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — compromised super user has unrestricted access
        # T1098: Account Manipulation — super user enables privilege manipulation
        "mitre_attack": ["T1078", "T1098"],
        # D3-UAP: User Account Permissions — restrict super user list
        "mitre_d3fend": ["D3-UAP"],
    },

    "KF-AUTHZ-003": {
        # Default deny policy
        # 800-53: AC-3, AC-6 → 800-171: 3.1.1, 3.1.2
        # CMMC L1
        "nist_800_171": ["3.1.1", "3.1.2"],
        "cmmc_level": 1,
        # T1530: Data from Cloud Storage Object — default allow exposes new topics
        "mitre_attack": ["T1530"],
        # D3-RBAC: Role-Based Access Control — deny-by-default
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-RBAC", "D3-ACH"],
    },

    "KF-AUTHZ-004": {
        # Topic-level ACLs configured
        # 800-53: AC-3, AC-6 → 800-171: 3.1.2, 3.1.5
        # CMMC L1
        "nist_800_171": ["3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1530: Data from Cloud Storage Object — unprotected topics allow exfil
        # T1078: Valid Accounts — credential reuse across topics
        "mitre_attack": ["T1530", "T1078"],
        # D3-RBAC: Role-Based Access Control — per-topic ACL grants
        "mitre_d3fend": ["D3-RBAC"],
    },

    "KF-AUTHZ-005": {
        # Cluster ACLs restricted
        # 800-53: AC-6(2), AC-3 → 800-171: 3.1.5, 3.1.2
        # CMMC L2: 3.1.5 is L1; AC-6(2) → L2 practice
        "nist_800_171": ["3.1.5", "3.1.2"],
        "cmmc_level": 2,
        # T1485: Data Destruction — ClusterAction can delete topics
        # T1078: Valid Accounts — admin operations via compromised principal
        "mitre_attack": ["T1485", "T1078"],
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-UAP"],
    },

    # ------------------------------------------------------------------ #
    # Network (network.py)
    # ------------------------------------------------------------------ #

    "KF-NET-001": {
        # Listeners not binding PLAINTEXT to all interfaces
        # 800-53: SC-7, CM-7 → 800-171: 3.13.1, 3.4.6
        # CMMC L1: 3.13.1 is Level 1
        "nist_800_171": ["3.13.1", "3.4.6"],
        "cmmc_level": 1,
        # T1133: External Remote Services — PLAINTEXT accessible externally
        # T1190: Exploit Public-Facing Application
        "mitre_attack": ["T1133", "T1190"],
        # D3-NI: Network Isolation
        # D3-NTF: Network Traffic Filtering
        "mitre_d3fend": ["D3-NI", "D3-NTF"],
    },

    "KF-NET-002": {
        # Advertised listeners configured
        # 800-53: SC-7, CM-6 → 800-171: 3.13.1, 3.4.2
        # CMMC L1
        "nist_800_171": ["3.13.1", "3.4.2"],
        "cmmc_level": 1,
        # T1133: External Remote Services — incorrect advertised host directs clients insecurely
        "mitre_attack": ["T1133"],
        # D3-NI: Network Isolation
        "mitre_d3fend": ["D3-NI"],
    },

    "KF-NET-003": {
        # JMX port secured
        # 800-53: CM-7, AC-17 → 800-171: 3.4.6, 3.4.7
        # CMMC L2
        "nist_800_171": ["3.4.6", "3.4.7"],
        "cmmc_level": 2,
        # T1219: Remote Access Software — JMX as management channel
        # T1609: Container Administration Command — JMX MBean invocation
        "mitre_attack": ["T1219", "T1609"],
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ACH"],
    },

    "KF-NET-004": {
        # Auto topic creation disabled
        # 800-53: CM-7 → 800-171: 3.4.6
        # CMMC L2
        "nist_800_171": ["3.4.6", "3.4.7"],
        "cmmc_level": 2,
        # T1530: Data from Cloud Storage Object — auto-created topics bypass ACL setup
        "mitre_attack": ["T1530"],
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ACH"],
    },

    # ------------------------------------------------------------------ #
    # Logging (logging_checks.py)
    # ------------------------------------------------------------------ #

    "KF-LOG-001": {
        # Log retention configured
        # 800-53: AU-11, AU-4 → 800-171: 3.3.1
        # CMMC L2
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1485: Data Destruction — insufficient retention may destroy forensic evidence
        "mitre_attack": ["T1485"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    "KF-LOG-002": {
        # Security events logged
        # 800-53: AU-2, AU-12 → 800-171: 3.3.1, 3.3.2
        # CMMC L2
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — inadequate logging enables detection evasion
        "mitre_attack": ["T1562.001"],
        # D3-ALCA: Application Log Audit
        # D3-DAM: Database Activity Monitoring (Kafka as data pipeline)
        "mitre_d3fend": ["D3-ALCA"],
    },

    "KF-LOG-003": {
        # Request logging enabled
        # 800-53: AU-3, AU-12 → 800-171: 3.3.1, 3.3.2
        # CMMC L2
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools
        "mitre_attack": ["T1562.001"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    # ------------------------------------------------------------------ #
    # ZooKeeper (zookeeper.py)
    # ------------------------------------------------------------------ #

    "KF-ZK-001": {
        # ZooKeeper SASL ACLs
        # 800-53: AC-3, IA-2 → 800-171: 3.1.1, 3.5.1
        # CMMC L1
        "nist_800_171": ["3.1.1", "3.5.1"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — unauthenticated ZK access
        "mitre_attack": ["T1078"],
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-UAP"],
    },

    "KF-ZK-002": {
        # ZooKeeper TLS
        # 800-53: SC-8 → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — ZK metadata in cleartext
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels
        "mitre_d3fend": ["D3-ET"],
    },

    "KF-ZK-003": {
        # ZooKeeper session timeout
        # 800-53: SC-5, CM-6 → 800-171: 3.4.2
        # CMMC L2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1499: Endpoint Denial of Service — session storm via timeout manipulation
        "mitre_attack": ["T1499"],
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ACH"],
    },

    # ------------------------------------------------------------------ #
    # Container Runtime (container.py)
    # ------------------------------------------------------------------ #

    "KF-CONT-001": {
        # Non-root user
        # 800-53: AC-6, CM-7 → 800-171: 3.1.5, 3.1.6, 3.4.6
        # CMMC L1
        "nist_800_171": ["3.1.5", "3.1.6", "3.4.6"],
        "cmmc_level": 1,
        # T1611: Escape to Host — root in container enables escape
        # T1068: Exploitation for Privilege Escalation
        "mitre_attack": ["T1611", "T1068"],
        # D3-CH: Container Hardening
        "mitre_d3fend": ["D3-CH", "D3-UAP"],
    },

    "KF-CONT-002": {
        # Not privileged
        # 800-53: CM-6 → 800-171: 3.4.2, 3.4.6
        # CMMC L2
        "nist_800_171": ["3.4.2", "3.4.6"],
        "cmmc_level": 2,
        # T1611: Escape to Host
        "mitre_attack": ["T1611"],
        # D3-CH: Container Hardening
        "mitre_d3fend": ["D3-CH"],
    },

    "KF-CONT-003": {
        # No dangerous capabilities
        # 800-53: CM-6, CM-7 → 800-171: 3.4.6, 3.4.7
        # CMMC L2
        "nist_800_171": ["3.4.6", "3.4.7"],
        "cmmc_level": 2,
        # T1611: Escape to Host
        "mitre_attack": ["T1611"],
        # D3-CH: Container Hardening
        # D3-PH: Platform Hardening
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "KF-CONT-004": {
        # Read-only root filesystem
        # 800-53: CM-6 → 800-171: 3.4.2
        # CMMC L2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1611: Escape to Host
        # T1014: Rootkit — writable FS enables persistence
        "mitre_attack": ["T1611", "T1014"],
        # D3-CH: Container Hardening
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "KF-CONT-005": {
        # Resource limits
        # 800-53: CM-6, SC-6 → 800-171: 3.4.2
        # CMMC L2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1499: Endpoint Denial of Service — unbounded resources
        "mitre_attack": ["T1499"],
        # D3-CH: Container Hardening
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "KF-CONT-006": {
        # No host namespace sharing
        # 800-53: SC-4, SC-7 → 800-171: 3.4.2, 3.1.3, 3.1.5
        # CMMC L2
        "nist_800_171": ["3.4.2", "3.1.3", "3.1.5"],
        "cmmc_level": 2,
        # T1611: Escape to Host — host namespace sharing
        # T1049: System Network Connections Discovery
        "mitre_attack": ["T1611", "T1049"],
        # D3-CH: Container Hardening
        # D3-NI: Network Isolation
        "mitre_d3fend": ["D3-CH", "D3-NI"],
    },
}


def enrich(result) -> None:
    """Enrich a CheckResult in-place with NIST 800-171, CMMC, and MITRE data."""
    data = FRAMEWORK_MAP.get(result.check_id)
    if not data:
        return
    if not result.nist_800_171:
        result.nist_800_171 = data.get("nist_800_171", [])
    if result.cmmc_level is None:
        result.cmmc_level = data.get("cmmc_level")
    if not result.mitre_attack:
        result.mitre_attack = data.get("mitre_attack", [])
    if not result.mitre_d3fend:
        result.mitre_d3fend = data.get("mitre_d3fend", [])


def enrich_all(results: list) -> list:
    """Enrich a list of CheckResult objects in-place; returns the same list."""
    for r in results:
        enrich(r)
    return results
