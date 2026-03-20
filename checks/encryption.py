"""Encryption/TLS checks for Apache Kafka (KF-ENC-001 through KF-ENC-005).

Controls assessed:
  KF-ENC-001  TLS/SSL enabled for client connections
  KF-ENC-002  TLS/SSL enabled for inter-broker communication
  KF-ENC-003  Strong TLS cipher suites configured
  KF-ENC-004  TLS client certificate validation enforced
  KF-ENC-005  ZooKeeper TLS connection enabled
"""

from .base import BaseChecker, CheckResult, Severity, Status

# Weak cipher patterns (not exhaustive — flags obviously weak configs)
_WEAK_CIPHER_PATTERNS = frozenset({
    "NULL", "EXPORT", "DES", "3DES", "RC4", "RC2", "ANON", "aNULL",
    "MD5", "SSLv2", "SSLv3",
})

# ssl.client.auth values
_STRONG_CLIENT_AUTH = frozenset({"required", "requested"})


class KafkaEncryptionChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        props_raw = self.runner.read_server_properties()
        props = self.runner.parse_properties(props_raw) if props_raw else {}

        return [
            self._check_tls_client(props),
            self._check_tls_inter_broker(props),
            self._check_cipher_suites(props),
            self._check_client_cert_validation(props),
            self._check_zookeeper_tls(props),
        ]

    # ------------------------------------------------------------------

    def _check_tls_client(self, props: dict) -> CheckResult:
        """KF-ENC-001: TLS/SSL enabled for client connections."""
        listeners = props.get("listeners", "").upper()
        protocol_map = props.get("listener.security.protocol.map", "").upper()

        ssl_listener = "SSL://" in listeners or "SASL_SSL://" in listeners
        ssl_in_map = ":SSL" in protocol_map or "SASL_SSL" in protocol_map

        # Also check for ssl.keystore.location as a signal
        keystore = props.get("ssl.keystore.location", "")

        tls_configured = ssl_listener or ssl_in_map or bool(keystore)

        if tls_configured:
            status = Status.PASS
            actual = f"listeners={listeners!r}"
            if keystore:
                actual += f", ssl.keystore.location={keystore!r}"
        else:
            status = Status.FAIL
            actual = "No SSL/TLS listener or keystore configured"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-ENC-001",
            title="TLS/SSL enabled for Kafka client connections",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="3.1",
            cis_id="cis-kafka-1.0-3.1",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-8(1)", "SC-23"],
            description=(
                "All Kafka client connections must use TLS to protect data in transit "
                "and prevent credential interception. A listener with SSL:// or SASL_SSL:// "
                "protocol and a configured keystore is required."
            ),
            rationale=(
                "Without TLS, all messages, consumer group IDs, and SASL credentials "
                "are transmitted in cleartext. Network capture provides complete visibility "
                "into Kafka traffic without any decryption effort."
            ),
            actual=actual,
            expected="SSL:// or SASL_SSL:// listener with ssl.keystore.location configured",
            remediation=(
                "Configure listeners=SASL_SSL://0.0.0.0:9093 in server.properties. "
                "Set ssl.keystore.location, ssl.keystore.password, ssl.key.password, and "
                "ssl.truststore.location. Generate certificates signed by an internal CA."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §3.1",
                "https://kafka.apache.org/documentation/#security_ssl",
                "NIST SP 800-53 Rev 5 SC-8(1)",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.tls.client", actual, cmd)],
        )

    def _check_tls_inter_broker(self, props: dict) -> CheckResult:
        """KF-ENC-002: TLS/SSL enabled for inter-broker communication."""
        ibc = props.get("security.inter.broker.protocol", "").upper()
        ssl_configured = ibc in ("SSL", "SASL_SSL")

        if ssl_configured:
            status = Status.PASS
            actual = f"security.inter.broker.protocol={ibc}"
        elif ibc == "SASL_PLAINTEXT":
            status = Status.WARN
            actual = "security.inter.broker.protocol=SASL_PLAINTEXT (auth without encryption)"
        elif ibc == "PLAINTEXT":
            status = Status.FAIL
            actual = "security.inter.broker.protocol=PLAINTEXT (no auth, no encryption)"
        else:
            status = Status.WARN
            actual = "security.inter.broker.protocol not set (defaults to PLAINTEXT)"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-ENC-002",
            title="TLS/SSL enabled for inter-broker communication",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="3.2",
            cis_id="cis-kafka-1.0-3.2",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-8(1)"],
            description=(
                "All data replicated between Kafka brokers must be encrypted in transit. "
                "Inter-broker replication without TLS exposes topic data on internal networks."
            ),
            rationale=(
                "Inter-broker replication carries the full contents of every topic partition. "
                "Without TLS, any actor with access to broker-to-broker network paths can "
                "capture the complete dataset with a passive sniffer."
            ),
            actual=actual,
            expected="security.inter.broker.protocol=SASL_SSL or SSL",
            remediation=(
                "Set security.inter.broker.protocol=SASL_SSL in server.properties. "
                "Ensure the broker keystore/truststore is configured for mutual TLS. "
                "Restart all brokers in a rolling fashion to apply the change."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §3.2",
                "https://kafka.apache.org/documentation/#security_ssl",
                "NIST SP 800-53 Rev 5 SC-8",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.inter.broker.protocol", actual, cmd)],
        )

    def _check_cipher_suites(self, props: dict) -> CheckResult:
        """KF-ENC-003: Strong TLS cipher suites configured."""
        cipher_suites = props.get("ssl.cipher.suites", "").strip()
        enabled_protocols = props.get("ssl.enabled.protocols", "").strip()

        weak_ciphers = []
        if cipher_suites:
            for suite in cipher_suites.split(","):
                suite = suite.strip().upper()
                if any(w in suite for w in _WEAK_CIPHER_PATTERNS):
                    weak_ciphers.append(suite)

        weak_protocols = []
        for proto in enabled_protocols.split(","):
            proto = proto.strip()
            if proto.upper() in ("SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"):
                weak_protocols.append(proto)

        if weak_ciphers or weak_protocols:
            status = Status.FAIL
            actual = f"cipher_suites={cipher_suites!r}, enabled_protocols={enabled_protocols!r} [WEAK: ciphers={weak_ciphers}, protocols={weak_protocols}]"
        elif not cipher_suites and not enabled_protocols:
            status = Status.WARN
            actual = "ssl.cipher.suites and ssl.enabled.protocols not explicitly configured (JVM defaults apply)"
        else:
            status = Status.PASS
            actual = f"cipher_suites={cipher_suites!r}, enabled_protocols={enabled_protocols!r}"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-ENC-003",
            title="Strong TLS cipher suites configured",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="3.3",
            cis_id="cis-kafka-1.0-3.3",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-23", "CM-6"],
            description=(
                "Kafka TLS connections must use strong cipher suites and protocol versions. "
                "Weak ciphers (NULL, EXPORT, DES, RC4) or deprecated protocols "
                "(SSLv2, SSLv3, TLSv1.0, TLSv1.1) must be explicitly disabled."
            ),
            rationale=(
                "Weak cipher suites are vulnerable to known attacks (BEAST, POODLE, SWEET32). "
                "Java JVM defaults may include deprecated ciphers. Explicit configuration "
                "ensures only approved suites are negotiated."
            ),
            actual=actual,
            expected="ssl.cipher.suites contains only TLS 1.2/1.3 AEAD suites; ssl.enabled.protocols=TLSv1.2,TLSv1.3",
            remediation=(
                "Set ssl.enabled.protocols=TLSv1.2,TLSv1.3 in server.properties. "
                "Set ssl.cipher.suites to ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384 "
                "(or similar AEAD suites). Verify with: openssl s_client -connect <broker>:9093"
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §3.3",
                "https://kafka.apache.org/documentation/#brokerconfigs_ssl.cipher.suites",
                "NIST SP 800-52 Rev 2 (TLS Guidelines)",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.ssl.cipher.suites", actual, cmd)],
        )

    def _check_client_cert_validation(self, props: dict) -> CheckResult:
        """KF-ENC-004: TLS client certificate validation enforced."""
        ssl_client_auth = props.get("ssl.client.auth", "none").lower()

        if ssl_client_auth == "required":
            status = Status.PASS
            actual = f"ssl.client.auth={ssl_client_auth} (mutual TLS enforced)"
        elif ssl_client_auth == "requested":
            status = Status.WARN
            actual = f"ssl.client.auth={ssl_client_auth} (client cert optional — not enforced)"
        else:
            status = Status.WARN
            actual = f"ssl.client.auth={ssl_client_auth} (no client certificate verification)"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-ENC-004",
            title="TLS client certificate validation enforced (ssl.client.auth=required)",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="3.4",
            cis_id="cis-kafka-1.0-3.4",
            fedramp_control="SC-17",
            nist_800_53_controls=["SC-17", "IA-5", "SC-8"],
            description=(
                "Kafka can require clients to present a valid TLS certificate during the "
                "handshake. When ssl.client.auth=required, only clients with certificates "
                "signed by the broker's trusted CA can connect."
            ),
            rationale=(
                "Client certificate validation provides mutual authentication at the TLS "
                "layer, independent of SASL credentials. Even if SASL credentials are "
                "compromised, an attacker without the client certificate cannot connect."
            ),
            actual=actual,
            expected="ssl.client.auth=required",
            remediation=(
                "Set ssl.client.auth=required in server.properties. "
                "Issue TLS client certificates for each Kafka client and producer. "
                "Configure ssl.truststore.location to the CA that signs client certificates. "
                "If mutual TLS is not feasible, ensure SASL authentication provides equivalent assurance."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §3.4",
                "https://kafka.apache.org/documentation/#brokerconfigs_ssl.client.auth",
                "NIST SP 800-53 Rev 5 SC-17",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.ssl.client.auth", actual, cmd)],
        )

    def _check_zookeeper_tls(self, props: dict) -> CheckResult:
        """KF-ENC-005: ZooKeeper TLS connection enabled."""
        zk_ssl = props.get("zookeeper.ssl.client.enable", "false").lower()
        zk_tls_keystore = props.get("zookeeper.ssl.keystore.location", "")
        zk_client_cnxn = props.get("zookeeper.clientCnxnSocket", "")

        # KRaft mode: no ZooKeeper
        kraft_mode = "process.roles" in props

        if kraft_mode:
            status = Status.SKIP
            actual = "KRaft mode detected — ZooKeeper not used"
        elif zk_ssl == "true" and zk_tls_keystore:
            status = Status.PASS
            actual = f"zookeeper.ssl.client.enable=true, keystore={zk_tls_keystore!r}"
        elif zk_ssl == "true":
            status = Status.WARN
            actual = "zookeeper.ssl.client.enable=true but keystore not configured"
        else:
            status = Status.FAIL
            actual = f"zookeeper.ssl.client.enable={zk_ssl} (ZooKeeper connection unencrypted)"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-ENC-005",
            title="ZooKeeper connection encrypted with TLS",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="3.5",
            cis_id="cis-kafka-1.0-3.5",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-8(1)"],
            description=(
                "In ZooKeeper-based Kafka deployments, the connection between Kafka "
                "brokers and ZooKeeper carries sensitive cluster metadata. This connection "
                "must be encrypted with TLS to prevent metadata disclosure."
            ),
            rationale=(
                "ZooKeeper protocol without TLS exposes controller election data, "
                "topic partition assignments, and SASL credentials stored as ZooKeeper "
                "znodes. Encrypting this connection is a separate control from "
                "zookeeper.set.acl authentication."
            ),
            actual=actual,
            expected="zookeeper.ssl.client.enable=true with keystore configured (or KRaft mode)",
            remediation=(
                "Set zookeeper.ssl.client.enable=true in server.properties. "
                "Configure zookeeper.ssl.keystore.location and zookeeper.ssl.truststore.location. "
                "Set zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty. "
                "Alternatively, migrate to Apache Kafka KRaft mode to eliminate ZooKeeper."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §3.5",
                "https://kafka.apache.org/documentation/#zk_tls_client_side_config",
                "NIST SP 800-53 Rev 5 SC-8(1)",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.zookeeper.ssl", actual, cmd)],
        )
