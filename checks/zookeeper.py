"""ZooKeeper security checks for Apache Kafka (KF-ZK-001 through KF-ZK-003).

Controls assessed:
  KF-ZK-001  ZooKeeper authentication via SASL (zookeeper.set.acl)
  KF-ZK-002  ZooKeeper connection encrypted (zookeeper.ssl.client.enable)
  KF-ZK-003  ZooKeeper session timeout configured appropriately
"""

from .base import BaseChecker, CheckResult, Severity, Status


class KafkaZookeeperChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        props_raw = self.runner.read_server_properties()
        props = self.runner.parse_properties(props_raw) if props_raw else {}

        # Check if KRaft mode — skip ZooKeeper checks
        kraft_mode = "process.roles" in props

        results = []
        results.extend(self._check_zk_sasl_acl(props, kraft_mode))
        results.extend(self._check_zk_tls(props, kraft_mode))
        results.extend(self._check_zk_session_timeout(props, kraft_mode))
        return results

    # ------------------------------------------------------------------

    def _check_zk_sasl_acl(self, props: dict, kraft_mode: bool) -> list[CheckResult]:
        """KF-ZK-001: ZooKeeper SASL ACLs enforced."""
        if kraft_mode:
            return [CheckResult(
                check_id="KF-ZK-001",
                title="ZooKeeper SASL ACLs enforced",
                status=Status.SKIP,
                severity=Severity.INFO,
                benchmark_control_id="7.1",
                cis_id="cis-kafka-1.0-7.1",
                description="KRaft mode detected — ZooKeeper not used; control not applicable.",
                rationale="KRaft mode eliminates the ZooKeeper dependency.",
                actual="KRaft mode (process.roles configured)",
                expected="N/A — KRaft mode",
                remediation="No action required — KRaft mode eliminates ZooKeeper.",
                references=["CIS Apache Kafka Container Benchmark v1.0 §7.1"],
                category="ZooKeeper",
                evidence_type="runtime-config",
                evidence=[],
            )]

        zk_set_acl = props.get("zookeeper.set.acl", "false").lower()
        zk_sasl = props.get("zookeeper.sasl.client", "true").lower()
        zk_connect = props.get("zookeeper.connect", "")

        if not zk_connect:
            # ZooKeeper not configured — possibly KRaft-like or standalone
            status = Status.WARN
            actual = "zookeeper.connect not configured"
        elif zk_set_acl == "true" and zk_sasl != "false":
            status = Status.PASS
            actual = f"zookeeper.set.acl=true, zookeeper.sasl.client={zk_sasl}"
        elif zk_set_acl == "false":
            status = Status.FAIL
            actual = f"zookeeper.set.acl=false (ZooKeeper znodes not ACL-protected)"
        else:
            status = Status.WARN
            actual = f"zookeeper.set.acl={zk_set_acl}, zookeeper.sasl.client={zk_sasl}"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-ZK-001",
            title="ZooKeeper SASL authentication and ACLs enforced",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="7.1",
            cis_id="cis-kafka-1.0-7.1",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-6", "IA-2"],
            description=(
                "When zookeeper.set.acl=true, Kafka sets ZooKeeper ACLs on all znodes it "
                "creates to restrict access to authenticated Kafka processes only. "
                "Without this, any ZooKeeper client can read or modify Kafka cluster state."
            ),
            rationale=(
                "ZooKeeper stores broker configuration, partition leadership, topic configs, "
                "and consumer group offsets. Unprotected ZooKeeper allows an attacker to "
                "modify partition assignments, delete consumer groups, or alter topic configs "
                "without touching the Kafka broker at all."
            ),
            actual=actual,
            expected="zookeeper.set.acl=true with SASL authentication configured",
            remediation=(
                "Set zookeeper.set.acl=true in server.properties. "
                "Configure ZooKeeper SASL via /etc/kafka/kafka_server_jaas.conf with "
                "ZooKeeperClient credentials. Set the KAFKA_OPTS JVM arg: "
                "-Djava.security.auth.login.config=/etc/kafka/kafka_server_jaas.conf"
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §7.1",
                "https://kafka.apache.org/documentation/#zk_sasl_authz",
                "NIST SP 800-53 Rev 5 AC-3",
            ],
            category="ZooKeeper",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.zookeeper.set.acl", actual, cmd)],
        )]

    def _check_zk_tls(self, props: dict, kraft_mode: bool) -> list[CheckResult]:
        """KF-ZK-002: ZooKeeper connection encrypted with TLS."""
        if kraft_mode:
            return [CheckResult(
                check_id="KF-ZK-002",
                title="ZooKeeper connection encrypted with TLS",
                status=Status.SKIP,
                severity=Severity.INFO,
                benchmark_control_id="7.2",
                cis_id="cis-kafka-1.0-7.2",
                description="KRaft mode detected — ZooKeeper not used; control not applicable.",
                rationale="KRaft mode eliminates the ZooKeeper dependency.",
                actual="KRaft mode (process.roles configured)",
                expected="N/A — KRaft mode",
                remediation="No action required.",
                references=["CIS Apache Kafka Container Benchmark v1.0 §7.2"],
                category="ZooKeeper",
                evidence_type="runtime-config",
                evidence=[],
            )]

        zk_ssl = props.get("zookeeper.ssl.client.enable", "false").lower()
        zk_keystore = props.get("zookeeper.ssl.keystore.location", "")
        zk_truststore = props.get("zookeeper.ssl.truststore.location", "")
        zk_cnxn_socket = props.get("zookeeper.clientCnxnSocket", "")
        zk_connect = props.get("zookeeper.connect", "")

        if not zk_connect:
            status = Status.WARN
            actual = "zookeeper.connect not configured — ZooKeeper usage unclear"
        elif zk_ssl == "true" and zk_keystore and zk_truststore:
            status = Status.PASS
            actual = (
                f"zookeeper.ssl.client.enable=true, "
                f"keystore={zk_keystore!r}, truststore={zk_truststore!r}"
            )
        elif zk_ssl == "true" and (not zk_keystore or not zk_truststore):
            status = Status.WARN
            actual = f"zookeeper.ssl.client.enable=true but keystore or truststore not configured"
        else:
            status = Status.FAIL
            actual = f"zookeeper.ssl.client.enable={zk_ssl} (ZooKeeper connection unencrypted)"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-ZK-002",
            title="ZooKeeper connection encrypted with TLS",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="7.2",
            cis_id="cis-kafka-1.0-7.2",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-8(1)"],
            description=(
                "The connection between Kafka brokers and ZooKeeper must be protected "
                "by TLS to prevent interception of cluster metadata in transit. "
                "ZooKeeper TLS is independent from Kafka client-facing TLS."
            ),
            rationale=(
                "Without ZooKeeper TLS, the ZooKeeper protocol (which carries partition "
                "leader election data, topic configs, and SASL credentials stored as znodes) "
                "is exposed in plaintext on the broker network. This is a separate and often "
                "overlooked attack surface from the Kafka broker listeners."
            ),
            actual=actual,
            expected=(
                "zookeeper.ssl.client.enable=true with keystore and truststore configured; "
                "zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty"
            ),
            remediation=(
                "Set in server.properties:\n"
                "  zookeeper.ssl.client.enable=true\n"
                "  zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty\n"
                "  zookeeper.ssl.keystore.location=/path/to/kafka.keystore.jks\n"
                "  zookeeper.ssl.keystore.password=<password>\n"
                "  zookeeper.ssl.truststore.location=/path/to/kafka.truststore.jks\n"
                "  zookeeper.ssl.truststore.password=<password>"
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §7.2",
                "https://kafka.apache.org/documentation/#zk_tls_client_side_config",
                "NIST SP 800-53 Rev 5 SC-8(1)",
            ],
            category="ZooKeeper",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.zookeeper.ssl", actual, cmd)],
        )]

    def _check_zk_session_timeout(self, props: dict, kraft_mode: bool) -> list[CheckResult]:
        """KF-ZK-003: ZooKeeper session timeout configured appropriately."""
        if kraft_mode:
            return [CheckResult(
                check_id="KF-ZK-003",
                title="ZooKeeper session timeout configured",
                status=Status.SKIP,
                severity=Severity.INFO,
                benchmark_control_id="7.3",
                cis_id="cis-kafka-1.0-7.3",
                description="KRaft mode detected — ZooKeeper not used; control not applicable.",
                rationale="KRaft mode eliminates the ZooKeeper dependency.",
                actual="KRaft mode (process.roles configured)",
                expected="N/A — KRaft mode",
                remediation="No action required.",
                references=["CIS Apache Kafka Container Benchmark v1.0 §7.3"],
                category="ZooKeeper",
                evidence_type="runtime-config",
                evidence=[],
            )]

        zk_session_timeout = props.get("zookeeper.session.timeout.ms", "")
        zk_connect = props.get("zookeeper.connect", "")

        if not zk_connect:
            status = Status.WARN
            actual = "zookeeper.connect not configured"
        elif not zk_session_timeout:
            # Kafka default is 18000ms (18 seconds)
            status = Status.WARN
            actual = "zookeeper.session.timeout.ms not set — defaults to 18000ms (18s)"
        else:
            try:
                timeout_ms = int(zk_session_timeout)
                if timeout_ms < 6000:
                    status = Status.WARN
                    actual = f"zookeeper.session.timeout.ms={timeout_ms} (very low — may cause instability)"
                elif timeout_ms > 60000:
                    status = Status.WARN
                    actual = f"zookeeper.session.timeout.ms={timeout_ms} (high — extends broker unavailability detection)"
                else:
                    status = Status.PASS
                    actual = f"zookeeper.session.timeout.ms={timeout_ms} (within recommended range)"
            except ValueError:
                status = Status.WARN
                actual = f"zookeeper.session.timeout.ms={zk_session_timeout!r} (non-numeric — review)"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-ZK-003",
            title="ZooKeeper session timeout configured appropriately",
            status=status,
            severity=Severity.LOW,
            benchmark_control_id="7.3",
            cis_id="cis-kafka-1.0-7.3",
            fedramp_control="SC-5",
            nist_800_53_controls=["SC-5", "CM-6"],
            description=(
                "ZooKeeper session timeout controls how long ZooKeeper waits before "
                "declaring a Kafka broker session dead. Very short timeouts cause "
                "unnecessary leader elections; very long timeouts delay detection of "
                "broker failures and can mask security-relevant broker disconnections."
            ),
            rationale=(
                "An attacker who can disrupt ZooKeeper connectivity may trigger leader "
                "election chaos with a too-short timeout, or hide their activity behind "
                "a too-long timeout that delays detection of abnormal broker disconnections. "
                "A balanced timeout (6-30 seconds) is appropriate for most deployments."
            ),
            actual=actual,
            expected="zookeeper.session.timeout.ms between 6000 and 30000 (6–30 seconds)",
            remediation=(
                "Set zookeeper.session.timeout.ms=18000 (18 seconds — Kafka default) "
                "in server.properties. Adjust based on network latency to ZooKeeper. "
                "Monitor broker-ZooKeeper disconnect events in Kafka logs."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §7.3",
                "https://kafka.apache.org/documentation/#brokerconfigs_zookeeper.session.timeout.ms",
                "NIST SP 800-53 Rev 5 SC-5",
            ],
            category="ZooKeeper",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.zookeeper.session.timeout", actual, cmd)],
        )]
