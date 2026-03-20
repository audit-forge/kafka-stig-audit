"""Authentication checks for Apache Kafka (KF-AUTH-001 through KF-AUTH-005).

Controls assessed:
  KF-AUTH-001  SASL authentication enabled on client-facing listeners
  KF-AUTH-002  SASL mechanism is SCRAM-SHA-256/512 or GSSAPI (not PLAIN)
  KF-AUTH-003  No PLAINTEXT protocol used for any listener
  KF-AUTH-004  Inter-broker authentication enabled
  KF-AUTH-005  ZooKeeper authentication enabled
"""

from .base import BaseChecker, CheckResult, Severity, Status

_SECURE_MECHANISMS = frozenset({"SCRAM-SHA-256", "SCRAM-SHA-512", "GSSAPI", "OAUTHBEARER"})
_PLAINTEXT_PROTOCOLS = frozenset({"PLAINTEXT", "SASL_PLAINTEXT"})
_SECURE_PROTOCOLS = frozenset({"SSL", "SASL_SSL"})


class KafkaAuthChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        props_raw = self.runner.read_server_properties()
        props = self.runner.parse_properties(props_raw) if props_raw else {}

        results = []
        results.extend(self._check_sasl_enabled(props))
        results.extend(self._check_sasl_mechanism(props))
        results.extend(self._check_no_plaintext_listeners(props))
        results.extend(self._check_inter_broker_auth(props))
        results.extend(self._check_zookeeper_auth(props))
        return results

    # ------------------------------------------------------------------

    def _check_sasl_enabled(self, props: dict) -> list[CheckResult]:
        """KF-AUTH-001: SASL authentication enabled on client-facing listeners."""
        listeners = props.get("listeners", "")
        security_protocol_map = props.get("listener.security.protocol.map", "")

        # Determine if any listener uses SASL_SSL or SASL_PLAINTEXT
        sasl_enabled = False
        if "SASL_SSL" in listeners or "SASL_PLAINTEXT" in listeners:
            sasl_enabled = True
        if "SASL_SSL" in security_protocol_map or "SASL_PLAINTEXT" in security_protocol_map:
            sasl_enabled = True

        actual = f"listeners={listeners!r}" if listeners else "listeners not configured (defaults)"
        if security_protocol_map:
            actual += f", listener.security.protocol.map={security_protocol_map!r}"

        cmd = "cat /etc/kafka/server.properties (or equivalent broker config)"
        return [CheckResult(
            check_id="KF-AUTH-001",
            title="SASL authentication enabled on client-facing listeners",
            status=Status.PASS if sasl_enabled else Status.FAIL,
            severity=Severity.CRITICAL,
            benchmark_control_id="2.1",
            cis_id="cis-kafka-1.0-2.1",
            fedramp_control="IA-2",
            nist_800_53_controls=["IA-2", "AC-3", "AC-17"],
            description=(
                "Apache Kafka client listeners must require SASL authentication. "
                "Unauthenticated access allows any network-reachable client to produce or "
                "consume messages without identity verification."
            ),
            rationale=(
                "Without authentication, any client that can reach the broker's listener port "
                "can read sensitive topics or inject malicious messages. SASL_SSL or SASL_PLAINTEXT "
                "(with TLS overlay) is required in regulated environments."
            ),
            actual=actual,
            expected="listeners includes SASL_SSL or SASL_PLAINTEXT; security.protocol.map configured",
            remediation=(
                "Set listeners=SASL_SSL://0.0.0.0:9093 (or SASL_PLAINTEXT with TLS) "
                "in server.properties. Configure listener.security.protocol.map to map "
                "each listener name to SASL_SSL or SASL_PLAINTEXT."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §2.1",
                "https://kafka.apache.org/documentation/#security_sasl",
                "NIST SP 800-53 Rev 5 IA-2",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.listeners", actual, cmd)],
        )]

    def _check_sasl_mechanism(self, props: dict) -> list[CheckResult]:
        """KF-AUTH-002: SASL mechanism is SCRAM-SHA-256/512 or GSSAPI, not PLAIN."""
        sasl_mechanism = props.get(
            "sasl.mechanism.inter.broker.protocol",
            props.get("sasl.enabled.mechanisms", "")
        ).upper().strip()

        mechanisms_raw = props.get("sasl.enabled.mechanisms", "").upper()
        mechanism_list = [m.strip() for m in mechanisms_raw.split(",") if m.strip()]

        # Check for weak PLAIN mechanism
        plain_in_use = "PLAIN" in mechanism_list and "SCRAM-SHA" not in mechanisms_raw
        # Fallback: no mechanism configured at all
        no_mechanism = not mechanisms_raw

        if no_mechanism:
            status = Status.WARN
            actual = "sasl.enabled.mechanisms not set — defaulting to GSSAPI (verify manually)"
        elif plain_in_use and not any(m in _SECURE_MECHANISMS for m in mechanism_list):
            status = Status.FAIL
            actual = f"sasl.enabled.mechanisms={mechanisms_raw} [PLAIN without stronger alternative]"
        elif any(m in _SECURE_MECHANISMS for m in mechanism_list):
            status = Status.PASS
            actual = f"sasl.enabled.mechanisms={mechanisms_raw}"
        else:
            status = Status.WARN
            actual = f"sasl.enabled.mechanisms={mechanisms_raw} [review required]"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTH-002",
            title="SASL mechanism is SCRAM-SHA-256/512 or GSSAPI (not PLAIN)",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.2",
            cis_id="cis-kafka-1.0-2.2",
            fedramp_control="IA-5",
            nist_800_53_controls=["IA-5", "SC-8", "AC-17"],
            description=(
                "SASL/PLAIN transmits credentials in base64-encoded form and provides no "
                "resistance to credential theft even over TLS. SCRAM-SHA-256/512 or Kerberos "
                "(GSSAPI) should be used to authenticate Kafka clients."
            ),
            rationale=(
                "SASL/PLAIN is equivalent to cleartext password authentication; the credential "
                "is trivially recoverable from a TLS session if the TLS key is compromised. "
                "SCRAM provides cryptographic proof-of-knowledge that does not expose the password."
            ),
            actual=actual,
            expected="sasl.enabled.mechanisms includes SCRAM-SHA-256, SCRAM-SHA-512, or GSSAPI",
            remediation=(
                "Set sasl.enabled.mechanisms=SCRAM-SHA-256 or SCRAM-SHA-512 in server.properties. "
                "For enterprise environments, prefer GSSAPI (Kerberos). "
                "Remove PLAIN from sasl.enabled.mechanisms unless it is the only mechanism "
                "and TLS is enforced end-to-end."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §2.2",
                "https://kafka.apache.org/documentation/#security_sasl_scram",
                "NIST SP 800-53 Rev 5 IA-5(1)",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.sasl.enabled.mechanisms", actual, cmd)],
        )]

    def _check_no_plaintext_listeners(self, props: dict) -> list[CheckResult]:
        """KF-AUTH-003: No PLAINTEXT protocol used for any listener."""
        listeners = props.get("listeners", "")
        protocol_map = props.get("listener.security.protocol.map", "")

        plaintext_found = False
        plaintext_items = []

        # Check listeners directly
        for segment in listeners.split(","):
            segment = segment.strip().upper()
            if segment.startswith("PLAINTEXT://") or ":PLAINTEXT" in segment:
                plaintext_found = True
                plaintext_items.append(segment)

        # Check protocol map
        for mapping in protocol_map.split(","):
            mapping = mapping.strip().upper()
            if mapping.endswith(":PLAINTEXT"):
                plaintext_found = True
                plaintext_items.append(mapping)

        if not listeners and not protocol_map:
            status = Status.WARN
            actual = "listeners/protocol map not in config — inspect JVM args or defaults"
        elif plaintext_found:
            status = Status.FAIL
            actual = f"PLAINTEXT listeners detected: {', '.join(plaintext_items)}"
        else:
            status = Status.PASS
            actual = f"No PLAINTEXT protocol found: listeners={listeners!r}"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTH-003",
            title="No PLAINTEXT protocol used for client-facing listeners",
            status=status,
            severity=Severity.CRITICAL,
            benchmark_control_id="2.3",
            cis_id="cis-kafka-1.0-2.3",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-8(1)", "IA-2"],
            description=(
                "Kafka PLAINTEXT listeners transmit all data, including credentials, "
                "in cleartext. Any listener accepting client connections must use SSL or "
                "SASL_SSL to protect data in transit and authenticate clients."
            ),
            rationale=(
                "PLAINTEXT protocol provides no encryption and no authentication. "
                "Any attacker with network access can intercept messages, inject data, "
                "or steal consumer group offsets. Regulated workloads must prohibit PLAINTEXT."
            ),
            actual=actual,
            expected="No PLAINTEXT or SASL_PLAINTEXT in listeners; all listeners use SSL or SASL_SSL",
            remediation=(
                "Replace PLAINTEXT:// listeners with SSL:// or SASL_SSL:// in server.properties. "
                "Update listener.security.protocol.map to remove PLAINTEXT mappings. "
                "Reconfigure all clients to connect via the secure listener."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §2.3",
                "https://kafka.apache.org/documentation/#security_ssl",
                "NIST SP 800-53 Rev 5 SC-8",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.listeners", actual, cmd)],
        )]

    def _check_inter_broker_auth(self, props: dict) -> list[CheckResult]:
        """KF-AUTH-004: Inter-broker authentication enabled."""
        inter_broker_protocol = props.get("security.inter.broker.protocol", "").upper()
        inter_broker_sasl = props.get("sasl.mechanism.inter.broker.protocol", "").upper()

        if inter_broker_protocol in ("SSL", "SASL_SSL"):
            status = Status.PASS
            actual = f"security.inter.broker.protocol={inter_broker_protocol}"
            if inter_broker_sasl:
                actual += f", sasl.mechanism.inter.broker.protocol={inter_broker_sasl}"
        elif inter_broker_protocol == "SASL_PLAINTEXT":
            status = Status.WARN
            actual = f"security.inter.broker.protocol=SASL_PLAINTEXT (SASL without TLS)"
        elif inter_broker_protocol == "PLAINTEXT":
            status = Status.FAIL
            actual = f"security.inter.broker.protocol=PLAINTEXT (unauthenticated inter-broker)"
        else:
            status = Status.WARN
            actual = "security.inter.broker.protocol not set — defaults to PLAINTEXT"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTH-004",
            title="Inter-broker authentication enabled with secure protocol",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.4",
            cis_id="cis-kafka-1.0-2.4",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-8(1)", "IA-3"],
            description=(
                "Kafka brokers authenticate to each other for replication and cluster "
                "coordination. Unauthenticated inter-broker communication allows a "
                "rogue broker to join the cluster and intercept or corrupt data."
            ),
            rationale=(
                "Inter-broker PLAINTEXT allows an attacker who compromises any broker "
                "network segment to inject a malicious broker without authentication. "
                "SASL_SSL requires certificate-based mutual TLS for broker-to-broker links."
            ),
            actual=actual,
            expected="security.inter.broker.protocol=SASL_SSL (or SSL with mutual TLS)",
            remediation=(
                "Set security.inter.broker.protocol=SASL_SSL in server.properties. "
                "Configure sasl.mechanism.inter.broker.protocol=SCRAM-SHA-256 or GSSAPI. "
                "Ensure all brokers trust the same CA certificate for mutual verification."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §2.4",
                "https://kafka.apache.org/documentation/#security_sasl_brokerconfig",
                "NIST SP 800-53 Rev 5 IA-3",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.inter.broker.protocol", actual, cmd)],
        )]

    def _check_zookeeper_auth(self, props: dict) -> list[CheckResult]:
        """KF-AUTH-005: ZooKeeper authentication enabled (zookeeper.set.acl)."""
        zk_set_acl = props.get("zookeeper.set.acl", "false").lower()
        zk_sasl_client = props.get("zookeeper.sasl.client", "true").lower()  # default true

        acl_enabled = zk_set_acl == "true"
        sasl_disabled = zk_sasl_client == "false"

        if acl_enabled and not sasl_disabled:
            status = Status.PASS
            actual = f"zookeeper.set.acl=true, zookeeper.sasl.client={zk_sasl_client}"
        elif not acl_enabled:
            status = Status.FAIL
            actual = f"zookeeper.set.acl={zk_set_acl} (ACLs not enforced)"
        else:
            status = Status.WARN
            actual = f"zookeeper.set.acl={zk_set_acl}, zookeeper.sasl.client={zk_sasl_client}"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTH-005",
            title="ZooKeeper authentication enabled (zookeeper.set.acl=true)",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.5",
            cis_id="cis-kafka-1.0-2.5",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-6", "IA-2"],
            description=(
                "Kafka uses ZooKeeper for cluster metadata and leader election "
                "(pre-KRaft deployments). Without ZooKeeper authentication, any "
                "process that reaches ZooKeeper can read or modify cluster state."
            ),
            rationale=(
                "ZooKeeper stores sensitive broker metadata, topic configurations, and "
                "consumer group offsets. Unauthenticated ZooKeeper access allows an attacker "
                "to alter partition assignments, delete topics, or manipulate consumer offsets "
                "without leaving Kafka broker-level audit trails."
            ),
            actual=actual,
            expected="zookeeper.set.acl=true and zookeeper.sasl.client=true",
            remediation=(
                "Set zookeeper.set.acl=true in server.properties. "
                "Configure JAAS with ZooKeeper SASL credentials (zookeeper.jaas.conf). "
                "Consider migrating to KRaft mode to eliminate the ZooKeeper dependency. "
                "Restrict ZooKeeper network access to Kafka brokers only."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §2.5",
                "https://kafka.apache.org/documentation/#zk_sasl_authz",
                "NIST SP 800-53 Rev 5 AC-3",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.zookeeper.set.acl", actual, cmd)],
        )]
