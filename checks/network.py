"""Network security checks for Apache Kafka (KF-NET-001 through KF-NET-004).

Controls assessed:
  KF-NET-001  Listeners do not bind to 0.0.0.0 with PLAINTEXT
  KF-NET-002  advertised.listeners configured with restricted hostnames
  KF-NET-003  JMX port secured or disabled
  KF-NET-004  Auto topic creation disabled in production
"""

from .base import BaseChecker, CheckResult, Severity, Status


class KafkaNetworkChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        props_raw = self.runner.read_server_properties()
        props = self.runner.parse_properties(props_raw) if props_raw else {}

        return [
            self._check_listeners_binding(props),
            self._check_advertised_listeners(props),
            self._check_jmx_security(props),
            self._check_auto_topic_creation(props),
        ]

    # ------------------------------------------------------------------

    def _check_listeners_binding(self, props: dict) -> CheckResult:
        """KF-NET-001: Listeners do not bind PLAINTEXT to all interfaces."""
        listeners = props.get("listeners", "").strip()

        # Parse listener bindings: NAME://HOST:PORT
        issues = []
        ok_listeners = []
        for segment in listeners.split(","):
            segment = segment.strip()
            if not segment:
                continue
            # Extract protocol
            proto = ""
            if "://" in segment:
                proto_part = segment.split("://")[0].upper()
                host_port = segment.split("://")[1]
                proto = proto_part
            else:
                host_port = segment

            host = host_port.split(":")[0] if ":" in host_port else host_port

            # Flag: PLAINTEXT bound to 0.0.0.0 or empty host
            if proto in ("PLAINTEXT", "SASL_PLAINTEXT") and host in ("0.0.0.0", "", "localhost"):
                if host == "0.0.0.0":
                    issues.append(f"{proto}://0.0.0.0 (PLAINTEXT on all interfaces)")
            if proto in ("PLAINTEXT", "SASL_PLAINTEXT") and not issues:
                ok_listeners.append(segment)

        if not listeners:
            status = Status.WARN
            actual = "listeners not configured — Kafka defaults to PLAINTEXT://0.0.0.0:9092"
        elif issues:
            status = Status.FAIL
            actual = f"Insecure listener binding(s): {'; '.join(issues)}"
        else:
            status = Status.PASS
            actual = f"listeners={listeners!r}"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-NET-001",
            title="Listeners do not bind PLAINTEXT to all network interfaces",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="5.1",
            cis_id="cis-kafka-1.0-5.1",
            fedramp_control="SC-7",
            nist_800_53_controls=["SC-7", "SC-7(5)", "CM-7"],
            description=(
                "Kafka listener bindings determine which network interfaces and protocols "
                "accept connections. Binding PLAINTEXT to 0.0.0.0 exposes the broker to "
                "unauthenticated, unencrypted connections on all network interfaces, "
                "including those accessible from untrusted networks."
            ),
            rationale=(
                "A PLAINTEXT listener on 0.0.0.0 allows any host that can reach the port "
                "to produce/consume messages without authentication or encryption. "
                "Even internal networks should not be trusted with PLAINTEXT Kafka access "
                "due to lateral movement risks."
            ),
            actual=actual,
            expected="PLAINTEXT not bound to 0.0.0.0; use SSL or SASL_SSL listeners only",
            remediation=(
                "Replace PLAINTEXT://0.0.0.0:9092 with SASL_SSL://0.0.0.0:9093 "
                "in listeners. If a PLAINTEXT listener is needed for internal tooling, "
                "bind it to the loopback interface (127.0.0.1) and protect with host firewall rules."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §5.1",
                "https://kafka.apache.org/documentation/#brokerconfigs_listeners",
                "NIST SP 800-53 Rev 5 SC-7",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.listeners", actual, cmd)],
        )

    def _check_advertised_listeners(self, props: dict) -> CheckResult:
        """KF-NET-002: advertised.listeners configured with specific hostnames."""
        advertised = props.get("advertised.listeners", "").strip()

        if not advertised:
            status = Status.WARN
            actual = "advertised.listeners not set — clients use broker's listener address"
        else:
            # Check for 0.0.0.0 in advertised listeners (which would be wrong)
            if "0.0.0.0" in advertised:
                status = Status.FAIL
                actual = f"advertised.listeners={advertised!r} [0.0.0.0 is not a valid advertised address]"
            elif "PLAINTEXT://" in advertised.upper():
                status = Status.WARN
                actual = f"advertised.listeners={advertised!r} [PLAINTEXT protocol advertised to clients]"
            else:
                status = Status.PASS
                actual = f"advertised.listeners={advertised!r}"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-NET-002",
            title="advertised.listeners configured with specific hostnames (not 0.0.0.0)",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="5.2",
            cis_id="cis-kafka-1.0-5.2",
            fedramp_control="SC-7",
            nist_800_53_controls=["SC-7", "CM-6"],
            description=(
                "advertised.listeners tells Kafka clients which address to use to connect "
                "to the broker. Using 0.0.0.0 or an unresolvable hostname causes clients "
                "to connect to incorrect addresses or leak internal network topology."
            ),
            rationale=(
                "Correctly advertising hostnames ensures clients connect to the right "
                "broker interface (SSL port vs PLAINTEXT). Advertising PLAINTEXT hostnames "
                "encourages clients to use unencrypted connections even when SSL is available."
            ),
            actual=actual,
            expected="advertised.listeners configured with SASL_SSL:// using specific hostname or IP",
            remediation=(
                "Set advertised.listeners=SASL_SSL://<broker-hostname>:9093 in server.properties. "
                "Use the broker's fully-qualified hostname or load-balancer DNS name. "
                "Never use 0.0.0.0 as an advertised listener address."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §5.2",
                "https://kafka.apache.org/documentation/#brokerconfigs_advertised.listeners",
                "NIST SP 800-53 Rev 5 CM-6",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.advertised.listeners", actual, cmd)],
        )

    def _check_jmx_security(self, props: dict) -> CheckResult:
        """KF-NET-003: JMX port secured or disabled."""
        # JMX is configured via JVM flags, not server.properties
        # We check for environment variables or common JVM args in the container
        jmx_port = props.get("JMX_PORT", "") or props.get("jmx.port", "")

        # For docker/kubectl mode, check environment variables
        jmx_env_found = False
        jmx_auth_set = False

        if self.runner.mode in ("docker", "kubectl"):
            if self.runner.mode == "docker":
                inspect_data = self.runner.container_inspect()
                env_vars = inspect_data.get("Config", {}).get("Env", [])
            else:
                pod_data = self.runner.pod_inspect()
                spec = pod_data.get("spec", {})
                containers = spec.get("containers", [])
                kafka_ctr = next(
                    (c for c in containers if "kafka" in c.get("name", "").lower()),
                    containers[0] if containers else {},
                )
                env_vars_raw = kafka_ctr.get("env", [])
                env_vars = [f"{e.get('name', '')}={e.get('value', '')}" for e in env_vars_raw]

            for env in env_vars:
                if "JMX_PORT" in env.upper():
                    jmx_env_found = True
                if "com.sun.jmx.remote.security" in env or "jmxremote.authenticate" in env:
                    jmx_auth_set = True
        else:
            # Direct mode: can't inspect environment
            return CheckResult(
                check_id="KF-NET-003",
                title="JMX port secured or disabled",
                status=Status.SKIP,
                severity=Severity.MEDIUM,
                benchmark_control_id="5.3",
                cis_id="cis-kafka-1.0-5.3",
                fedramp_control="CM-7",
                nist_800_53_controls=["CM-7", "SC-7"],
                description="JMX security assessment requires docker or kubectl mode.",
                rationale="JMX configuration is in JVM environment variables; direct mode cannot inspect these.",
                actual="direct mode — JMX environment inspection not available",
                expected="run with --mode docker or --mode kubectl",
                remediation="Re-run with --mode docker or --mode kubectl to assess JMX security.",
                references=["CIS Apache Kafka Container Benchmark v1.0 §5.3"],
                category="Network",
                evidence_type="runtime-config",
                evidence=[],
            )

        if jmx_env_found and not jmx_auth_set:
            status = Status.FAIL
            actual = "JMX_PORT set in environment but JMX authentication not configured"
        elif jmx_env_found and jmx_auth_set:
            status = Status.PASS
            actual = "JMX_PORT configured with authentication settings"
        elif not jmx_env_found:
            status = Status.WARN
            actual = "JMX_PORT not found in environment — verify JVM launch args for -Dcom.sun.management.jmxremote"
        else:
            status = Status.WARN
            actual = "JMX configuration state unclear — manual review required"

        return CheckResult(
            check_id="KF-NET-003",
            title="JMX port secured or disabled",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="5.3",
            cis_id="cis-kafka-1.0-5.3",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "SC-7", "AC-17"],
            description=(
                "Kafka JMX exposes broker metrics, configuration, and limited management "
                "operations. An unauthenticated JMX port allows any host that can reach "
                "the port to enumerate broker metrics, alter logging levels, or trigger "
                "GC via MBean operations."
            ),
            rationale=(
                "JMX over RMI without authentication is equivalent to an unauthenticated "
                "management API. Attackers can use JMX to modify Log4j configuration "
                "for log injection, dump heap data, or enumerate sensitive properties."
            ),
            actual=actual,
            expected="JMX disabled or configured with -Dcom.sun.management.jmxremote.authenticate=true and SSL",
            remediation=(
                "Either disable JMX (remove JMX_PORT env var) or secure it: "
                "set -Dcom.sun.management.jmxremote.authenticate=true, "
                "-Dcom.sun.management.jmxremote.ssl=true, "
                "-Dcom.sun.management.jmxremote.access.file=<path>. "
                "Restrict JMX port with host firewall rules to monitoring systems only."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §5.3",
                "https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html",
                "NIST SP 800-53 Rev 5 CM-7",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[self.evidence("container.env.JMX", actual, "docker inspect / kubectl get pod")],
        )

    def _check_auto_topic_creation(self, props: dict) -> CheckResult:
        """KF-NET-004: Auto topic creation disabled in production."""
        auto_create = props.get("auto.create.topics.enable", "true").lower()

        if auto_create == "false":
            status = Status.PASS
            actual = "auto.create.topics.enable=false"
        elif auto_create == "true":
            status = Status.WARN
            actual = "auto.create.topics.enable=true (producer errors can create unintended topics)"
        else:
            status = Status.WARN
            actual = f"auto.create.topics.enable={auto_create} (review required)"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-NET-004",
            title="Auto topic creation disabled in production",
            status=status,
            severity=Severity.LOW,
            benchmark_control_id="5.4",
            cis_id="cis-kafka-1.0-5.4",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "CM-6", "AC-6"],
            description=(
                "When auto.create.topics.enable=true, any producer or consumer that "
                "references a non-existent topic will cause Kafka to create it automatically "
                "with default settings. This can bypass security controls on topic creation "
                "and lead to unintended topic proliferation."
            ),
            rationale=(
                "Automatically created topics may not inherit the intended retention policy, "
                "replication factor, or ACLs. A misconfigured client referencing a wrong "
                "topic name could silently create a new topic with no ACL enforcement, "
                "allowing all users to read or write it."
            ),
            actual=actual,
            expected="auto.create.topics.enable=false",
            remediation=(
                "Set auto.create.topics.enable=false in server.properties. "
                "Use kafka-topics --create with explicit configurations for each topic. "
                "Grant CreateTopics ACL only to authorized admin principals."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §5.4",
                "https://kafka.apache.org/documentation/#brokerconfigs_auto.create.topics.enable",
                "NIST SP 800-53 Rev 5 CM-7",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.auto.create.topics.enable", actual, cmd)],
        )
