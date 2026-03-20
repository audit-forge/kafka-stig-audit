"""Logging and monitoring checks for Apache Kafka (KF-LOG-001 through KF-LOG-003).

Controls assessed:
  KF-LOG-001  Log retention configured (retention period and size limits)
  KF-LOG-002  Security events logged (log4j security appender)
  KF-LOG-003  Request logging / audit trail enabled
"""

from .base import BaseChecker, CheckResult, Severity, Status


class KafkaLoggingChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        props_raw = self.runner.read_server_properties()
        props = self.runner.parse_properties(props_raw) if props_raw else {}

        return [
            self._check_log_retention(props),
            self._check_security_logging(props),
            self._check_request_logging(props),
        ]

    # ------------------------------------------------------------------

    def _check_log_retention(self, props: dict) -> CheckResult:
        """KF-LOG-001: Log retention configured."""
        retention_hours = props.get("log.retention.hours", "")
        retention_ms = props.get("log.retention.ms", "")
        retention_bytes = props.get("log.retention.bytes", "")

        # Kafka default retention is 168 hours (7 days)
        if retention_hours:
            try:
                hours = int(retention_hours)
                if hours < 24:
                    status = Status.WARN
                    actual = f"log.retention.hours={hours} (less than 24 hours — may miss incident response window)"
                elif hours > 8760:  # 1 year
                    status = Status.PASS
                    actual = f"log.retention.hours={hours} (extended retention configured)"
                else:
                    status = Status.PASS
                    actual = f"log.retention.hours={hours}"
            except ValueError:
                status = Status.WARN
                actual = f"log.retention.hours={retention_hours!r} (non-numeric — review)"
        elif retention_ms:
            status = Status.PASS
            actual = f"log.retention.ms={retention_ms}"
        else:
            status = Status.WARN
            actual = "log.retention.hours/ms not configured — Kafka defaults to 168 hours (7 days)"

        if retention_bytes:
            actual += f", log.retention.bytes={retention_bytes}"

        cmd = "cat /etc/kafka/server.properties"
        return CheckResult(
            check_id="KF-LOG-001",
            title="Log retention period and size limits configured",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.1",
            cis_id="cis-kafka-1.0-6.1",
            fedramp_control="AU-11",
            nist_800_53_controls=["AU-11", "AU-4", "SI-12"],
            description=(
                "Kafka log retention controls how long message data is preserved on brokers. "
                "Retention must be long enough to satisfy incident response and forensic "
                "investigation requirements, but bounded to prevent unbounded disk growth."
            ),
            rationale=(
                "Insufficient retention can eliminate evidence needed during incident response. "
                "NIST SP 800-92 recommends audit logs be retained for at least 90 days online "
                "and 1 year offline. Kafka message logs may serve as an audit trail in "
                "event-sourced architectures."
            ),
            actual=actual,
            expected="log.retention.hours >= 168 (7 days) for most workloads; adjust per data classification",
            remediation=(
                "Set log.retention.hours=720 (30 days) or longer for regulated workloads. "
                "Set log.retention.bytes=-1 (no size limit) unless disk constraints require it. "
                "For compliance, export topic data to a long-term store (S3, HDFS) before "
                "Kafka retention expires."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §6.1",
                "https://kafka.apache.org/documentation/#brokerconfigs_log.retention.hours",
                "NIST SP 800-53 Rev 5 AU-11",
                "NIST SP 800-92 (Log Management Guide)",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.log.retention", actual, cmd)],
        )

    def _check_security_logging(self, props: dict) -> CheckResult:
        """KF-LOG-002: Security events logged via Log4j security appender."""
        # Try to read log4j configuration
        log4j_raw = ""
        if self.runner.mode in ("docker", "kubectl"):
            candidates = [
                "/opt/kafka/config/log4j.properties",
                "/etc/kafka/log4j.properties",
                "/opt/bitnami/kafka/config/log4j.properties",
            ]
            for path in candidates:
                if self.runner.mode == "docker":
                    cmd_list = ["docker", "exec", self.runner.container or "", "cat", path]
                else:
                    cmd_list = ["kubectl", "exec", "-n", self.runner.namespace,
                                self.runner.pod or "", "--", "cat", path]
                res = self.runner.exec(cmd_list)
                if res.returncode == 0 and res.stdout.strip():
                    log4j_raw = res.stdout
                    break

        if not log4j_raw:
            if self.runner.mode == "direct":
                status = Status.SKIP
                actual = "direct mode — cannot read log4j.properties from broker"
            else:
                status = Status.WARN
                actual = "log4j.properties not found in standard locations — verify logging configuration manually"
        else:
            # Check for security-related loggers
            has_kafka_logger = "log4j.logger.kafka" in log4j_raw
            has_auth_logger = "kafka.authorizer" in log4j_raw or "kafka.security" in log4j_raw
            has_request_logger = "kafka.request.logger" in log4j_raw

            if has_auth_logger:
                status = Status.PASS
                actual = "kafka.authorizer or kafka.security logger configured in log4j.properties"
            elif has_kafka_logger:
                status = Status.WARN
                actual = "kafka logger found but no dedicated authorizer/security logger configured"
            else:
                status = Status.FAIL
                actual = "No security-relevant loggers found in log4j.properties"

        cmd = "cat /opt/kafka/config/log4j.properties (or equivalent)"
        return CheckResult(
            check_id="KF-LOG-002",
            title="Security events logged (authorizer and authentication events)",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.2",
            cis_id="cis-kafka-1.0-6.2",
            fedramp_control="AU-2",
            nist_800_53_controls=["AU-2", "AU-3", "AU-12"],
            description=(
                "Kafka logs authorization decisions and authentication events via Log4j. "
                "The kafka.authorizer.logger and kafka.security.logger must be configured "
                "at INFO or DEBUG level to capture ACL denials and authentication failures."
            ),
            rationale=(
                "Authorization failure events provide the primary signal for detecting "
                "unauthorized access attempts. Without logging ACL denials, an attacker "
                "testing access permissions leaves no trace. NIST requires audit records "
                "for successful and unsuccessful access attempts."
            ),
            actual=actual,
            expected="log4j.properties includes kafka.authorizer.logger=INFO or DEBUG",
            remediation=(
                "Add to log4j.properties:\n"
                "  log4j.logger.kafka.authorizer.logger=INFO, authorizerAppender\n"
                "  log4j.logger.kafka.security=INFO, authorizerAppender\n"
                "Ship logs to a SIEM or centralized logging system (ELK, Splunk). "
                "Retain security event logs for ≥90 days."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §6.2",
                "https://kafka.apache.org/documentation/#security_authz_logging",
                "NIST SP 800-53 Rev 5 AU-2",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[self.evidence("log4j.security.logger", actual, cmd)],
        )

    def _check_request_logging(self, props: dict) -> CheckResult:
        """KF-LOG-003: Request logging / audit trail enabled."""
        # Check server.properties for log4j reference
        log4j_config = props.get("log4j.configuration", props.get("log4j.rootLogger", ""))
        controlled_shutdown = props.get("controlled.shutdown.enable", "true").lower()

        # Try to detect request logger from log4j config file
        log4j_raw = ""
        if self.runner.mode in ("docker", "kubectl"):
            candidates = [
                "/opt/kafka/config/log4j.properties",
                "/etc/kafka/log4j.properties",
                "/opt/bitnami/kafka/config/log4j.properties",
            ]
            for path in candidates:
                if self.runner.mode == "docker":
                    cmd_list = ["docker", "exec", self.runner.container or "", "cat", path]
                else:
                    cmd_list = ["kubectl", "exec", "-n", self.runner.namespace,
                                self.runner.pod or "", "--", "cat", path]
                res = self.runner.exec(cmd_list)
                if res.returncode == 0 and res.stdout.strip():
                    log4j_raw = res.stdout
                    break

        if not log4j_raw:
            if self.runner.mode == "direct":
                status = Status.SKIP
                actual = "direct mode — cannot assess request logging configuration"
            else:
                status = Status.WARN
                actual = "log4j.properties not accessible — request logging state unknown"
        else:
            has_request_logger = (
                "kafka.request.logger" in log4j_raw
                or "requestAppender" in log4j_raw
                or "requestLogger" in log4j_raw
            )
            if has_request_logger:
                status = Status.PASS
                actual = "kafka.request.logger configured in log4j.properties"
            else:
                status = Status.WARN
                actual = "kafka.request.logger not found — produce/consume request audit trail not enabled"

        cmd = "cat /opt/kafka/config/log4j.properties"
        return CheckResult(
            check_id="KF-LOG-003",
            title="Request logging enabled for audit trail",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.3",
            cis_id="cis-kafka-1.0-6.3",
            fedramp_control="AU-3",
            nist_800_53_controls=["AU-3", "AU-12", "AU-14"],
            description=(
                "Kafka request logging records produce and consume requests at the broker. "
                "Enabling kafka.request.logger provides an audit trail of which principals "
                "produced to or consumed from which topics at what time."
            ),
            rationale=(
                "Without request logging, there is no broker-side record of which client "
                "produced a message or consumed a partition offset. This makes forensic "
                "investigation of data exfiltration or message injection difficult."
            ),
            actual=actual,
            expected="log4j.logger.kafka.request.logger=WARN or DEBUG (with shipper to SIEM)",
            remediation=(
                "Add to log4j.properties:\n"
                "  log4j.logger.kafka.request.logger=WARN, requestAppender\n"
                "Note: DEBUG-level request logging is verbose. Use WARN level to capture "
                "errors and unusual patterns. Ship to a SIEM for correlation."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §6.3",
                "https://kafka.apache.org/documentation/#logging",
                "NIST SP 800-53 Rev 5 AU-3",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[self.evidence("log4j.request.logger", actual, cmd)],
        )
