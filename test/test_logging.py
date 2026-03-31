"""Tests for Kafka logging and monitoring checks."""
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.logging_checks import KafkaLoggingChecker
from checks.base import Status, Severity


class MockKafkaRunner:
    def __init__(self, props_content="", mode="docker", container="test",
                 log4j_content=""):
        self._props_content = props_content
        self.mode = mode
        self.container = container
        self.pod = "kafka-0"
        self.namespace = "default"
        self.command_log = []
        self.last_error = None
        self._log4j_content = log4j_content

    def read_server_properties(self):
        return self._props_content

    def parse_properties(self, content):
        props = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
        return props

    def acls_list(self):
        return subprocess.CompletedProcess([], 0, "", "")

    def container_inspect(self):
        return {}

    def pod_inspect(self):
        return {}

    def exec(self, cmd):
        # Simulate returning log4j content for the first candidate path
        if self._log4j_content and "cat" in cmd:
            return subprocess.CompletedProcess(cmd, 0, self._log4j_content, "")
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _run_logging_checks(props_str, mode="docker", log4j_content=""):
    runner = MockKafkaRunner(props_str, mode=mode, log4j_content=log4j_content)
    checker = KafkaLoggingChecker(runner)
    results = checker.run()
    return {r.check_id: r for r in results}


class TestKafkaLoggingChecks:
    # KF-LOG-001 — Log retention
    def test_log_001_pass_retention_hours_set(self):
        props = "log.retention.hours=720\n"
        results = _run_logging_checks(props)
        assert results["KF-LOG-001"].status == Status.PASS

    def test_log_001_pass_retention_ms_set(self):
        props = "log.retention.ms=2592000000\n"
        results = _run_logging_checks(props)
        assert results["KF-LOG-001"].status == Status.PASS

    def test_log_001_pass_extended_retention(self):
        props = "log.retention.hours=9000\n"
        results = _run_logging_checks(props)
        assert results["KF-LOG-001"].status == Status.PASS

    def test_log_001_warn_short_retention(self):
        props = "log.retention.hours=12\n"
        results = _run_logging_checks(props)
        assert results["KF-LOG-001"].status == Status.WARN

    def test_log_001_warn_not_configured(self):
        results = _run_logging_checks("")
        r = results["KF-LOG-001"]
        assert r.status == Status.WARN
        assert "168" in r.actual  # mentions Kafka default

    def test_log_001_severity_medium(self):
        results = _run_logging_checks("")
        assert results["KF-LOG-001"].severity == Severity.MEDIUM

    # KF-LOG-002 — Security event logging
    def test_log_002_skip_in_direct_mode(self):
        results = _run_logging_checks("", mode="direct")
        assert results["KF-LOG-002"].status == Status.SKIP

    def test_log_002_pass_auth_logger_present(self):
        log4j = (
            "log4j.rootLogger=INFO, stdout\n"
            "log4j.logger.kafka.authorizer.logger=INFO, authorizerAppender\n"
        )
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-002"].status == Status.PASS

    def test_log_002_pass_security_logger_present(self):
        log4j = (
            "log4j.rootLogger=INFO, stdout\n"
            "log4j.logger.kafka.security=INFO, stdout\n"
        )
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-002"].status == Status.PASS

    def test_log_002_warn_generic_logger_only(self):
        log4j = "log4j.logger.kafka=INFO, stdout\n"
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-002"].status == Status.WARN

    def test_log_002_fail_no_security_logger(self):
        log4j = "log4j.rootLogger=INFO, stdout\n"
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-002"].status == Status.FAIL

    def test_log_002_warn_log4j_not_found_docker(self):
        # Docker mode but exec returns not-found for all candidates
        results = _run_logging_checks("", mode="docker", log4j_content="")
        assert results["KF-LOG-002"].status == Status.WARN

    # KF-LOG-003 — Request logging
    def test_log_003_skip_in_direct_mode(self):
        results = _run_logging_checks("", mode="direct")
        assert results["KF-LOG-003"].status == Status.SKIP

    def test_log_003_pass_request_logger_present(self):
        log4j = (
            "log4j.rootLogger=INFO, stdout\n"
            "log4j.logger.kafka.request.logger=WARN, requestAppender\n"
        )
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-003"].status == Status.PASS

    def test_log_003_pass_request_appender_reference(self):
        log4j = "requestAppender.File=/var/log/kafka/requests.log\n"
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-003"].status == Status.PASS

    def test_log_003_warn_no_request_logger(self):
        log4j = "log4j.rootLogger=INFO, stdout\n"
        results = _run_logging_checks("", mode="docker", log4j_content=log4j)
        assert results["KF-LOG-003"].status == Status.WARN

    def test_log_003_warn_log4j_not_accessible_docker(self):
        results = _run_logging_checks("", mode="docker", log4j_content="")
        assert results["KF-LOG-003"].status == Status.WARN

    # Metadata checks
    def test_all_checks_returned(self):
        results = _run_logging_checks("")
        expected = {"KF-LOG-001", "KF-LOG-002", "KF-LOG-003"}
        assert expected.issubset(results.keys())

    def test_all_have_nist_controls(self):
        results = _run_logging_checks("log.retention.hours=720\n")
        for result in results.values():
            if result.status != Status.SKIP:
                assert result.nist_800_53_controls, (
                    f"{result.check_id} missing NIST 800-53 controls"
                )
