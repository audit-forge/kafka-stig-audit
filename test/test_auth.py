"""Tests for Kafka authentication checks."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.auth import KafkaAuthChecker
from checks.base import Status, Severity


class MockKafkaRunner:
    def __init__(self, props_content="", mode="docker", container="test"):
        self._props_content = props_content
        self.mode = mode
        self.container = container
        self.pod = None
        self.namespace = "default"
        self.command_log = []
        self.last_error = None

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
        import subprocess
        return subprocess.CompletedProcess([], 0, "", "")

    def container_inspect(self):
        return {}

    def pod_inspect(self):
        return {}

    def exec(self, cmd):
        import subprocess
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _run_auth_checks(props_str):
    runner = MockKafkaRunner(props_str)
    checker = KafkaAuthChecker(runner)
    results = checker.run()
    return {r.check_id: r for r in results}


class TestKafkaAuthChecks:
    def test_auth_001_pass_sasl_ssl_listener(self):
        props = "listeners=SASL_SSL://0.0.0.0:9093\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-001"]
        assert r.status == Status.PASS
        assert r.severity == Severity.CRITICAL

    def test_auth_001_fail_no_sasl(self):
        props = "listeners=PLAINTEXT://0.0.0.0:9092\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-001"]
        assert r.status == Status.FAIL

    def test_auth_002_pass_scram(self):
        props = "sasl.enabled.mechanisms=SCRAM-SHA-256\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-002"]
        assert r.status == Status.PASS

    def test_auth_002_fail_plain_only(self):
        props = "sasl.enabled.mechanisms=PLAIN\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-002"]
        assert r.status == Status.FAIL

    def test_auth_003_fail_plaintext(self):
        props = "listeners=PLAINTEXT://0.0.0.0:9092\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-003"]
        assert r.status == Status.FAIL

    def test_auth_003_pass_ssl_only(self):
        props = "listeners=SSL://0.0.0.0:9093\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-003"]
        assert r.status == Status.PASS

    def test_auth_004_pass_sasl_ssl(self):
        props = "security.inter.broker.protocol=SASL_SSL\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-004"]
        assert r.status == Status.PASS

    def test_auth_004_fail_plaintext(self):
        props = "security.inter.broker.protocol=PLAINTEXT\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-004"]
        assert r.status == Status.FAIL

    def test_auth_005_pass_zk_acl(self):
        props = "zookeeper.set.acl=true\nzookeeper.connect=zk:2181\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-005"]
        assert r.status == Status.PASS

    def test_auth_005_fail_no_acl(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.set.acl=false\n"
        results = _run_auth_checks(props)
        r = results["KF-AUTH-005"]
        assert r.status == Status.FAIL

    def test_all_checks_returned(self):
        results = _run_auth_checks("")
        expected = {"KF-AUTH-001", "KF-AUTH-002", "KF-AUTH-003", "KF-AUTH-004", "KF-AUTH-005"}
        assert expected.issubset(results.keys())

    def test_check_ids_correct(self):
        results = _run_auth_checks("listeners=SASL_SSL://0.0.0.0:9093\n")
        for check_id, result in results.items():
            assert result.check_id == check_id

    def test_all_have_nist_controls(self):
        results = _run_auth_checks("listeners=SASL_SSL://0.0.0.0:9093\n")
        for result in results.values():
            assert result.nist_800_53_controls, f"{result.check_id} has no NIST 800-53 controls"

    def test_all_have_remediation(self):
        results = _run_auth_checks("")
        for result in results.values():
            # PASS results may have empty remediation — FAILs must have it
            if result.status == Status.FAIL:
                assert result.remediation, f"{result.check_id} FAIL missing remediation"
