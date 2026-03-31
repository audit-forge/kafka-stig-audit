"""Tests for Kafka network security checks."""
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.network import KafkaNetworkChecker
from checks.base import Status, Severity


class MockKafkaRunner:
    def __init__(self, props_content="", mode="docker", container="test",
                 docker_env=None, pod_env=None):
        self._props_content = props_content
        self.mode = mode
        self.container = container
        self.pod = "kafka-0"
        self.namespace = "default"
        self.command_log = []
        self.last_error = None
        self._docker_env = docker_env or []
        self._pod_env = pod_env or []

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
        return {"Config": {"Env": self._docker_env}}

    def pod_inspect(self):
        env_list = [{"name": e.split("=", 1)[0], "value": e.split("=", 1)[1]}
                    for e in self._pod_env if "=" in e]
        return {"spec": {"containers": [{"name": "kafka", "env": env_list}]}}

    def exec(self, cmd):
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _run_network_checks(props_str, mode="docker", docker_env=None, pod_env=None):
    runner = MockKafkaRunner(props_str, mode=mode,
                             docker_env=docker_env, pod_env=pod_env)
    checker = KafkaNetworkChecker(runner)
    results = checker.run()
    return {r.check_id: r for r in results}


class TestKafkaNetworkChecks:
    # KF-NET-001 — Listener binding
    def test_net_001_pass_sasl_ssl_listener(self):
        props = "listeners=SASL_SSL://0.0.0.0:9093\n"
        results = _run_network_checks(props)
        assert results["KF-NET-001"].status == Status.PASS

    def test_net_001_pass_ssl_listener(self):
        props = "listeners=SSL://0.0.0.0:9093\n"
        results = _run_network_checks(props)
        assert results["KF-NET-001"].status == Status.PASS

    def test_net_001_fail_plaintext_all_interfaces(self):
        props = "listeners=PLAINTEXT://0.0.0.0:9092\n"
        results = _run_network_checks(props)
        assert results["KF-NET-001"].status == Status.FAIL

    def test_net_001_warn_no_listeners_configured(self):
        results = _run_network_checks("")
        r = results["KF-NET-001"]
        assert r.status == Status.WARN
        assert "defaults" in r.actual.lower()

    def test_net_001_severity_high(self):
        results = _run_network_checks("listeners=SASL_SSL://0.0.0.0:9093\n")
        assert results["KF-NET-001"].severity == Severity.HIGH

    # KF-NET-002 — advertised.listeners
    def test_net_002_pass_sasl_ssl_hostname(self):
        props = "advertised.listeners=SASL_SSL://broker1.example.com:9093\n"
        results = _run_network_checks(props)
        assert results["KF-NET-002"].status == Status.PASS

    def test_net_002_fail_advertised_zero_zero(self):
        props = "advertised.listeners=SASL_SSL://0.0.0.0:9093\n"
        results = _run_network_checks(props)
        assert results["KF-NET-002"].status == Status.FAIL

    def test_net_002_warn_plaintext_advertised(self):
        props = "advertised.listeners=PLAINTEXT://broker1.internal:9092\n"
        results = _run_network_checks(props)
        assert results["KF-NET-002"].status == Status.WARN

    def test_net_002_warn_not_configured(self):
        results = _run_network_checks("")
        assert results["KF-NET-002"].status == Status.WARN

    # KF-NET-003 — JMX security
    def test_net_003_skip_in_direct_mode(self):
        results = _run_network_checks("", mode="direct")
        r = results["KF-NET-003"]
        assert r.status == Status.SKIP

    def test_net_003_pass_jmx_with_auth(self):
        env = [
            "JMX_PORT=9999",
            "KAFKA_JMX_OPTS=-Dcom.sun.management.jmxremote.authenticate=true "
            "-Djmxremote.authenticate=true",
        ]
        results = _run_network_checks("", mode="docker", docker_env=env)
        assert results["KF-NET-003"].status == Status.PASS

    def test_net_003_fail_jmx_without_auth(self):
        env = ["JMX_PORT=9999"]
        results = _run_network_checks("", mode="docker", docker_env=env)
        assert results["KF-NET-003"].status == Status.FAIL

    def test_net_003_warn_no_jmx_env(self):
        results = _run_network_checks("", mode="docker", docker_env=[])
        assert results["KF-NET-003"].status == Status.WARN

    # KF-NET-004 — Auto topic creation
    def test_net_004_pass_auto_create_disabled(self):
        props = "auto.create.topics.enable=false\n"
        results = _run_network_checks(props)
        assert results["KF-NET-004"].status == Status.PASS

    def test_net_004_warn_auto_create_enabled(self):
        props = "auto.create.topics.enable=true\n"
        results = _run_network_checks(props)
        assert results["KF-NET-004"].status == Status.WARN

    def test_net_004_warn_default_value(self):
        # Default is true
        results = _run_network_checks("")
        assert results["KF-NET-004"].status == Status.WARN

    # Metadata checks
    def test_all_checks_returned(self):
        results = _run_network_checks("")
        expected = {"KF-NET-001", "KF-NET-002", "KF-NET-003", "KF-NET-004"}
        assert expected.issubset(results.keys())

    def test_all_have_nist_controls(self):
        results = _run_network_checks("listeners=SASL_SSL://0.0.0.0:9093\n")
        for result in results.values():
            if result.status != Status.SKIP:
                assert result.nist_800_53_controls, (
                    f"{result.check_id} has no NIST 800-53 controls"
                )

    def test_all_have_remediation_on_fail(self):
        props = "listeners=PLAINTEXT://0.0.0.0:9092\nauto.create.topics.enable=true\n"
        results = _run_network_checks(props)
        for result in results.values():
            if result.status == Status.FAIL:
                assert result.remediation, f"{result.check_id} FAIL missing remediation"
