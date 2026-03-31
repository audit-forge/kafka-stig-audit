"""Tests for Kafka ZooKeeper security checks."""
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.zookeeper import KafkaZookeeperChecker
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
        return subprocess.CompletedProcess([], 0, "", "")

    def container_inspect(self):
        return {}

    def pod_inspect(self):
        return {}

    def exec(self, cmd):
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _run_zk_checks(props_str):
    runner = MockKafkaRunner(props_str)
    checker = KafkaZookeeperChecker(runner)
    results = checker.run()
    return {r.check_id: r for r in results}


class TestKafkaZookeeperChecks:
    # KF-ZK-001 — ZooKeeper SASL ACLs
    def test_zk_001_pass_acl_set(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.set.acl=true\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-001"].status == Status.PASS

    def test_zk_001_fail_acl_false(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.set.acl=false\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-001"].status == Status.FAIL

    def test_zk_001_warn_no_zk_connect(self):
        results = _run_zk_checks("")
        assert results["KF-ZK-001"].status == Status.WARN

    def test_zk_001_skip_kraft_mode(self):
        props = "process.roles=broker,controller\nnode.id=1\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-001"].status == Status.SKIP

    # KF-ZK-002 — ZooKeeper TLS
    def test_zk_002_pass_ssl_with_certs(self):
        props = (
            "zookeeper.connect=zk:2181\n"
            "zookeeper.ssl.client.enable=true\n"
            "zookeeper.ssl.keystore.location=/etc/kafka/zk.keystore.jks\n"
            "zookeeper.ssl.truststore.location=/etc/kafka/zk.truststore.jks\n"
        )
        results = _run_zk_checks(props)
        assert results["KF-ZK-002"].status == Status.PASS

    def test_zk_002_fail_ssl_disabled(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.ssl.client.enable=false\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-002"].status == Status.FAIL

    def test_zk_002_warn_ssl_but_no_keystore(self):
        props = (
            "zookeeper.connect=zk:2181\n"
            "zookeeper.ssl.client.enable=true\n"
        )
        results = _run_zk_checks(props)
        assert results["KF-ZK-002"].status == Status.WARN

    def test_zk_002_warn_no_zk_connect(self):
        results = _run_zk_checks("")
        assert results["KF-ZK-002"].status == Status.WARN

    def test_zk_002_skip_kraft_mode(self):
        props = "process.roles=broker,controller\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-002"].status == Status.SKIP

    # KF-ZK-003 — ZooKeeper session timeout
    def test_zk_003_pass_timeout_in_range(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.session.timeout.ms=18000\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-003"].status == Status.PASS

    def test_zk_003_warn_timeout_too_low(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.session.timeout.ms=2000\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-003"].status == Status.WARN

    def test_zk_003_warn_timeout_too_high(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.session.timeout.ms=120000\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-003"].status == Status.WARN

    def test_zk_003_warn_no_timeout_set(self):
        props = "zookeeper.connect=zk:2181\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-003"].status == Status.WARN

    def test_zk_003_warn_no_zk_connect(self):
        results = _run_zk_checks("")
        assert results["KF-ZK-003"].status == Status.WARN

    def test_zk_003_skip_kraft_mode(self):
        props = "process.roles=broker\n"
        results = _run_zk_checks(props)
        assert results["KF-ZK-003"].status == Status.SKIP

    # Metadata checks
    def test_all_checks_returned(self):
        results = _run_zk_checks("zookeeper.connect=zk:2181\n")
        expected = {"KF-ZK-001", "KF-ZK-002", "KF-ZK-003"}
        assert expected.issubset(results.keys())

    def test_kraft_all_skipped(self):
        props = "process.roles=broker,controller\n"
        results = _run_zk_checks(props)
        for check_id in ("KF-ZK-001", "KF-ZK-002", "KF-ZK-003"):
            assert results[check_id].status == Status.SKIP, (
                f"{check_id} should be SKIP in KRaft mode"
            )

    def test_all_have_nist_controls_when_not_skipped(self):
        props = "zookeeper.connect=zk:2181\nzookeeper.set.acl=true\n"
        results = _run_zk_checks(props)
        for result in results.values():
            if result.status != Status.SKIP:
                assert result.nist_800_53_controls, (
                    f"{result.check_id} missing NIST 800-53 controls"
                )
