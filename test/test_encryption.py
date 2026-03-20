"""Tests for Kafka encryption checks."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.encryption import KafkaEncryptionChecker
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

    def container_inspect(self):
        return {}

    def pod_inspect(self):
        return {}

    def exec(self, cmd):
        import subprocess
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _run_enc_checks(props_str):
    runner = MockKafkaRunner(props_str)
    checker = KafkaEncryptionChecker(runner)
    results = checker.run()
    return {r.check_id: r for r in results}


class TestKafkaEncryptionChecks:
    def test_enc_001_pass_ssl_listener(self):
        props = "listeners=SASL_SSL://0.0.0.0:9093\nssl.keystore.location=/opt/kafka/ssl/kafka.keystore.jks\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-001"]
        assert r.status == Status.PASS

    def test_enc_001_fail_no_tls(self):
        props = "listeners=PLAINTEXT://0.0.0.0:9092\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-001"]
        assert r.status == Status.FAIL

    def test_enc_002_pass_sasl_ssl(self):
        props = "security.inter.broker.protocol=SASL_SSL\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-002"]
        assert r.status == Status.PASS

    def test_enc_002_fail_plaintext(self):
        props = "security.inter.broker.protocol=PLAINTEXT\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-002"]
        assert r.status == Status.FAIL

    def test_enc_003_pass_strong_ciphers(self):
        props = (
            "ssl.enabled.protocols=TLSv1.2,TLSv1.3\n"
            "ssl.cipher.suites=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
        )
        results = _run_enc_checks(props)
        r = results["KF-ENC-003"]
        assert r.status == Status.PASS

    def test_enc_003_fail_weak_cipher(self):
        props = "ssl.cipher.suites=NULL-MD5,TLS_RSA_WITH_DES_CBC_SHA\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-003"]
        assert r.status == Status.FAIL

    def test_enc_003_warn_no_config(self):
        props = ""
        results = _run_enc_checks(props)
        r = results["KF-ENC-003"]
        assert r.status == Status.WARN

    def test_enc_004_pass_client_auth_required(self):
        props = "ssl.client.auth=required\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-004"]
        assert r.status == Status.PASS

    def test_enc_004_warn_client_auth_none(self):
        props = "ssl.client.auth=none\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-004"]
        assert r.status == Status.WARN

    def test_enc_005_pass_zk_ssl(self):
        props = (
            "zookeeper.ssl.client.enable=true\n"
            "zookeeper.ssl.keystore.location=/opt/kafka/ssl/zk.keystore.jks\n"
            "zookeeper.ssl.truststore.location=/opt/kafka/ssl/zk.truststore.jks\n"
        )
        results = _run_enc_checks(props)
        r = results["KF-ENC-005"]
        assert r.status == Status.PASS

    def test_enc_005_fail_no_zk_ssl(self):
        props = "zookeeper.connect=zk:2181\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-005"]
        assert r.status == Status.FAIL

    def test_enc_005_skip_kraft_mode(self):
        props = "process.roles=broker,controller\n"
        results = _run_enc_checks(props)
        r = results["KF-ENC-005"]
        assert r.status == Status.SKIP

    def test_all_checks_returned(self):
        results = _run_enc_checks("")
        expected = {"KF-ENC-001", "KF-ENC-002", "KF-ENC-003", "KF-ENC-004", "KF-ENC-005"}
        assert expected == set(results.keys())
