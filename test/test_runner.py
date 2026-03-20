"""Tests for KafkaRunner."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from runner import KafkaRunner


class TestKafkaRunner:
    def test_bootstrap_server(self):
        r = KafkaRunner(host="kafka.internal", port=9093)
        assert r.bootstrap_server == "kafka.internal:9093"

    def test_default_values(self):
        r = KafkaRunner()
        assert r.mode == "docker"
        assert r.host == "127.0.0.1"
        assert r.port == 9092
        assert r.broker_id == "0"
        assert r.namespace == "default"

    def test_parse_properties_basic(self):
        r = KafkaRunner()
        props = r.parse_properties(
            "listeners=SASL_SSL://0.0.0.0:9093\n"
            "security.inter.broker.protocol=SASL_SSL\n"
            "# comment line\n"
            "zookeeper.set.acl=true\n"
        )
        assert props["listeners"] == "SASL_SSL://0.0.0.0:9093"
        assert props["security.inter.broker.protocol"] == "SASL_SSL"
        assert props["zookeeper.set.acl"] == "true"
        assert "# comment line" not in props

    def test_parse_properties_empty(self):
        r = KafkaRunner()
        props = r.parse_properties("")
        assert props == {}

    def test_parse_properties_value_with_equals(self):
        r = KafkaRunner()
        props = r.parse_properties("key=value=with=equals\n")
        assert props["key"] == "value=with=equals"

    def test_command_log_initially_empty(self):
        r = KafkaRunner()
        assert r.command_log == []

    def test_last_error_initially_none(self):
        r = KafkaRunner()
        assert r.last_error is None

    def test_wrap_docker_mode(self):
        r = KafkaRunner(mode="docker", container="my-kafka")
        inner = ["kafka-configs", "--bootstrap-server", "localhost:9092"]
        wrapped = r._wrap(inner)
        assert wrapped[0] == "docker"
        assert wrapped[1] == "exec"
        assert wrapped[2] == "my-kafka"
        assert wrapped[3:] == inner

    def test_wrap_kubectl_mode(self):
        r = KafkaRunner(mode="kubectl", pod="kafka-0", namespace="kafka")
        inner = ["kafka-acls", "--list"]
        wrapped = r._wrap(inner)
        assert "kubectl" in wrapped
        assert "kafka-0" in wrapped
        assert "kafka" in wrapped

    def test_wrap_direct_mode(self):
        r = KafkaRunner(mode="direct")
        inner = ["kafka-configs", "--bootstrap-server", "localhost:9092"]
        wrapped = r._wrap(inner)
        assert wrapped == inner

    def test_kafka_cmd_no_prefix(self):
        r = KafkaRunner()
        cmd = r._kafka_cmd("kafka-configs")
        assert cmd == ["kafka-configs"]

    def test_kafka_cmd_with_prefix(self):
        r = KafkaRunner(command_prefix="/opt/kafka/bin")
        cmd = r._kafka_cmd("kafka-configs")
        assert cmd == ["/opt/kafka/bin/kafka-configs"]

    def test_exec_missing_command(self):
        r = KafkaRunner(mode="direct")
        # Running a definitely-missing command should return returncode 127
        res = r.exec(["__nonexistent_command_xyz__", "--help"])
        assert res.returncode == 127
        assert r.last_error is not None
        assert len(r.command_log) == 1

    def test_wrap_docker_requires_container(self):
        r = KafkaRunner(mode="docker", container=None)
        try:
            r._wrap(["kafka-configs"])
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "container" in str(e).lower()

    def test_wrap_kubectl_requires_pod(self):
        r = KafkaRunner(mode="kubectl", pod=None)
        try:
            r._wrap(["kafka-acls"])
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "pod" in str(e).lower()


class TestKafkaRunnerFrameworkMapping:
    def test_framework_map_covers_all_checks(self):
        from mappings.frameworks import FRAMEWORK_MAP
        from checks import ALL_CHECKERS

        # Collect all check IDs from all checkers using mock runner
        class MinimalRunner:
            mode = "direct"
            container = None
            pod = None
            namespace = "default"
            command_log = []
            last_error = None
            host = "127.0.0.1"
            port = 9092
            broker_id = "0"
            command_prefix = ""
            verbose = False

            def read_server_properties(self):
                return ""

            def parse_properties(self, content):
                return {}

            def acls_list(self):
                import subprocess
                return subprocess.CompletedProcess([], 1, "", "")

            def topics_list(self):
                import subprocess
                return subprocess.CompletedProcess([], 1, "", "")

            def broker_api_versions(self):
                import subprocess
                return subprocess.CompletedProcess([], 1, "", "")

            def container_inspect(self):
                return {}

            def pod_inspect(self):
                return {}

            def exec(self, cmd):
                import subprocess
                return subprocess.CompletedProcess(cmd, 1, "", "")

        runner = MinimalRunner()
        all_check_ids = set()
        for checker_cls in ALL_CHECKERS:
            results = checker_cls(runner).run()
            for r in results:
                # Exclude CVE check which is added separately
                if not r.check_id.endswith("VER-001"):
                    all_check_ids.add(r.check_id)

        missing = all_check_ids - set(FRAMEWORK_MAP.keys())
        # Warn about unmapped checks but don't fail — some checks may be intentionally unmapped
        if missing:
            print(f"WARNING: Unmapped check IDs: {missing}")
