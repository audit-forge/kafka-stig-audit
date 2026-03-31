"""Tests for Kafka authorization checks."""
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.authz import KafkaAuthzChecker
from checks.base import Status, Severity


class MockKafkaRunner:
    def __init__(self, props_content="", acls_stdout="", acls_returncode=0,
                 mode="docker", container="test"):
        self._props_content = props_content
        self._acls_stdout = acls_stdout
        self._acls_returncode = acls_returncode
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
        return subprocess.CompletedProcess(
            [], self._acls_returncode, self._acls_stdout, ""
        )

    def container_inspect(self):
        return {}

    def pod_inspect(self):
        return {}

    def exec(self, cmd):
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _run_authz_checks(props_str, acls_stdout="", acls_returncode=0):
    runner = MockKafkaRunner(props_str, acls_stdout=acls_stdout,
                             acls_returncode=acls_returncode)
    checker = KafkaAuthzChecker(runner)
    results = checker.run()
    return {r.check_id: r for r in results}


class TestKafkaAuthzChecks:
    # KF-AUTHZ-001 — ACL authorizer enabled
    def test_authz_001_pass_zk_authorizer(self):
        props = "authorizer.class.name=kafka.security.authorizer.AclAuthorizer\n"
        results = _run_authz_checks(props)
        r = results["KF-AUTHZ-001"]
        assert r.status == Status.PASS
        assert r.severity == Severity.CRITICAL

    def test_authz_001_pass_kraft_authorizer(self):
        props = (
            "authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer\n"
            "process.roles=broker,controller\n"
        )
        results = _run_authz_checks(props)
        assert results["KF-AUTHZ-001"].status == Status.PASS

    def test_authz_001_fail_no_authorizer(self):
        results = _run_authz_checks("")
        assert results["KF-AUTHZ-001"].status == Status.FAIL

    def test_authz_001_warn_custom_authorizer(self):
        props = "authorizer.class.name=com.example.CustomAuthorizer\n"
        results = _run_authz_checks(props)
        assert results["KF-AUTHZ-001"].status == Status.WARN

    # KF-AUTHZ-002 — Super users restricted
    def test_authz_002_pass_few_super_users(self):
        props = "super.users=User:admin;User:kafka\n"
        results = _run_authz_checks(props)
        assert results["KF-AUTHZ-002"].status == Status.PASS

    def test_authz_002_warn_many_super_users(self):
        props = "super.users=User:a;User:b;User:c;User:d\n"
        results = _run_authz_checks(props)
        assert results["KF-AUTHZ-002"].status == Status.WARN

    def test_authz_002_warn_no_super_users_configured(self):
        results = _run_authz_checks("")
        assert results["KF-AUTHZ-002"].status == Status.WARN

    # KF-AUTHZ-003 — Default deny policy
    def test_authz_003_pass_deny_by_default(self):
        props = "allow.everyone.if.no.acl.found=false\n"
        results = _run_authz_checks(props)
        assert results["KF-AUTHZ-003"].status == Status.PASS

    def test_authz_003_fail_allow_by_default(self):
        props = "allow.everyone.if.no.acl.found=true\n"
        results = _run_authz_checks(props)
        assert results["KF-AUTHZ-003"].status == Status.FAIL

    def test_authz_003_fail_default_value(self):
        # Default Kafka value is true — no config means allow-by-default
        results = _run_authz_checks("")
        assert results["KF-AUTHZ-003"].status == Status.FAIL

    # KF-AUTHZ-004 — Topic-level ACLs
    def test_authz_004_pass_topic_acls_present(self):
        acls = "Current ACLs for resource `Topic:LITERAL:my-topic`:\n  User:app1 has ALLOW permission\n"
        results = _run_authz_checks("", acls_stdout=acls, acls_returncode=0)
        assert results["KF-AUTHZ-004"].status == Status.PASS

    def test_authz_004_error_acls_failed(self):
        results = _run_authz_checks("", acls_stdout="", acls_returncode=1)
        assert results["KF-AUTHZ-004"].status == Status.ERROR

    def test_authz_004_warn_authorizer_but_no_acls(self):
        acls = "Current ACLs for resource `Cluster:LITERAL:kafka-cluster`:\n  User:broker has ALLOW ClusterAction\n"
        props = "authorizer.class.name=kafka.security.authorizer.AclAuthorizer\n"
        results = _run_authz_checks(props, acls_stdout=acls, acls_returncode=0)
        # No topic lines → warn since authorizer is set but no topic ACLs
        assert results["KF-AUTHZ-004"].status == Status.WARN

    # KF-AUTHZ-005 — Cluster-level ACLs
    def test_authz_005_pass_cluster_acls_no_wildcard(self):
        acls = "Current ACLs for resource `Cluster:LITERAL:kafka-cluster`:\n  User:broker has ALLOW ClusterAction\n"
        results = _run_authz_checks("", acls_stdout=acls, acls_returncode=0)
        assert results["KF-AUTHZ-005"].status == Status.PASS

    def test_authz_005_fail_wildcard_cluster_grant(self):
        acls = "Current ACLs for resource `Cluster:LITERAL:kafka-cluster`:\n  User:* has ALLOW ClusterAction\n"
        results = _run_authz_checks("", acls_stdout=acls, acls_returncode=0)
        assert results["KF-AUTHZ-005"].status == Status.FAIL

    def test_authz_005_warn_no_cluster_acls(self):
        acls = "Current ACLs for resource `Topic:LITERAL:test`:\n  User:app has ALLOW Read\n"
        results = _run_authz_checks("", acls_stdout=acls, acls_returncode=0)
        assert results["KF-AUTHZ-005"].status == Status.WARN

    def test_authz_005_error_acls_failed(self):
        results = _run_authz_checks("", acls_stdout="", acls_returncode=1)
        assert results["KF-AUTHZ-005"].status == Status.ERROR

    # Metadata checks
    def test_all_checks_returned(self):
        results = _run_authz_checks("")
        expected = {
            "KF-AUTHZ-001", "KF-AUTHZ-002", "KF-AUTHZ-003",
            "KF-AUTHZ-004", "KF-AUTHZ-005",
        }
        assert expected.issubset(results.keys())

    def test_all_have_nist_controls(self):
        results = _run_authz_checks("authorizer.class.name=kafka.security.authorizer.AclAuthorizer\n")
        for result in results.values():
            assert result.nist_800_53_controls, f"{result.check_id} has no NIST 800-53 controls"

    def test_all_have_remediation_on_fail(self):
        results = _run_authz_checks("")
        for result in results.values():
            if result.status == Status.FAIL:
                assert result.remediation, f"{result.check_id} FAIL missing remediation"
