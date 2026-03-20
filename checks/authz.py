"""Authorization checks for Apache Kafka (KF-AUTHZ-001 through KF-AUTHZ-005).

Controls assessed:
  KF-AUTHZ-001  ACL authorizer enabled (authorizer.class.name)
  KF-AUTHZ-002  Super users restricted to minimum required
  KF-AUTHZ-003  allow.everyone.if.no.acl.found=false
  KF-AUTHZ-004  Topic-level ACLs configured
  KF-AUTHZ-005  Cluster-level ACLs restricted
"""

from .base import BaseChecker, CheckResult, Severity, Status


class KafkaAuthzChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        props_raw = self.runner.read_server_properties()
        props = self.runner.parse_properties(props_raw) if props_raw else {}

        acls_res = self.runner.acls_list()
        acls_output = acls_res.stdout if acls_res.returncode == 0 else ""

        results = []
        results.extend(self._check_authorizer_enabled(props))
        results.extend(self._check_super_users(props))
        results.extend(self._check_allow_everyone(props))
        results.extend(self._check_topic_acls(props, acls_output))
        results.extend(self._check_cluster_acls(acls_output))
        return results

    # ------------------------------------------------------------------

    def _check_authorizer_enabled(self, props: dict) -> list[CheckResult]:
        """KF-AUTHZ-001: ACL authorizer class configured."""
        authorizer = props.get("authorizer.class.name", "").strip()
        # KRaft mode uses a different class
        kraft_authorizer = props.get("authorizer.class.name", "")
        kraft_mode = "process.roles" in props

        if authorizer:
            # Both ZooKeeper (AclAuthorizer) and KRaft (StandardAuthorizer) are acceptable
            known_authorizers = (
                "kafka.security.authorizer.AclAuthorizer",
                "org.apache.kafka.metadata.authorizer.StandardAuthorizer",
            )
            if any(a in authorizer for a in known_authorizers):
                status = Status.PASS
            else:
                status = Status.WARN  # Custom authorizer — review required
            actual = f"authorizer.class.name={authorizer!r}"
        else:
            status = Status.FAIL
            actual = "authorizer.class.name not set — no ACL enforcement"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTHZ-001",
            title="ACL authorizer enabled (authorizer.class.name configured)",
            status=status,
            severity=Severity.CRITICAL,
            benchmark_control_id="4.1",
            cis_id="cis-kafka-1.0-4.1",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-6", "AC-17"],
            description=(
                "Kafka's authorization subsystem must be enabled via authorizer.class.name. "
                "Without an authorizer, any authenticated client has full access to all "
                "topics, consumer groups, and cluster operations."
            ),
            rationale=(
                "Authentication proves identity; authorization enforces what that identity "
                "is allowed to do. Without an authorizer, authentication alone does not "
                "prevent a compromised credential from reading all topics or deleting data."
            ),
            actual=actual,
            expected="authorizer.class.name=kafka.security.authorizer.AclAuthorizer (or StandardAuthorizer for KRaft)",
            remediation=(
                "Set authorizer.class.name=kafka.security.authorizer.AclAuthorizer in server.properties "
                "(ZooKeeper mode) or authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer "
                "(KRaft mode). Ensure super.users is restricted. Grant ACLs to each principal."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §4.1",
                "https://kafka.apache.org/documentation/#security_authz",
                "NIST SP 800-53 Rev 5 AC-3",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.authorizer", actual, cmd)],
        )]

    def _check_super_users(self, props: dict) -> list[CheckResult]:
        """KF-AUTHZ-002: Super users restricted to minimum required principals."""
        super_users = props.get("super.users", "").strip()

        if not super_users:
            status = Status.WARN
            actual = "super.users not configured (no explicit super users)"
            count = 0
        else:
            # super.users is semicolon-separated list of User:xxx;User:yyy
            user_list = [u.strip() for u in super_users.split(";") if u.strip()]
            count = len(user_list)
            actual = f"super.users={super_users!r} ({count} super user(s))"
            if count > 3:
                status = Status.WARN
            else:
                status = Status.PASS

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTHZ-002",
            title="Super users restricted to minimum required principals",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="4.2",
            cis_id="cis-kafka-1.0-4.2",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6", "AC-6(5)", "AC-2"],
            description=(
                "Kafka super users bypass all ACL checks and have unrestricted access to "
                "all topics, consumer groups, and cluster operations. Super user access "
                "must be limited to the minimum number of principals required for "
                "administrative operations."
            ),
            rationale=(
                "Super users are equivalent to database superusers — they bypass all "
                "authorization checks. Each additional super user expands the blast radius "
                "of a credential compromise. Production environments should have at most "
                "1-2 named super user principals for break-glass administrative access."
            ),
            actual=actual,
            expected="super.users contains ≤3 principals; each documented and business-justified",
            remediation=(
                "Review super.users and remove any service accounts or application principals. "
                "Super user access should be reserved for Kafka admin tooling and break-glass "
                "access only. Rotate credentials regularly for super user principals."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §4.2",
                "https://kafka.apache.org/documentation/#brokerconfigs_super.users",
                "NIST SP 800-53 Rev 5 AC-6(5)",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.super.users", actual, cmd)],
        )]

    def _check_allow_everyone(self, props: dict) -> list[CheckResult]:
        """KF-AUTHZ-003: allow.everyone.if.no.acl.found=false."""
        allow_everyone = props.get("allow.everyone.if.no.acl.found", "true").lower()

        if allow_everyone == "false":
            status = Status.PASS
            actual = "allow.everyone.if.no.acl.found=false (deny-by-default)"
        elif allow_everyone == "true":
            status = Status.FAIL
            actual = "allow.everyone.if.no.acl.found=true (allow-by-default — everyone can access resources without ACLs)"
        else:
            status = Status.WARN
            actual = f"allow.everyone.if.no.acl.found={allow_everyone} (review required)"

        cmd = "cat /etc/kafka/server.properties"
        return [CheckResult(
            check_id="KF-AUTHZ-003",
            title="Default deny policy enforced (allow.everyone.if.no.acl.found=false)",
            status=status,
            severity=Severity.CRITICAL,
            benchmark_control_id="4.3",
            cis_id="cis-kafka-1.0-4.3",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-6", "CM-6"],
            description=(
                "When allow.everyone.if.no.acl.found=true (the Kafka default), any topic or "
                "resource that lacks an explicit ACL is accessible by all authenticated users. "
                "This is equivalent to a default-allow firewall policy."
            ),
            rationale=(
                "The default-allow behavior means that operators must explicitly deny every "
                "resource, which is operationally infeasible. Setting deny-by-default ensures "
                "that newly created topics require explicit grants before clients can access them, "
                "enforcing least-privilege throughout the topic lifecycle."
            ),
            actual=actual,
            expected="allow.everyone.if.no.acl.found=false",
            remediation=(
                "Set allow.everyone.if.no.acl.found=false in server.properties. "
                "After enabling deny-by-default, audit all existing topic ACLs to ensure "
                "producer/consumer principals have explicit ALLOW grants. "
                "Use: kafka-acls --bootstrap-server ... --add --allow-principal User:app1 --operation Read --topic my-topic"
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §4.3",
                "https://kafka.apache.org/documentation/#brokerconfigs_allow.everyone.if.no.acl.found",
                "NIST SP 800-53 Rev 5 AC-6",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[self.evidence("server.properties.allow.everyone", actual, cmd)],
        )]

    def _check_topic_acls(self, props: dict, acls_output: str) -> list[CheckResult]:
        """KF-AUTHZ-004: Topic-level ACLs configured."""
        if not acls_output:
            status = Status.ERROR
            actual = "kafka-acls --list failed or returned no output"
        else:
            topic_acls = [line for line in acls_output.splitlines() if "topic" in line.lower()]
            if topic_acls:
                status = Status.PASS
                actual = f"Found topic ACL entries: {len(topic_acls)} line(s) referencing topic resources"
            else:
                authorizer = props.get("authorizer.class.name", "")
                if authorizer:
                    status = Status.WARN
                    actual = "Authorizer enabled but no topic ACLs found — all topic access may be denied"
                else:
                    status = Status.FAIL
                    actual = "No topic ACLs and no authorizer configured"

        cmd = "kafka-acls --bootstrap-server <host>:9092 --list"
        return [CheckResult(
            check_id="KF-AUTHZ-004",
            title="Topic-level ACLs configured for producer/consumer principals",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="4.4",
            cis_id="cis-kafka-1.0-4.4",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-6", "AC-2"],
            description=(
                "Each Kafka topic should have explicit ACLs granting only the required "
                "principals Read or Write access. Wildcard grants ('*') and overly broad "
                "principal grants must be avoided."
            ),
            rationale=(
                "Without topic-level ACLs, any authenticated client can produce to or consume "
                "from any topic (when allow.everyone.if.no.acl.found=true). Granular topic ACLs "
                "ensure that compromising one application's credentials does not expose all topics."
            ),
            actual=actual,
            expected="Each topic has explicit ALLOW ACLs for named principals; no wildcard grants",
            remediation=(
                "For each topic, run: kafka-acls --bootstrap-server ... --add "
                "--allow-principal User:<name> --operation Read|Write --topic <topic-name>. "
                "Audit for wildcard (*) principal grants using: kafka-acls --list --topic '*'. "
                "Remove any ACL with principal=User:* unless operationally required."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §4.4",
                "https://kafka.apache.org/documentation/#security_authz_primitives",
                "NIST SP 800-53 Rev 5 AC-3",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[self.evidence("kafka-acls.topic", actual, cmd)],
        )]

    def _check_cluster_acls(self, acls_output: str) -> list[CheckResult]:
        """KF-AUTHZ-005: Cluster-level ACLs restricted."""
        if not acls_output:
            status = Status.ERROR
            actual = "kafka-acls --list failed or returned no output"
        else:
            cluster_acl_lines = [line for line in acls_output.splitlines() if "cluster" in line.lower()]
            # Look for dangerous cluster-wide grants
            wildcard_cluster = any("User:*" in line for line in cluster_acl_lines)

            if wildcard_cluster:
                status = Status.FAIL
                actual = f"Wildcard cluster ACL found: {[l for l in cluster_acl_lines if 'User:*' in l]}"
            elif cluster_acl_lines:
                status = Status.PASS
                actual = f"Cluster ACLs present ({len(cluster_acl_lines)} entries); no wildcard principals detected"
            else:
                status = Status.WARN
                actual = "No cluster ACLs found — ClusterAction may be unrestricted"

        cmd = "kafka-acls --bootstrap-server <host>:9092 --list --cluster"
        return [CheckResult(
            check_id="KF-AUTHZ-005",
            title="Cluster-level ACLs restricted — no wildcard principal grants",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="4.5",
            cis_id="cis-kafka-1.0-4.5",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6", "AC-6(2)", "AC-3"],
            description=(
                "Kafka cluster ACLs control administrative operations such as "
                "CreateTopics, DeleteTopics, Describe, and ClusterAction (replication). "
                "Wildcard grants on the Cluster resource allow any authenticated user "
                "to perform administrative cluster operations."
            ),
            rationale=(
                "ClusterAction is required for inter-broker replication. Granting it to "
                "wildcard principals (User:*) allows any client to initiate replication "
                "connections or alter cluster metadata. Restrict ClusterAction to named "
                "broker principals only."
            ),
            actual=actual,
            expected="No User:* ACLs on Cluster resource; ClusterAction restricted to broker principals",
            remediation=(
                "Run: kafka-acls --list --cluster to identify all cluster ACLs. "
                "Remove wildcard cluster grants: kafka-acls --remove --allow-principal User:* "
                "--operation ClusterAction --cluster. "
                "Grant specific operations only to named admin principals."
            ),
            references=[
                "CIS Apache Kafka Container Benchmark v1.0 §4.5",
                "https://kafka.apache.org/documentation/#security_authz_primitives",
                "NIST SP 800-53 Rev 5 AC-6(2)",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[self.evidence("kafka-acls.cluster", actual, cmd)],
        )]
