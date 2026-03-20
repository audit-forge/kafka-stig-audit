"""Container-level security checks for Kafka (docker/kubectl modes only).

These checks assess controls set *outside* Kafka — in the container runtime
or orchestrator — and are invisible to kafka-configs or server.properties.
All checks emit SKIP status when running in --mode direct.

Control references:
  CIS Docker Benchmark v1.6  (sections 4 and 5)
  CIS Kubernetes Benchmark v1.8  (section 5.2)
  NIST SP 800-190 (Application Container Security Guide)
"""

from .base import BaseChecker, CheckResult, Severity, Status

_DANGEROUS_CAPS = frozenset({
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "NET_RAW", "SYS_RAWIO", "MKNOD", "AUDIT_CONTROL", "SYS_BOOT",
    "MAC_ADMIN", "MAC_OVERRIDE",
})

_CONT_CHECKS = [
    ("KF-CONT-001", "Kafka container runs as a non-root user"),
    ("KF-CONT-002", "Kafka container does not run in privileged mode"),
    ("KF-CONT-003", "No dangerous Linux capabilities granted to Kafka container"),
    ("KF-CONT-004", "Kafka container root filesystem is read-only"),
    ("KF-CONT-005", "Kafka container has CPU and memory resource limits"),
    ("KF-CONT-006", "Kafka container does not share host network, PID, or IPC namespaces"),
]


class KafkaContainerChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        mode = getattr(self.runner, "mode", "direct")
        if mode == "direct":
            return self._all_skipped()
        if mode == "docker":
            ctx = self._normalize_docker()
        elif mode == "kubectl":
            ctx = self._normalize_kubectl()
        else:
            return self._all_skipped()

        if ctx is None:
            return self._all_error(mode)

        return [
            self._check_nonroot(ctx),
            self._check_privileged(ctx),
            self._check_caps(ctx),
            self._check_readonly_rootfs(ctx),
            self._check_resource_limits(ctx),
            self._check_host_namespaces(ctx),
        ]

    # ------------------------------------------------------------------
    # Normalizers
    # ------------------------------------------------------------------

    def _normalize_docker(self) -> dict | None:
        data = self.runner.container_inspect()
        if not data:
            return None
        hc = data.get("HostConfig", {})
        cfg = data.get("Config", {})
        return {
            "source": "docker",
            "inspect_cmd": f"docker inspect {self.runner.container or '<container>'}",
            "user": (cfg.get("User") or "").strip(),
            "run_as_non_root": None,
            "allow_privilege_escalation": None,
            "privileged": bool(hc.get("Privileged", False)),
            "cap_add": [c.upper() for c in (hc.get("CapAdd") or [])],
            "cap_drop": [c.upper() for c in (hc.get("CapDrop") or [])],
            "read_only_rootfs": bool(hc.get("ReadonlyRootfs", False)),
            "memory_limit_set": int(hc.get("Memory", 0)) > 0,
            "cpu_limit_set": int(hc.get("NanoCpus", 0)) > 0,
            "host_network": hc.get("NetworkMode", "") == "host",
            "host_pid": hc.get("PidMode", "") == "host",
            "host_ipc": hc.get("IpcMode", "private") == "host",
            "raw": data,
        }

    def _normalize_kubectl(self) -> dict | None:
        data = self.runner.pod_inspect()
        if not data:
            return None
        spec = data.get("spec", {})
        pod_sc = spec.get("securityContext", {})
        containers = spec.get("containers", [])
        ctr = next(
            (c for c in containers if "kafka" in c.get("name", "").lower()),
            containers[0] if containers else {},
        )
        sc = ctr.get("securityContext", {})
        caps = sc.get("capabilities", {})
        limits = ctr.get("resources", {}).get("limits", {})
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot", False))
        return {
            "source": "kubectl",
            "inspect_cmd": f"kubectl get pod -n {self.runner.namespace} {self.runner.pod or '<pod>'} -o json",
            "user": str(run_as_user) if run_as_user is not None else "",
            "run_as_non_root": run_as_non_root,
            "allow_privilege_escalation": sc.get("allowPrivilegeEscalation"),
            "privileged": bool(sc.get("privileged", False)),
            "cap_add": [c.upper() for c in (caps.get("add") or [])],
            "cap_drop": [c.upper() for c in (caps.get("drop") or [])],
            "read_only_rootfs": bool(sc.get("readOnlyRootFilesystem", False)),
            "memory_limit_set": bool(limits.get("memory")),
            "cpu_limit_set": bool(limits.get("cpu")),
            "host_network": bool(spec.get("hostNetwork", False)),
            "host_pid": bool(spec.get("hostPID", False)),
            "host_ipc": bool(spec.get("hostIPC", False)),
            "raw": data,
        }

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_nonroot(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        user = ctx.get("user", "")
        run_as_non_root = ctx.get("run_as_non_root")
        if src == "docker":
            is_nonroot = bool(user) and user not in ("0", "root")
            actual = f"User={user!r}" if user else "User not set (defaults to root)"
        else:
            run_as_user_int = int(user) if user.isdigit() else None
            is_nonroot = bool(run_as_non_root) or (run_as_user_int is not None and run_as_user_int > 0)
            parts = []
            if user:
                parts.append(f"runAsUser={user}")
            if run_as_non_root is not None:
                parts.append(f"runAsNonRoot={run_as_non_root}")
            actual = ", ".join(parts) if parts else "runAsUser/runAsNonRoot not set"
        return CheckResult(
            check_id="KF-CONT-001",
            title="Kafka container runs as a non-root user",
            status=Status.PASS if is_nonroot else Status.FAIL,
            severity=Severity.HIGH,
            benchmark_control_id="8.1",
            cis_id="cis-kafka-1.0-8.1",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6", "CM-7"],
            description="Kafka must run as a non-root user to limit container escape impact.",
            rationale=(
                "Running as UID 0 provides a direct privilege escalation path if container "
                "isolation is bypassed. Kafka does not require root access for normal operation."
            ),
            actual=actual,
            expected="non-zero, non-root UID (e.g. kafka user UID 1000 or similar)",
            remediation=(
                "Set USER kafka in the Dockerfile or configure runAsUser/runAsNonRoot "
                "in the pod/container securityContext. Use a dedicated kafka UID."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §4.1",
                "CIS Kubernetes Benchmark v1.8 §5.2.6",
                "NIST SP 800-190 §4.4.1",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[self.evidence(f"container.{src}.user", {"user": user, "run_as_non_root": run_as_non_root}, ctx["inspect_cmd"])],
        )

    def _check_privileged(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        privileged = ctx.get("privileged", False)
        ape = ctx.get("allow_privilege_escalation")
        if src == "kubectl":
            is_fail = privileged or (ape is True)
            actual_parts = [f"privileged={privileged}"]
            if ape is not None:
                actual_parts.append(f"allowPrivilegeEscalation={ape}")
            actual = ", ".join(actual_parts)
        else:
            is_fail = privileged
            actual = f"Privileged={privileged}"
        return CheckResult(
            check_id="KF-CONT-002",
            title="Kafka container does not run in privileged mode",
            status=Status.FAIL if is_fail else Status.PASS,
            severity=Severity.CRITICAL,
            benchmark_control_id="8.2",
            cis_id="cis-kafka-1.0-8.2",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "AC-6", "SC-4"],
            description="Privileged containers have near-unrestricted host access. Kafka never requires privileged mode.",
            rationale="Privileged mode disables seccomp, AppArmor, SELinux, and capability restrictions.",
            actual=actual,
            expected="privileged=False, allowPrivilegeEscalation=False",
            remediation=(
                "Remove privileged: true from the container spec. "
                "Set allowPrivilegeEscalation: false in the securityContext."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.4",
                "CIS Kubernetes Benchmark v1.8 §5.2.1",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[self.evidence(f"container.{src}.privileged", {"privileged": privileged, "allowPrivilegeEscalation": ape}, ctx["inspect_cmd"])],
        )

    def _check_caps(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        cap_add = ctx.get("cap_add", [])
        cap_drop = ctx.get("cap_drop", [])
        dangerous_added = sorted(_DANGEROUS_CAPS & set(cap_add))
        drops_all = "ALL" in cap_drop
        if dangerous_added:
            status = Status.FAIL
        elif not drops_all:
            status = Status.WARN
        else:
            status = Status.PASS
        actual = (
            f"cap_add={cap_add or '[]'}, cap_drop={cap_drop or '[]'}"
            + (f" [DANGEROUS: {dangerous_added}]" if dangerous_added else "")
        )
        return CheckResult(
            check_id="KF-CONT-003",
            title="No dangerous Linux capabilities granted to Kafka container",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="8.3",
            cis_id="cis-kafka-1.0-8.3",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "AC-6"],
            description="Kafka does not require elevated Linux capabilities. Drop ALL capabilities.",
            rationale="Capabilities such as SYS_ADMIN and NET_ADMIN significantly expand the attack surface.",
            actual=actual,
            expected="cap_drop=[ALL], cap_add=[] (or empty)",
            remediation="Add 'drop: [ALL]' to capabilities in the container securityContext (or --cap-drop ALL for docker run).",
            references=[
                "CIS Docker Benchmark v1.6 §5.3",
                "CIS Kubernetes Benchmark v1.8 §5.2.8",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[self.evidence(f"container.{src}.capabilities", {"cap_add": cap_add, "cap_drop": cap_drop}, ctx["inspect_cmd"])],
        )

    def _check_readonly_rootfs(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        read_only = ctx.get("read_only_rootfs", False)
        return CheckResult(
            check_id="KF-CONT-004",
            title="Kafka container root filesystem is read-only",
            status=Status.PASS if read_only else Status.WARN,
            severity=Severity.MEDIUM,
            benchmark_control_id="8.4",
            cis_id="cis-kafka-1.0-8.4",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "SC-28"],
            description="A read-only root filesystem prevents attackers from persisting changes to the container layer.",
            rationale="If an attacker achieves RCE inside the container, a writable root filesystem allows them to install backdoors.",
            actual=f"ReadonlyRootfs={read_only}",
            expected="ReadonlyRootfs=True",
            remediation=(
                "Set readOnlyRootFilesystem: true in the container securityContext. "
                "Mount /var/log, /tmp, and Kafka log directories as writable volumes."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.12",
                "CIS Kubernetes Benchmark v1.8 §5.2.4",
                "NIST SP 800-190 §4.4.3",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[self.evidence(f"container.{src}.read_only_rootfs", read_only, ctx["inspect_cmd"])],
        )

    def _check_resource_limits(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        mem_set = ctx.get("memory_limit_set", False)
        cpu_set = ctx.get("cpu_limit_set", False)
        if mem_set and cpu_set:
            status = Status.PASS
        elif mem_set or cpu_set:
            status = Status.WARN
        else:
            status = Status.FAIL
        actual = f"memory_limit={'set' if mem_set else 'unset'}, cpu_limit={'set' if cpu_set else 'unset'}"
        return CheckResult(
            check_id="KF-CONT-005",
            title="Kafka container has memory and CPU resource limits configured",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="8.5",
            cis_id="cis-kafka-1.0-8.5",
            fedramp_control="SC-6",
            nist_800_53_controls=["SC-6", "SI-17"],
            description="Resource limits prevent a Kafka container from consuming unbounded CPU or memory.",
            rationale="Kafka is a high-throughput system; without limits, it can exhaust host resources and cause denial-of-service.",
            actual=actual,
            expected="both memory and CPU limits set",
            remediation=(
                "Set resources.limits.memory and resources.limits.cpu in Kubernetes spec "
                "or --memory and --cpus for docker run. Size based on expected throughput."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.10",
                "CIS Kubernetes Benchmark v1.8 §5.2.3",
                "NIST SP 800-190 §4.5",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[self.evidence(f"container.{src}.resource_limits", {"memory_limit_set": mem_set, "cpu_limit_set": cpu_set}, ctx["inspect_cmd"])],
        )

    def _check_host_namespaces(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        host_network = ctx.get("host_network", False)
        host_pid = ctx.get("host_pid", False)
        host_ipc = ctx.get("host_ipc", False)
        violations = [x for x, v in [("hostNetwork", host_network), ("hostPID", host_pid), ("hostIPC", host_ipc)] if v]
        actual = (
            f"hostNetwork={host_network}, hostPID={host_pid}, hostIPC={host_ipc}"
            + (f" [VIOLATIONS: {violations}]" if violations else "")
        )
        return CheckResult(
            check_id="KF-CONT-006",
            title="Kafka container does not share host network, PID, or IPC namespaces",
            status=Status.FAIL if violations else Status.PASS,
            severity=Severity.HIGH,
            benchmark_control_id="8.6",
            cis_id="cis-kafka-1.0-8.6",
            fedramp_control="SC-4",
            nist_800_53_controls=["SC-4", "SC-7", "AC-6"],
            description="Sharing host namespaces collapses isolation boundaries between the Kafka container and the host.",
            rationale=(
                "hostNetwork exposes Kafka to all host interfaces. "
                "hostPID allows the container to inspect host processes. "
                "hostIPC allows shared memory access across containers."
            ),
            actual=actual,
            expected="hostNetwork=False, hostPID=False, hostIPC=False",
            remediation="Remove hostNetwork, hostPID, and hostIPC from the pod spec.",
            references=[
                "CIS Docker Benchmark v1.6 §5.14, §5.16, §5.17",
                "CIS Kubernetes Benchmark v1.8 §5.2.2, §5.2.3, §5.2.4",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[self.evidence(f"container.{src}.namespaces", {"hostNetwork": host_network, "hostPID": host_pid, "hostIPC": host_ipc}, ctx["inspect_cmd"])],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _all_skipped(self) -> list[CheckResult]:
        return [
            CheckResult(
                check_id=cid,
                title=title,
                status=Status.SKIP,
                severity=Severity.INFO,
                benchmark_control_id=f"8.{i + 1}",
                cis_id=f"cis-kafka-1.0-8.{i + 1}",
                fedramp_control=None,
                nist_800_53_controls=[],
                description="Container-level controls require docker or kubectl mode.",
                rationale="Container inspection is not available in direct/CLI mode.",
                actual="direct mode — container inspection not available",
                expected="run with --mode docker or --mode kubectl",
                remediation="Re-run with --mode docker --container <name> or --mode kubectl --pod <name>.",
                references=["CIS Docker Benchmark", "CIS Kubernetes Benchmark"],
                category="Container",
                evidence_type="container-config",
                evidence=[],
            )
            for i, (cid, title) in enumerate(_CONT_CHECKS)
        ]

    def _all_error(self, mode: str) -> list[CheckResult]:
        ref = (self.runner.container if mode == "docker" else self.runner.pod) or "<unknown>"
        inspect_cmd = (
            f"docker inspect {ref}" if mode == "docker" else f"kubectl get pod {ref} -o json"
        )
        return [
            CheckResult(
                check_id=cid,
                title=title,
                status=Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id=f"8.{i + 1}",
                cis_id=f"cis-kafka-1.0-8.{i + 1}",
                fedramp_control=None,
                nist_800_53_controls=[],
                description="Container inspection failed; controls could not be assessed.",
                rationale="Evidence cannot be collected if the runtime inspection command fails.",
                actual=f"inspection failed for {ref}",
                expected="successful container inspect output",
                remediation=f"Verify the container/pod exists and the audit user has permission to run: {inspect_cmd}",
                references=["CIS Docker Benchmark", "CIS Kubernetes Benchmark"],
                category="Container",
                evidence_type="container-config",
                evidence=[self.evidence("container.inspect_error", f"failed: {inspect_cmd}", inspect_cmd)],
            )
            for i, (cid, title) in enumerate(_CONT_CHECKS)
        ]
