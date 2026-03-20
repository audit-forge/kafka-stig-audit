#!/usr/bin/env python3
"""Runner helpers for kafka-stig-audit."""
from dataclasses import dataclass, field
import json
import shlex
import subprocess


@dataclass
class KafkaRunner:
    mode: str = "docker"
    container: str | None = None
    pod: str | None = None
    namespace: str = "default"
    host: str = "127.0.0.1"
    port: int = 9092
    command_prefix: str = ""      # e.g. "/opt/kafka/bin" for non-PATH installs
    username: str | None = None   # SASL username for external checks
    password: str | None = None   # SASL password
    tls: bool = False             # use SSL/TLS for direct connections
    broker_id: str = "0"          # broker entity name for kafka-configs
    verbose: bool = False
    last_error: str | None = None
    command_log: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def bootstrap_server(self) -> str:
        return f"{self.host}:{self.port}"

    def _kafka_cmd(self, script: str) -> list[str]:
        """Resolve a kafka script name (e.g. 'kafka-configs') to a command list."""
        if self.command_prefix:
            import os
            return [os.path.join(self.command_prefix, script)]
        return [script]

    def _wrap(self, inner: list[str]) -> list[str]:
        """Wrap an inner command for docker/kubectl exec."""
        if self.mode == "docker":
            if not self.container:
                raise ValueError("--container is required for docker mode")
            return ["docker", "exec", self.container] + inner
        if self.mode == "kubectl":
            if not self.pod:
                raise ValueError("--pod is required for kubectl mode")
            return ["kubectl", "exec", "-n", self.namespace, self.pod, "--"] + inner
        # direct — run as-is
        return inner

    def exec(self, command: list[str]) -> subprocess.CompletedProcess:
        if self.verbose:
            print("[runner]", shlex.join(command))
        try:
            res = subprocess.run(command, capture_output=True, text=True, timeout=30)
        except FileNotFoundError as exc:
            self.last_error = str(exc)
            entry = {"command": shlex.join(command), "returncode": 127, "stdout": "", "stderr": str(exc)}
            self.command_log.append(entry)
            return subprocess.CompletedProcess(command, 127, "", str(exc))
        except subprocess.TimeoutExpired:
            self.last_error = "timeout"
            entry = {"command": shlex.join(command), "returncode": -1, "stdout": "", "stderr": "timeout"}
            self.command_log.append(entry)
            return subprocess.CompletedProcess(command, -1, "", "timeout")
        self.last_error = res.stderr.strip() or None if res.returncode != 0 else None
        self.command_log.append({
            "command": shlex.join(command),
            "returncode": res.returncode,
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip(),
        })
        return res

    # ------------------------------------------------------------------
    # Kafka CLI wrappers
    # ------------------------------------------------------------------

    def broker_api_versions(self) -> subprocess.CompletedProcess:
        """Run kafka-broker-api-versions to detect version and connectivity."""
        cmd = self._kafka_cmd("kafka-broker-api-versions") + [
            "--bootstrap-server", self.bootstrap_server,
        ]
        return self.exec(self._wrap(cmd))

    def configs_describe(self, entity_type: str = "brokers", entity_name: str | None = None) -> subprocess.CompletedProcess:
        """Run kafka-configs --describe for a given entity type."""
        entity_name = entity_name or self.broker_id
        cmd = self._kafka_cmd("kafka-configs") + [
            "--bootstrap-server", self.bootstrap_server,
            "--describe",
            "--entity-type", entity_type,
            "--entity-name", entity_name,
        ]
        return self.exec(self._wrap(cmd))

    def acls_list(self) -> subprocess.CompletedProcess:
        """Run kafka-acls --list to enumerate all ACLs."""
        cmd = self._kafka_cmd("kafka-acls") + [
            "--bootstrap-server", self.bootstrap_server,
            "--list",
        ]
        return self.exec(self._wrap(cmd))

    def topics_list(self) -> subprocess.CompletedProcess:
        """Run kafka-topics --list."""
        cmd = self._kafka_cmd("kafka-topics") + [
            "--bootstrap-server", self.bootstrap_server,
            "--list",
        ]
        return self.exec(self._wrap(cmd))

    def read_server_properties(self) -> str:
        """Try to read server.properties from the broker container."""
        candidates = [
            "/opt/kafka/config/server.properties",
            "/etc/kafka/server.properties",
            "/kafka/config/server.properties",
            "/opt/bitnami/kafka/config/server.properties",
        ]
        if self.mode == "direct":
            return ""
        for path in candidates:
            if self.mode == "docker":
                cmd = ["docker", "exec", self.container or "", "cat", path]
            else:
                cmd = ["kubectl", "exec", "-n", self.namespace, self.pod or "", "--", "cat", path]
            res = self.exec(cmd)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout
        return ""

    def parse_properties(self, content: str) -> dict[str, str]:
        """Parse a Java .properties file into a dict."""
        props: dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                props[key.strip()] = val.strip()
        return props

    def test_connection(self) -> bool:
        """Test broker connectivity via kafka-broker-api-versions."""
        res = self.broker_api_versions()
        return res.returncode == 0

    def container_inspect(self) -> dict:
        """Return parsed `docker inspect` for the configured container, or {}."""
        if self.mode != "docker" or not self.container:
            return {}
        res = self.exec(["docker", "inspect", self.container])
        if res.returncode != 0:
            return {}
        try:
            data = json.loads(res.stdout)
            return data[0] if isinstance(data, list) and data else {}
        except (json.JSONDecodeError, IndexError):
            return {}

    def pod_inspect(self) -> dict:
        """Return parsed `kubectl get pod -o json` for the configured pod, or {}."""
        if self.mode != "kubectl" or not self.pod:
            return {}
        res = self.exec(["kubectl", "get", "pod", "-n", self.namespace, self.pod, "-o", "json"])
        if res.returncode != 0:
            return {}
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return {}

    def snapshot(self) -> dict:
        """Collect a runtime snapshot of Kafka broker state."""
        props_raw = self.read_server_properties()
        props = self.parse_properties(props_raw) if props_raw else {}

        container_meta: dict | None = None
        if self.mode == "docker":
            container_meta = self.container_inspect() or None
        elif self.mode == "kubectl":
            container_meta = self.pod_inspect() or None

        acls_res = self.acls_list()
        topics_res = self.topics_list()

        return {
            "server_properties": props,
            "acls_raw": acls_res.stdout if acls_res.returncode == 0 else "",
            "topics_raw": topics_res.stdout if topics_res.returncode == 0 else "",
            "command_log_tail": self.command_log[-10:],
            "last_error": self.last_error,
            "container_meta": container_meta,
        }
