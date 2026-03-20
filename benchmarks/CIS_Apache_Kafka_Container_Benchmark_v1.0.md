# CIS Apache Kafka Container Security Benchmark v1.0

**Status:** Draft — For Review and Comment
**Release Date:** 2026-03-19
**Applies To:** Apache Kafka 2.8+ (ZooKeeper and KRaft modes), containerized deployments
**Tool:** kafka-stig-audit v0.1.0

---

## Disclaimer

This benchmark is an independent, community-developed security guidance document based
on publicly available Apache Kafka documentation, the CIS Benchmarks program methodology,
and operational experience with Kafka deployments in regulated environments.

This document is **not** an official CIS Benchmark. It has not been reviewed, endorsed,
or published by the Center for Internet Security (CIS). It is published under the
Apache 2.0 license for free use, modification, and distribution.

References to "CIS" in control IDs (e.g., `cis-kafka-1.0-2.1`) indicate alignment with
CIS Benchmark methodology and numbering conventions, not official CIS publication.

---

## Overview

Apache Kafka is a distributed event streaming platform used as the backbone for
real-time data pipelines and streaming applications. When deployed in regulated
environments, Kafka brokers must be hardened to protect:

- **Message confidentiality** — topics may carry PII, financial data, health records
- **Message integrity** — tampering with Kafka events corrupts downstream systems
- **Availability** — Kafka is typically a critical data path with zero-tolerance for downtime
- **Authentication and authorization** — producers and consumers must be identified and scoped

This benchmark covers Kafka broker security in containerized deployments (Docker and Kubernetes),
addressing both Kafka-specific configuration and container runtime posture.

---

## Scope

### In Scope
- Apache Kafka broker configuration (`server.properties`, JAAS config)
- SASL authentication mechanisms (SCRAM, GSSAPI, PLAIN)
- TLS/SSL configuration for client and inter-broker communication
- ACL authorization (AclAuthorizer, StandardAuthorizer)
- ZooKeeper security (pre-KRaft deployments)
- Container runtime hardening (Docker and Kubernetes)
- CVE and CISA KEV vulnerability management

### Out of Scope
- Kafka Connect worker configuration
- Kafka Streams application security
- Schema Registry security
- KSQL/ksqlDB security
- Zookeeper server configuration (only broker-side ZK config)
- Producer/consumer client security

---

## Assessment Profile

| Profile | Description |
|---------|-------------|
| Level 1 | Minimum security baseline; suitable for all Kafka deployments |
| Level 2 | Enhanced security; suitable for regulated and sensitive workloads |

---

## Section 1 — Benchmark Overview

### 1.1 Control Numbering

Controls are numbered as `§N.M` where N is the section and M is the control sequence.
Each control has a corresponding automated check ID (e.g., `KF-AUTH-001`).

### 1.2 Assessment Modes

The `kafka-stig-audit` tool supports three assessment modes:

| Mode | Description |
|------|-------------|
| `docker` | Exec into a running Kafka container via `docker exec` |
| `kubectl` | Exec into a Kafka pod via `kubectl exec` |
| `direct` | Connect to Kafka broker directly via network |

Container-level checks (Section 8) require `docker` or `kubectl` mode.

---

## Section 2 — Authentication

Authentication in Kafka is handled at the listener level via SASL mechanisms.
Every broker should require authenticated connections from clients, inter-broker
peers, and ZooKeeper.

### 2.1 — SASL Authentication Enabled on Client-Facing Listeners (KF-AUTH-001)

**Profile:** Level 1 | **Severity:** CRITICAL

**Description:**
Configure at least one listener with SASL_SSL or SASL_PLAINTEXT protocol to require
client authentication. Unauthenticated listeners allow any reachable host to produce
or consume messages.

**Rationale:**
Without authentication, there is no concept of identity in Kafka. Any network-reachable
client can produce to any topic, consume any message, and perform cluster operations
without audit attribution.

**Assessment:**
Check that `listeners` in `server.properties` contains `SASL_SSL://` or `SASL_PLAINTEXT://`,
and that `listener.security.protocol.map` maps listener names to SASL-enabled protocols.

**Remediation:**
```properties
listeners=SASL_SSL://0.0.0.0:9093
listener.security.protocol.map=SASL_SSL:SASL_SSL
inter.broker.listener.name=SASL_SSL
```

**Framework Mappings:**
NIST 800-53: IA-2, AC-3, AC-17 | NIST 800-171: 3.5.1, 3.5.2, 3.1.1 | CMMC Level 1

---

### 2.2 — SASL Mechanism is SCRAM-SHA-256/512 or GSSAPI (KF-AUTH-002)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Use SCRAM-SHA-256, SCRAM-SHA-512, or GSSAPI (Kerberos) as the SASL mechanism.
SASL/PLAIN transmits credentials in base64 form and should not be used as the
sole mechanism.

**Rationale:**
SCRAM provides cryptographic proof-of-knowledge. The password is never transmitted
in a form that can be decoded from a TLS session key compromise, unlike PLAIN which
is effectively base64-encoded cleartext.

**Assessment:**
Check `sasl.enabled.mechanisms` for SCRAM-SHA-256, SCRAM-SHA-512, or GSSAPI.
PLAIN without a stronger alternative is a failure.

**Remediation:**
```properties
sasl.enabled.mechanisms=SCRAM-SHA-256
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-256
```

**Framework Mappings:**
NIST 800-53: IA-5, SC-8, AC-17 | NIST 800-171: 3.5.3, 3.5.7, 3.5.10 | CMMC Level 2

---

### 2.3 — No PLAINTEXT Protocol Used for Client Listeners (KF-AUTH-003)

**Profile:** Level 1 | **Severity:** CRITICAL

**Description:**
Eliminate PLAINTEXT:// protocol from all Kafka listeners. PLAINTEXT provides no
encryption and no authentication and must not be used in production.

**Assessment:**
Check that `listeners` and `listener.security.protocol.map` contain no PLAINTEXT mappings.

**Remediation:**
Replace any `PLAINTEXT://` listener with `SSL://` or `SASL_SSL://`. Update all clients.

**Framework Mappings:**
NIST 800-53: SC-8, SC-8(1), IA-2 | NIST 800-171: 3.13.8, 3.5.1 | CMMC Level 2

---

### 2.4 — Inter-Broker Authentication Enabled (KF-AUTH-004)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Configure `security.inter.broker.protocol=SASL_SSL` to require authenticated,
encrypted communication between Kafka brokers for replication.

**Assessment:**
Check `security.inter.broker.protocol` for SSL or SASL_SSL.

**Remediation:**
```properties
security.inter.broker.protocol=SASL_SSL
sasl.mechanism.inter.broker.protocol=SCRAM-SHA-256
```

**Framework Mappings:**
NIST 800-53: SC-8, SC-8(1), IA-3 | NIST 800-171: 3.13.8, 3.5.2 | CMMC Level 2

---

### 2.5 — ZooKeeper Authentication Enabled (KF-AUTH-005)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Set `zookeeper.set.acl=true` to configure ZooKeeper ACLs on all Kafka-created znodes.
(Not applicable in KRaft mode.)

**Assessment:**
Check `zookeeper.set.acl` and `zookeeper.sasl.client` in `server.properties`.

**Remediation:**
```properties
zookeeper.set.acl=true
# Configure JAAS:
# -Djava.security.auth.login.config=/etc/kafka/kafka_server_jaas.conf
```

**Framework Mappings:**
NIST 800-53: AC-3, AC-6, IA-2 | NIST 800-171: 3.1.1, 3.5.1 | CMMC Level 1

---

## Section 3 — Encryption

### 3.1 — TLS/SSL Enabled for Client Connections (KF-ENC-001)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
All client-facing Kafka listeners must use TLS to encrypt data in transit.
Configure an SSL or SASL_SSL listener with a valid keystore and truststore.

**Remediation:**
```properties
ssl.keystore.location=/var/private/ssl/kafka.keystore.jks
ssl.keystore.password=<password>
ssl.key.password=<password>
ssl.truststore.location=/var/private/ssl/kafka.truststore.jks
ssl.truststore.password=<password>
```

**Framework Mappings:**
NIST 800-53: SC-8, SC-8(1), SC-23 | NIST 800-171: 3.13.8 | CMMC Level 2

---

### 3.2 — TLS/SSL Enabled for Inter-Broker Communication (KF-ENC-002)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Kafka broker-to-broker replication traffic must be encrypted with TLS.
Set `security.inter.broker.protocol=SASL_SSL` or `SSL`.

**Framework Mappings:**
NIST 800-53: SC-8, SC-8(1) | NIST 800-171: 3.13.8 | CMMC Level 2

---

### 3.3 — Strong TLS Cipher Suites Configured (KF-ENC-003)

**Profile:** Level 2 | **Severity:** MEDIUM

**Description:**
Explicitly configure `ssl.cipher.suites` and `ssl.enabled.protocols` to exclude
weak ciphers (NULL, EXPORT, DES, RC4) and deprecated protocol versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1).

**Remediation:**
```properties
ssl.enabled.protocols=TLSv1.2,TLSv1.3
ssl.cipher.suites=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

**Framework Mappings:**
NIST 800-53: SC-8, SC-23, CM-6 | NIST 800-171: 3.13.8, 3.4.2 | CMMC Level 2

---

### 3.4 — TLS Client Certificate Validation Enforced (KF-ENC-004)

**Profile:** Level 2 | **Severity:** MEDIUM

**Description:**
Set `ssl.client.auth=required` to require clients to present a valid certificate
signed by the broker's trusted CA.

**Remediation:**
```properties
ssl.client.auth=required
```

**Framework Mappings:**
NIST 800-53: SC-17, IA-5, SC-8 | NIST 800-171: 3.5.3, 3.13.8 | CMMC Level 2

---

### 3.5 — ZooKeeper Connection Encrypted (KF-ENC-005)

**Profile:** Level 2 | **Severity:** HIGH

**Description:**
Configure TLS for Kafka-to-ZooKeeper connections using `zookeeper.ssl.client.enable=true`.
(Not applicable in KRaft mode.)

**Remediation:**
```properties
zookeeper.ssl.client.enable=true
zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty
zookeeper.ssl.keystore.location=/path/to/kafka.keystore.jks
zookeeper.ssl.truststore.location=/path/to/kafka.truststore.jks
```

**Framework Mappings:**
NIST 800-53: SC-8, SC-8(1) | NIST 800-171: 3.13.8 | CMMC Level 2

---

## Section 4 — Authorization

### 4.1 — ACL Authorizer Enabled (KF-AUTHZ-001)

**Profile:** Level 1 | **Severity:** CRITICAL

**Description:**
Set `authorizer.class.name` to enable ACL enforcement. Without an authorizer,
authenticated clients have unrestricted access to all resources.

**Remediation:**
```properties
# ZooKeeper mode:
authorizer.class.name=kafka.security.authorizer.AclAuthorizer
# KRaft mode:
authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer
```

**Framework Mappings:**
NIST 800-53: AC-3, AC-6, AC-17 | NIST 800-171: 3.1.1, 3.1.2, 3.1.5 | CMMC Level 1

---

### 4.2 — Super Users Restricted (KF-AUTHZ-002)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Limit `super.users` to the minimum required principals (≤3). Super users bypass all
ACL checks. Remove application service accounts from this list.

**Framework Mappings:**
NIST 800-53: AC-6, AC-6(5), AC-2 | NIST 800-171: 3.1.5, 3.1.6 | CMMC Level 1

---

### 4.3 — Default Deny Policy Enforced (KF-AUTHZ-003)

**Profile:** Level 1 | **Severity:** CRITICAL

**Description:**
Set `allow.everyone.if.no.acl.found=false` to enforce deny-by-default. The Kafka
default (true) allows any authenticated user to access resources without ACLs.

**Remediation:**
```properties
allow.everyone.if.no.acl.found=false
```

**Framework Mappings:**
NIST 800-53: AC-3, AC-6, CM-6 | NIST 800-171: 3.1.1, 3.1.2 | CMMC Level 1

---

### 4.4 — Topic-Level ACLs Configured (KF-AUTHZ-004)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Each topic must have explicit ACLs granting only the required principals Read or
Write access. Wildcard principal grants (User:*) must be avoided.

**Remediation:**
```bash
kafka-acls --bootstrap-server localhost:9092 \
  --add --allow-principal User:app1 \
  --operation Read --topic my-topic
```

**Framework Mappings:**
NIST 800-53: AC-3, AC-6, AC-2 | NIST 800-171: 3.1.2, 3.1.5 | CMMC Level 1

---

### 4.5 — Cluster-Level ACLs Restricted (KF-AUTHZ-005)

**Profile:** Level 2 | **Severity:** HIGH

**Description:**
Verify that no wildcard principal (User:*) has ClusterAction or other cluster-level
operations. ClusterAction should be restricted to broker principals only.

**Framework Mappings:**
NIST 800-53: AC-6(2), AC-3 | NIST 800-171: 3.1.5, 3.1.2 | CMMC Level 2

---

## Section 5 — Network Security

### 5.1 — Listeners Not Binding PLAINTEXT to All Interfaces (KF-NET-001)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Kafka must not bind PLAINTEXT listeners to 0.0.0.0. All externally accessible
listeners must use SSL or SASL_SSL.

**Framework Mappings:**
NIST 800-53: SC-7, SC-7(5), CM-7 | NIST 800-171: 3.13.1, 3.4.6 | CMMC Level 1

---

### 5.2 — advertised.listeners Configured (KF-NET-002)

**Profile:** Level 1 | **Severity:** MEDIUM

**Description:**
Set `advertised.listeners` to broker-specific hostnames using SSL or SASL_SSL protocol.
Do not use 0.0.0.0 as an advertised address.

**Framework Mappings:**
NIST 800-53: SC-7, CM-6 | NIST 800-171: 3.13.1, 3.4.2 | CMMC Level 1

---

### 5.3 — JMX Port Secured or Disabled (KF-NET-003)

**Profile:** Level 2 | **Severity:** MEDIUM

**Description:**
If JMX is enabled (JMX_PORT environment variable), configure JMX authentication
and SSL. If not required, remove the JMX_PORT environment variable.

**Remediation:**
```bash
# In JVM args / environment:
-Dcom.sun.management.jmxremote.authenticate=true
-Dcom.sun.management.jmxremote.ssl=true
-Dcom.sun.management.jmxremote.access.file=/etc/kafka/jmxremote.access
```

**Framework Mappings:**
NIST 800-53: CM-7, SC-7, AC-17 | NIST 800-171: 3.4.6, 3.4.7 | CMMC Level 2

---

### 5.4 — Auto Topic Creation Disabled (KF-NET-004)

**Profile:** Level 2 | **Severity:** LOW

**Description:**
Set `auto.create.topics.enable=false` to prevent unauthenticated topic creation
via producer/consumer reference.

**Remediation:**
```properties
auto.create.topics.enable=false
```

**Framework Mappings:**
NIST 800-53: CM-7 | NIST 800-171: 3.4.6, 3.4.7 | CMMC Level 2

---

## Section 6 — Logging and Monitoring

### 6.1 — Log Retention Configured (KF-LOG-001)

**Profile:** Level 1 | **Severity:** MEDIUM

**Description:**
Configure `log.retention.hours` or `log.retention.ms` for an appropriate retention
period. NIST SP 800-92 recommends ≥90 days for audit logs.

**Remediation:**
```properties
log.retention.hours=720  # 30 days
```

**Framework Mappings:**
NIST 800-53: AU-11, AU-4, SI-12 | NIST 800-171: 3.3.1 | CMMC Level 2

---

### 6.2 — Security Events Logged (KF-LOG-002)

**Profile:** Level 1 | **Severity:** MEDIUM

**Description:**
Configure `kafka.authorizer.logger` in Log4j at INFO or DEBUG level to capture
authorization decisions and authentication failures.

**Remediation:**
Add to `log4j.properties`:
```properties
log4j.logger.kafka.authorizer.logger=INFO, authorizerAppender
log4j.logger.kafka.security=INFO, authorizerAppender
```

**Framework Mappings:**
NIST 800-53: AU-2, AU-12 | NIST 800-171: 3.3.1, 3.3.2 | CMMC Level 2

---

### 6.3 — Request Logging Enabled (KF-LOG-003)

**Profile:** Level 2 | **Severity:** MEDIUM

**Description:**
Enable `kafka.request.logger` to create an audit trail of produce/consume requests.

**Remediation:**
```properties
log4j.logger.kafka.request.logger=WARN, requestAppender
```

**Framework Mappings:**
NIST 800-53: AU-3, AU-12, AU-14 | NIST 800-171: 3.3.1, 3.3.2 | CMMC Level 2

---

## Section 7 — ZooKeeper Security

*(Controls apply only to ZooKeeper-based deployments; all are SKIP in KRaft mode.)*

### 7.1 — ZooKeeper SASL Authentication and ACLs Enforced (KF-ZK-001)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Set `zookeeper.set.acl=true` so Kafka configures ZooKeeper node ACLs to restrict
access to authenticated Kafka processes.

**Framework Mappings:**
NIST 800-53: AC-3, AC-6, IA-2 | NIST 800-171: 3.1.1, 3.5.1 | CMMC Level 1

---

### 7.2 — ZooKeeper Connection Encrypted (KF-ZK-002)

**Profile:** Level 2 | **Severity:** HIGH

**Description:**
Enable `zookeeper.ssl.client.enable=true` with a configured keystore and truststore
to encrypt the Kafka-to-ZooKeeper connection.

**Framework Mappings:**
NIST 800-53: SC-8, SC-8(1) | NIST 800-171: 3.13.8 | CMMC Level 2

---

### 7.3 — ZooKeeper Session Timeout Configured (KF-ZK-003)

**Profile:** Level 2 | **Severity:** LOW

**Description:**
Configure `zookeeper.session.timeout.ms` between 6000 and 30000 ms (6–30 seconds).
Very short timeouts cause instability; very long timeouts delay broker failure detection.

**Remediation:**
```properties
zookeeper.session.timeout.ms=18000
```

**Framework Mappings:**
NIST 800-53: SC-5, CM-6 | NIST 800-171: 3.4.2 | CMMC Level 2

---

## Section 8 — Container Runtime Hardening

### 8.1 — Kafka Container Runs as Non-Root User (KF-CONT-001)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
The Kafka process must run as a non-root user (e.g., kafka UID 1000).
Running as root amplifies container escape impact.

**Remediation (Docker):**
```dockerfile
RUN groupadd -r kafka && useradd -r -g kafka kafka
USER kafka
```

**Remediation (Kubernetes):**
```yaml
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
```

**Framework Mappings:**
NIST 800-53: AC-6, CM-7 | NIST 800-171: 3.1.5, 3.1.6, 3.4.6 | CMMC Level 1

---

### 8.2 — Kafka Container Not Privileged (KF-CONT-002)

**Profile:** Level 1 | **Severity:** CRITICAL

**Description:**
The Kafka container must never run with `privileged: true`. There is no operational
requirement for Kafka to have privileged container access.

**Remediation (Kubernetes):**
```yaml
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
```

**Framework Mappings:**
NIST 800-53: CM-7, AC-6, SC-4 | NIST 800-171: 3.4.2, 3.4.6 | CMMC Level 2

---

### 8.3 — No Dangerous Linux Capabilities (KF-CONT-003)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Drop ALL Linux capabilities. Kafka requires no special capabilities for normal operation.

**Remediation (Kubernetes):**
```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
```

**Framework Mappings:**
NIST 800-53: CM-7, AC-6 | NIST 800-171: 3.4.6, 3.4.7 | CMMC Level 2

---

### 8.4 — Read-Only Root Filesystem (KF-CONT-004)

**Profile:** Level 2 | **Severity:** MEDIUM

**Description:**
Mount the Kafka container's root filesystem as read-only. Mount Kafka log directories
and `/tmp` as writable volumes.

**Remediation (Kubernetes):**
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: kafka-logs
    mountPath: /opt/kafka/logs
  - name: tmp
    mountPath: /tmp
```

**Framework Mappings:**
NIST 800-53: CM-7, SC-28 | NIST 800-171: 3.4.2 | CMMC Level 2

---

### 8.5 — Resource Limits Configured (KF-CONT-005)

**Profile:** Level 1 | **Severity:** MEDIUM

**Description:**
Set CPU and memory limits for the Kafka container to prevent resource exhaustion
and denial-of-service to co-located workloads.

**Remediation (Kubernetes):**
```yaml
resources:
  limits:
    memory: "8Gi"
    cpu: "4"
  requests:
    memory: "4Gi"
    cpu: "2"
```

**Framework Mappings:**
NIST 800-53: SC-6, SI-17 | NIST 800-171: 3.4.2 | CMMC Level 2

---

### 8.6 — No Host Namespace Sharing (KF-CONT-006)

**Profile:** Level 1 | **Severity:** HIGH

**Description:**
Do not configure `hostNetwork`, `hostPID`, or `hostIPC` for the Kafka pod.
Kafka does not require host namespace access for normal operation.

**Remediation (Kubernetes):**
```yaml
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
```

**Framework Mappings:**
NIST 800-53: SC-4, SC-7, AC-6 | NIST 800-171: 3.4.2, 3.1.3, 3.1.5 | CMMC Level 2

---

## Appendix A — Control Summary

| Control ID | Section | Title | Severity | Level |
|-----------|---------|-------|----------|-------|
| KF-AUTH-001 | 2.1 | SASL authentication enabled | CRITICAL | 1 |
| KF-AUTH-002 | 2.2 | SCRAM-SHA-256/512 or GSSAPI | HIGH | 1 |
| KF-AUTH-003 | 2.3 | No PLAINTEXT listeners | CRITICAL | 1 |
| KF-AUTH-004 | 2.4 | Inter-broker authentication | HIGH | 1 |
| KF-AUTH-005 | 2.5 | ZooKeeper authentication | HIGH | 1 |
| KF-ENC-001 | 3.1 | TLS for client connections | HIGH | 1 |
| KF-ENC-002 | 3.2 | TLS for inter-broker | HIGH | 1 |
| KF-ENC-003 | 3.3 | Strong cipher suites | MEDIUM | 2 |
| KF-ENC-004 | 3.4 | Client cert validation | MEDIUM | 2 |
| KF-ENC-005 | 3.5 | ZooKeeper TLS | HIGH | 2 |
| KF-AUTHZ-001 | 4.1 | ACL authorizer enabled | CRITICAL | 1 |
| KF-AUTHZ-002 | 4.2 | Super users restricted | HIGH | 1 |
| KF-AUTHZ-003 | 4.3 | Default deny policy | CRITICAL | 1 |
| KF-AUTHZ-004 | 4.4 | Topic-level ACLs | HIGH | 1 |
| KF-AUTHZ-005 | 4.5 | Cluster ACLs restricted | HIGH | 2 |
| KF-NET-001 | 5.1 | No PLAINTEXT on 0.0.0.0 | HIGH | 1 |
| KF-NET-002 | 5.2 | advertised.listeners configured | MEDIUM | 1 |
| KF-NET-003 | 5.3 | JMX secured or disabled | MEDIUM | 2 |
| KF-NET-004 | 5.4 | Auto topic creation disabled | LOW | 2 |
| KF-LOG-001 | 6.1 | Log retention configured | MEDIUM | 1 |
| KF-LOG-002 | 6.2 | Security events logged | MEDIUM | 1 |
| KF-LOG-003 | 6.3 | Request logging enabled | MEDIUM | 2 |
| KF-ZK-001 | 7.1 | ZooKeeper SASL ACLs | HIGH | 1 |
| KF-ZK-002 | 7.2 | ZooKeeper TLS | HIGH | 2 |
| KF-ZK-003 | 7.3 | ZooKeeper session timeout | LOW | 2 |
| KF-CONT-001 | 8.1 | Non-root user | HIGH | 1 |
| KF-CONT-002 | 8.2 | Not privileged | CRITICAL | 1 |
| KF-CONT-003 | 8.3 | No dangerous capabilities | HIGH | 1 |
| KF-CONT-004 | 8.4 | Read-only root filesystem | MEDIUM | 2 |
| KF-CONT-005 | 8.5 | Resource limits | MEDIUM | 1 |
| KF-CONT-006 | 8.6 | No host namespace sharing | HIGH | 1 |
| KF-VER-001 | — | CVE/KEV scan | VARIABLE | 1 |

**Total: 31 controls + 1 CVE scan = 32 automated checks**

---

## Appendix B — Framework Mapping Matrix

| Control ID | NIST 800-53 | NIST 800-171 | CMMC Level | MITRE ATT&CK |
|-----------|-------------|--------------|------------|--------------|
| KF-AUTH-001 | IA-2, AC-3 | 3.5.1, 3.5.2 | 1 | T1133, T1078 |
| KF-AUTH-002 | IA-5, SC-8 | 3.5.3, 3.5.7 | 2 | T1110, T1040 |
| KF-AUTH-003 | SC-8, SC-8(1) | 3.13.8 | 2 | T1040, T1557 |
| KF-AUTH-004 | SC-8, IA-3 | 3.13.8, 3.5.2 | 2 | T1557, T1040 |
| KF-AUTH-005 | AC-3, IA-2 | 3.1.1, 3.5.1 | 1 | T1078 |
| KF-ENC-001 | SC-8, SC-23 | 3.13.8 | 2 | T1040, T1557 |
| KF-AUTHZ-001 | AC-3, AC-6 | 3.1.1, 3.1.2 | 1 | T1078, T1530 |
| KF-AUTHZ-003 | AC-3, AC-6 | 3.1.1, 3.1.2 | 1 | T1530 |
| KF-CONT-001 | AC-6, CM-7 | 3.1.5, 3.4.6 | 1 | T1611, T1068 |
| KF-CONT-002 | CM-7, SC-4 | 3.4.2, 3.4.6 | 2 | T1611 |

*(Full matrix available in mappings/MITRE-mappings.csv and mappings/CMMC-compliance-matrix.csv)*

---

## Appendix C — CVE/KEV Vulnerability Scanning

The `kafka-stig-audit` tool integrates with:

- **NVD API v2** — NIST National Vulnerability Database for known CVEs
- **CISA KEV Catalog** — Known Exploited Vulnerabilities catalog

Results are cached for 24 hours in `data/cve_cache.json` and `data/kev_cache.json`.

Set `NVD_API_KEY` environment variable for higher NVD rate limits.

See `docs/CVE_SCANNING.md` for details.

---

*This document is maintained by the audit-forge community. Contributions welcome via GitHub.*
