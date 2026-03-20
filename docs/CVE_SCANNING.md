# CVE/KEV Vulnerability Scanning

`kafka-stig-audit` integrates with the NIST National Vulnerability Database (NVD)
and the CISA Known Exploited Vulnerabilities (KEV) catalog to identify known
vulnerabilities in the detected Kafka version.

## How It Works

1. **Version Detection** — runs `kafka-broker-api-versions` and parses the version string
2. **NVD Query** — searches NVD API v2 for CVEs matching "apache kafka \<version\>"
3. **KEV Cross-reference** — checks each CVE against the CISA KEV catalog
4. **Result Generation** — produces a `KF-VER-001` CheckResult with severity based on CVSS/KEV

## Version Detection

The version is detected from `kafka-broker-api-versions` output, which prints
the broker version as part of the API versions response.

If version detection fails, the CVE scan is skipped with a warning.

## NVD API Integration

### Rate Limits

Without an API key:
- 5 requests per 30 seconds
- The tool sleeps 6 seconds between requests

With an API key:
- 50 requests per 30 seconds

### Setting an API Key

```bash
export NVD_API_KEY=your-api-key-here
python audit.py --mode docker --container kafka
```

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

## CISA KEV Catalog

The CISA Known Exploited Vulnerabilities catalog lists CVEs that are actively
exploited in the wild. A KEV hit automatically elevates severity to CRITICAL
regardless of CVSS score, since active exploitation represents immediate risk.

## Caching

Results are cached for 24 hours:
- `data/cve_cache.json` — NVD CVE data (keyed by "product:version")
- `data/kev_cache.json` — CISA KEV catalog (full catalog)

### Cache Invalidation

Delete the cache files to force a fresh fetch:
```bash
rm data/cve_cache.json data/kev_cache.json
```

### Offline Mode

Stale cache (>24 hours old) is used as fallback on network failure.
The tool warns when returning stale data.

## Severity Calculation

| Condition | Severity |
|-----------|----------|
| CVE in CISA KEV catalog | CRITICAL |
| CVSS score ≥ 9.0 | CRITICAL |
| CVSS score ≥ 7.0 | HIGH |
| CVSS score < 7.0 | MEDIUM |
| No CVEs found | INFO (PASS) |

## Skipping CVE Scans

Use `--skip-cve` for faster compliance-only scans:

```bash
python audit.py --mode docker --container kafka --skip-cve
```

## CVE Filtering

The NVD search uses keyword `"apache kafka <version>"`. Results are filtered
to ensure the description contains "kafka" or "apache" to reduce false positives.

## Output

CVE findings appear as `KF-VER-001` in all output formats:

```json
{
  "check_id": "KF-VER-001",
  "title": "Apache Kafka version 3.5.0 — CVE/KEV vulnerability scan",
  "status": "FAIL",
  "severity": "HIGH",
  "cve_ids": ["CVE-2024-XXXXX", "CVE-2024-YYYYY"],
  "kev_score": "",
  "cve_remediation": "Upgrade Apache Kafka to a patched version...",
  "local_path": "/opt/kafka/bin/kafka-server-start.sh"
}
```

In CSV output:
- `CVE_ID` — semicolon-separated list of CVE IDs
- `KEV_Score` — `HIGH_PRIORITY (CISA KEV - Added: YYYY-MM-DD)` if KEV hit
- `CVE_Remediation` — upgrade guidance

## Notable Kafka CVEs (Historical Reference)

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2024-27309 | HIGH | Apache Kafka: Incorrect Access Control |
| CVE-2023-25194 | HIGH | RCE in Kafka Connect |
| CVE-2022-34917 | HIGH | Heap OOM DoS in Kafka broker |

Always query NVD directly for the most current vulnerability data.

## Kafka CVE Resources

- Apache Kafka CVE List: https://kafka.apache.org/cve-list
- NVD Kafka Search: https://nvd.nist.gov/vuln/search/results?query=apache+kafka
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
