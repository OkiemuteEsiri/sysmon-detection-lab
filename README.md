# Sysmon Detection Lab

Defensive Windows detection-engineering project that turns synthetic Sysmon telemetry into explainable, evidence-backed findings with risk scoring, ATT&CK context, investigation guidance, remediation, and revalidation criteria.

## Why this project exists

Sysmon is valuable because it provides rich endpoint telemetry, but raw event volume alone does not create useful detections. This lab demonstrates how to convert selected Sysmon Event IDs into structured security findings while preserving evidence, separating severity from confidence, and avoiding the common mistake of treating an ATT&CK mapping as proof of compromise.

## Capabilities

- Immutable, validated Sysmon event and finding models.
- Fail-closed JSON ingestion with required-field checks and duplicate record-ID rejection.
- Host-scoped, deterministic defensive detections.
- Explainable 0–100 risk scoring with separate confidence values.
- ATT&CK-aligned investigation context.
- Evidence-preserving Markdown reporting.
- Offline CLI suitable for CI and lab workflows.
- Clearly synthetic telemetry using documentation-only domains/IP ranges.
- Unit tests covering validation, detection behavior, false-positive controls, deterministic output, and reporting.
- Remediation and revalidation guidance for every finding.

## Detection coverage

| Detection | Sysmon context | ATT&CK |
|---|---|---|
| Suspicious PowerShell execution | Event ID 1 | T1059.001 |
| Sensitive LSASS process access | Event ID 10 | T1003.001 |
| Run/RunOnce persistence change | Event IDs 12/13 | T1060 |
| DNS query with process context | Event ID 22 | T1071.004 |
| Unsigned process + unusual outbound network connection | Event IDs 1 + 3 | T1105, T1071 |

These mappings are used as taxonomy and triage context. They do not by themselves establish malicious intent or successful compromise.

## Architecture

```text
Synthetic Sysmon JSON
        |
        v
  Fail-closed ingestion
        |
        v
Validated immutable models
        |
        v
 Host-scoped detection engine
        |
        +--> risk score / severity / confidence
        +--> evidence IDs
        +--> ATT&CK context
        +--> remediation + validation
        |
        v
 Markdown assessment report
```

## Repository structure

```text
.github/workflows/ci.yml     Least-privilege GitHub Actions workflow
data/                        Synthetic Sysmon telemetry
src/models.py                Domain models and validation
src/io.py                    Fail-closed JSON ingestion
src/detections.py            Detection and correlation logic
src/reporting.py             Executive/technical reporting
src/cli.py                   Offline CLI
tests/                       Unit tests
docs/                        Architecture and methodology
reports/                     Example output
```

## Run locally

Requires Python 3.12+ and no third-party packages.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_sysmon_events.json --output reports/generated-assessment.md
```

## Detection-engineering approach

The lab deliberately favors transparent logic over opaque scoring. Each finding contains the supporting evidence IDs, rationale, risk score, confidence, ATT&CK context, remediation guidance, and a validation condition. This makes the output suitable for analyst review and post-remediation verification rather than simply producing alerts.

The current rules cover both single-event and correlated behavior. For example, a network connection from an unsigned process is only raised when process-creation telemetry and network telemetry align on the same host/image within a short time window. A signed process connecting over normal web ports is intentionally not treated the same way.

## Investigation workflow

1. Validate telemetry integrity and timestamps.
2. Review process lineage, signer state, user context, asset criticality, and approved-change evidence.
3. Correlate endpoint findings with identity, network, EDR, and threat-intelligence context where available.
4. Escalate or contain only when the activity is unauthorized or corroborated.
5. Preserve relevant evidence before destructive remediation where operationally feasible.
6. Remediate the underlying condition.
7. Revalidate the endpoint and document closure evidence.

## Skills demonstrated

- Windows endpoint telemetry analysis
- Sysmon event interpretation
- Detection engineering
- Python security automation
- Defensive correlation logic
- Risk scoring and evidence preservation
- MITRE ATT&CK mapping
- Incident-response triage
- Security reporting
- Remediation validation
- Unit testing and CI/CD security hygiene

## Limitations

This repository is a defensive lab, not a production detection platform. It does not perform live endpoint collection, EDR isolation, credential extraction, memory dumping, exploit delivery, persistence deployment, or production targeting. The included data is synthetic and intentionally non-sensitive.

## Roadmap

Future safe extensions may include process-tree enrichment, baseline-aware prevalence scoring, signer reputation inputs from synthetic fixtures, configurable suppression rules, additional Sysmon Event IDs, Sigma-rule export, and ATT&CK coverage reporting.

## Safety statement

This project is intended for authorized defensive security engineering, detection validation, incident response, education, and portfolio demonstration only.
