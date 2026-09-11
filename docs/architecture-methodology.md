# Architecture and Detection Methodology

## Purpose

This lab demonstrates defensive detection engineering using synthetic Sysmon telemetry. It is designed for investigation, validation, and recruiter-facing portfolio evidence rather than live endpoint control.

## Architecture

1. `src/io.py` performs fail-closed JSON ingestion, required-field validation, timestamp normalization, and duplicate record-ID rejection.
2. `src/models.py` defines immutable telemetry and finding models with explicit schema constraints.
3. `src/detections.py` performs host-scoped correlation and explainable rule evaluation.
4. `src/reporting.py` converts findings into executive and technical Markdown output.
5. `src/cli.py` provides an offline command-line workflow suitable for CI smoke tests.

## Detection Coverage

- Suspicious PowerShell process creation using Sysmon Event ID 1.
- Sensitive process access involving LSASS using Event ID 10.
- Registry Run/RunOnce persistence changes using Event IDs 12/13.
- DNS activity using Event ID 22, with optional process context.
- Unsigned process plus unusual outbound connection correlation using Event IDs 1 and 3.

## Risk Model

Risk is intentionally bounded to 0–100 and is explainable per rule. Severity is derived from risk score while confidence remains a separate field. This prevents severity and certainty from being conflated.

## ATT&CK Context

Mappings include T1059.001, T1003.001, T1060, T1071/T1071.004, and T1105. ATT&CK mappings are contextual taxonomy only; they do not prove malicious intent or compromise.

## Investigation Workflow

1. Validate source telemetry and timestamp integrity.
2. Review parent/child process lineage and code-signing state.
3. Correlate endpoint, identity, network, and change-management context.
4. Escalate only when the activity is unauthorized or corroborated.
5. Preserve evidence before containment where operationally feasible.
6. Apply remediation.
7. Re-run collection or baseline validation and document closure evidence.

## Limitations

This repository does not include live collection agents, EDR API actions, memory dumping, credential extraction, offensive payloads, or production targeting. Synthetic domains and documentation IP ranges are used for demonstrations.
