# Example Sysmon Detection Assessment

## Executive Summary

Synthetic telemetry produced several investigation-worthy signals across three lab endpoints. The highest-priority item is sensitive access to LSASS on `LAB-WIN-01`, followed by encoded PowerShell execution, a Run-key change, and an unsigned process establishing a non-standard outbound connection on `LAB-WIN-02`.

These detections are evidence-based triage signals, not proof of compromise. Each requires validation against endpoint ownership, software inventory, change records, signer information, and supporting EDR/identity/network telemetry.

## Priority Findings

### Sensitive process access involving LSASS
- Host: `LAB-WIN-01`
- Severity: Critical
- ATT&CK: T1003.001
- Action: validate the source process and signer; isolate only if unauthorized or corroborated; assess credential exposure and preserve evidence.

### Suspicious PowerShell process creation
- Host: `LAB-WIN-01`
- Severity: High
- ATT&CK: T1059.001
- Action: review parent-child lineage and script provenance; remove unauthorized execution sources and revalidate.

### Run key persistence change
- Host: `LAB-WIN-01`
- Severity: High
- ATT&CK: T1060
- Action: validate the autorun against approved software/change records and remove unauthorized persistence.

### Unsigned process with unusual outbound connection
- Host: `LAB-WIN-02`
- Severity: High
- ATT&CK: T1105, T1071
- Action: review binary origin/hash and destination context before containment or blocking decisions.

## Closure Standard

A finding is not considered closed solely because the original event stops appearing. Closure requires documented remediation, evidence that the control state is restored, and a revalidation step demonstrating that the unauthorized condition does not recur.
