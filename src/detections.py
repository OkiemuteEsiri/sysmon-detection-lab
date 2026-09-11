from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from .models import DetectionFinding, SysmonEvent


def _fid(rule: str, host: str, evidence: list[str]) -> str:
    material = f"{rule}|{host}|{'|'.join(sorted(evidence))}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


def _severity(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def detect(events: list[SysmonEvent]) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    by_host: dict[str, list[SysmonEvent]] = defaultdict(list)
    for event in events:
        by_host[event.host].append(event)

    for host, host_events in by_host.items():
        host_events.sort(key=lambda e: e.timestamp)
        findings.extend(_suspicious_powershell(host, host_events))
        findings.extend(_lsass_access(host, host_events))
        findings.extend(_registry_persistence(host, host_events))
        findings.extend(_dns_process_correlation(host, host_events))
        findings.extend(_unsigned_network_process(host, host_events))
    return sorted(findings, key=lambda f: (-f.risk_score, f.finding_id))


def _suspicious_powershell(host: str, events: list[SysmonEvent]) -> list[DetectionFinding]:
    out = []
    terms = (" -enc ", " -encodedcommand ", "frombase64string", "hidden")
    for e in events:
        cl = f" {e.command_line.lower()} "
        if e.event_id == 1 and "powershell" in e.image.lower() and any(t in cl for t in terms):
            score = 82 if "frombase64string" in cl or "encodedcommand" in cl else 74
            out.append(DetectionFinding(_fid("PS", host, [e.record_id]), "Suspicious PowerShell process creation", host, _severity(score), 88, score, ("T1059.001",), (e.record_id,), "Sysmon process telemetry shows PowerShell with encoded or hidden execution indicators.", "Review parent/child process lineage, validate the script source, and contain the endpoint if corroborating malicious activity is present.", "Confirm the command is authorized, remove unauthorized execution sources, and verify no recurrence after remediation."))
    return out


def _lsass_access(host: str, events: list[SysmonEvent]) -> list[DetectionFinding]:
    out = []
    for e in events:
        target = str(e.extra.get("target_image", "")).lower()
        granted = str(e.extra.get("granted_access", "")).lower()
        if e.event_id == 10 and "lsass.exe" in target and granted not in {"", "0x1000", "0x100000"}:
            score = 90
            out.append(DetectionFinding(_fid("LSASS", host, [e.record_id]), "Sensitive process access involving LSASS", host, _severity(score), 90, score, ("T1003.001",), (e.record_id,), "Sysmon process-access telemetry indicates non-trivial access to LSASS; this requires validation because legitimate security tools can also generate this signal.", "Validate the source process and signer, isolate if unauthorized, rotate exposed credentials where appropriate, and preserve endpoint evidence.", "Re-run the approved security workflow or baseline and confirm unauthorized LSASS access no longer occurs."))
    return out


def _registry_persistence(host: str, events: list[SysmonEvent]) -> list[DetectionFinding]:
    keys = ("\\software\\microsoft\\windows\\currentversion\\run", "\\runonce")
    out = []
    for e in events:
        if e.event_id in {12, 13} and any(k in e.target_object.lower() for k in keys):
            score = 72
            out.append(DetectionFinding(_fid("RUNKEY", host, [e.record_id]), "Run key persistence change", host, _severity(score), 80, score, ("T1060",), (e.record_id,), "A Sysmon registry event modified a common autorun location.", "Validate the value, owning application, signer and change ticket; remove unauthorized autoruns and investigate the creating process.", "Confirm the expected autorun baseline and verify the registry value does not reappear."))
    return out


def _dns_process_correlation(host: str, events: list[SysmonEvent]) -> list[DetectionFinding]:
    out = []
    for i, e in enumerate(events):
        if e.event_id != 22:
            continue
        query = str(e.extra.get("query_name", "")).lower()
        if not query.endswith((".invalid", ".test")):
            continue
        evidence = [e.record_id]
        for p in events[max(0, i - 5):i + 1]:
            if p.event_id == 1 and abs(e.timestamp - p.timestamp) <= timedelta(minutes=2):
                evidence.append(p.record_id)
        score = 58 if len(evidence) == 1 else 68
        out.append(DetectionFinding(_fid("DNS", host, evidence), "Unusual DNS query with process context", host, _severity(score), 72, score, ("T1071.004",), tuple(evidence), "Synthetic DNS telemetry shows a query to a documentation-only domain and, when available, correlated process creation context.", "Validate the initiating process and destination reputation in an approved environment; block only with corroborating evidence.", "Confirm the process no longer produces unauthorized DNS activity after remediation."))
    return out


def _unsigned_network_process(host: str, events: list[SysmonEvent]) -> list[DetectionFinding]:
    out = []
    recent_processes = [e for e in events if e.event_id == 1]
    for net in (e for e in events if e.event_id == 3):
        for proc in reversed(recent_processes):
            if proc.image == net.image and timedelta(0) <= net.timestamp - proc.timestamp <= timedelta(minutes=5):
                if proc.signed is False and net.destination_port not in {80, 443}:
                    score = 76
                    ev = [proc.record_id, net.record_id]
                    out.append(DetectionFinding(_fid("UNSIGNEDNET", host, ev), "Unsigned process initiated unusual network connection", host, _severity(score), 82, score, ("T1105", "T1071"), tuple(ev), "An unsigned process created shortly before an outbound connection on a non-web port.", "Validate binary origin and hash, review destination context, and isolate only when the activity is unauthorized or corroborated.", "Confirm the approved binary baseline and verify the connection pattern does not recur."))
                break
    return out
