from __future__ import annotations

from collections import Counter

from .models import DetectionFinding


def metrics(findings: list[DetectionFinding]) -> dict[str, object]:
    return {
        "total_findings": len(findings),
        "critical_high": sum(f.severity in {"Critical", "High"} for f in findings),
        "hosts": len({f.host for f in findings}),
        "highest_risk_score": max((f.risk_score for f in findings), default=0),
        "severity_counts": dict(Counter(f.severity for f in findings)),
    }


def render_markdown(findings: list[DetectionFinding]) -> str:
    m = metrics(findings)
    lines = [
        "# Sysmon Detection Assessment",
        "",
        "## Executive Summary",
        f"- Total findings: {m['total_findings']}",
        f"- Critical/High findings: {m['critical_high']}",
        f"- Hosts affected: {m['hosts']}",
        f"- Highest risk score: {m['highest_risk_score']}/100",
        "",
        "> ATT&CK mappings provide investigation context; a mapping is not proof of compromise.",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("No findings were generated from the supplied telemetry.")
    for f in findings:
        lines.extend([
            "",
            f"### {f.title}",
            f"- Finding ID: `{f.finding_id}`",
            f"- Host: `{f.host}`",
            f"- Severity: **{f.severity}**",
            f"- Risk score: **{f.risk_score}/100**",
            f"- Confidence: **{f.confidence}%**",
            f"- ATT&CK: {', '.join(f.mitre_techniques)}",
            f"- Evidence: {', '.join(f.evidence_ids)}",
            f"- Rationale: {f.rationale}",
            f"- Remediation: {f.remediation}",
            f"- Validation: {f.validation}",
        ])
    return "\n".join(lines) + "\n"
