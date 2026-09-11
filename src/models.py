from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SUPPORTED_EVENT_IDS = {1, 3, 7, 8, 10, 11, 12, 13, 22, 23, 25}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class SysmonEvent:
    event_id: int
    record_id: str
    timestamp: datetime
    host: str
    user: str
    image: str = ""
    parent_image: str = ""
    command_line: str = ""
    destination_ip: str = ""
    destination_port: int | None = None
    target_object: str = ""
    target_filename: str = ""
    signed: bool | None = None
    signature_status: str = ""
    hashes: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event_id not in SUPPORTED_EVENT_IDS:
            raise ValueError(f"unsupported Sysmon event id: {self.event_id}")
        if not self.record_id.strip() or not self.host.strip():
            raise ValueError("record_id and host are required")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        if self.destination_port is not None and not 0 < self.destination_port <= 65535:
            raise ValueError("destination_port out of range")


@dataclass(frozen=True)
class DetectionFinding:
    finding_id: str
    title: str
    host: str
    severity: str
    confidence: int
    risk_score: int
    mitre_techniques: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    rationale: str
    remediation: str
    validation: str

    def __post_init__(self) -> None:
        if self.severity not in {"Low", "Medium", "High", "Critical"}:
            raise ValueError("invalid severity")
        if not 0 <= self.confidence <= 100 or not 0 <= self.risk_score <= 100:
            raise ValueError("confidence and risk_score must be 0-100")
        if not self.evidence_ids:
            raise ValueError("findings require evidence")
