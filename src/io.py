from __future__ import annotations

import json
from pathlib import Path

from .models import SysmonEvent, parse_utc


def load_events(path: str | Path) -> list[SysmonEvent]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")

    required = {"event_id", "record_id", "timestamp", "host", "user"}
    seen: set[str] = set()
    events: list[SysmonEvent] = []
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("every event must be an object")
        missing = required - row.keys()
        if missing:
            raise ValueError(f"missing required fields: {sorted(missing)}")
        rid = str(row["record_id"])
        if rid in seen:
            raise ValueError(f"duplicate record_id: {rid}")
        seen.add(rid)
        events.append(SysmonEvent(
            event_id=int(row["event_id"]),
            record_id=rid,
            timestamp=parse_utc(str(row["timestamp"])),
            host=str(row["host"]),
            user=str(row["user"]),
            image=str(row.get("image", "")),
            parent_image=str(row.get("parent_image", "")),
            command_line=str(row.get("command_line", "")),
            destination_ip=str(row.get("destination_ip", "")),
            destination_port=(int(row["destination_port"]) if row.get("destination_port") is not None else None),
            target_object=str(row.get("target_object", "")),
            target_filename=str(row.get("target_filename", "")),
            signed=row.get("signed"),
            signature_status=str(row.get("signature_status", "")),
            hashes=dict(row.get("hashes", {})),
            extra=dict(row.get("extra", {})),
        ))
    return events
