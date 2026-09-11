from __future__ import annotations

import argparse
from pathlib import Path

from .detections import detect
from .io import load_events
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Sysmon telemetry and generate a defensive Markdown report.")
    parser.add_argument("input", help="Path to JSON Sysmon event array")
    parser.add_argument("--output", default="reports/generated-assessment.md", help="Markdown report path")
    args = parser.parse_args()

    events = load_events(args.input)
    findings = detect(events)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(findings), encoding="utf-8")
    print(f"events={len(events)} findings={len(findings)} report={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
