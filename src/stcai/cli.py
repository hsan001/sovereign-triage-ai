from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from stcai.pipeline import SovereignTriagePipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stcai",
        description="S-TCAI: Sovereign-Triage & Compliance AI (DESC ISR v2.0 & UAE NESA IAS)",
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Path to input telemetry file (Sysmon JSON array or Linux auditd log)",
    )
    parser.add_argument(
        "--source-type",
        "-s",
        choices=["sysmon", "auditd"],
        required=True,
        help="Telemetry format: 'sysmon' (JSON) or 'auditd' (multi-line log)",
    )
    parser.add_argument(
        "--criticality",
        "-c",
        choices=["low", "standard", "high", "critical_sovereign"],
        default="critical_sovereign",
        help="Target host asset criticality for DESC ISR SLA calculation",
    )
    parser.add_argument(
        "--output-md",
        "-o",
        default=None,
        help="Optional path to write the generated Executive Markdown Dossier",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1

    pipeline = SovereignTriagePipeline()
    if args.source_type == "sysmon":
        records = json.loads(input_path.read_text(encoding="utf-8"))
        if isinstance(records, dict):
            records = [records]
        result = pipeline.run_sysmon_json_records(
            records,
            asset_criticality=args.criticality,
        )
    else:
        lines = input_path.read_text(encoding="utf-8").splitlines()
        result = pipeline.run_auditd_lines(
            lines,
            asset_criticality=args.criticality,
        )

    dossier_md = result.to_executive_markdown()
    if args.output_md:
        out_path = Path(args.output_md)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(dossier_md, encoding="utf-8")
        print(f"[S-TCAI] Dossier written to {out_path}")
    else:
        print(dossier_md)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
