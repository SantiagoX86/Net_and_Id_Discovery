"""
cli.py

Milestone: M5 – Entry / Control Layer (CLI)

Design intent:
- Thin control-layer entry point only
- No discovery business logic
- No authentication, negotiation, or exploitative behavior
- Deterministic execution across all domains
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import json
from datetime import datetime, timezone

from Core_Framework import DiscoveryContext, DiscoveryOrchestrator
from Network_Discovery_Domain import NetworkDiscoveryModule
from Identity_Discovery_Domain import IdentityDiscoveryDomain

from Output_Reporting import generate_markdown_report, serialize_run_to_json

def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser for controlled discovery execution.
    """
    parser = argparse.ArgumentParser(
        description="WAUIG Bank - Enterprise Security Discovery Orchestration Framework"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname for discovery execution.",
    )

    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for optional output artifacts. Default: current directory.",
    )

    parser.add_argument(
        "--no-files",
        action="store_true",
        help="Disable file artifact generation and print results to console only.",
    )

    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run identifier override.",
    )

    return parser

def validate_target(target: str) -> str:
    """
    Validate target as either IPv4 address or hostname.
    Returns normalized target or raises ValueError.
    """

    try:
        ipaddress.IPv4Address(target)
        return target
    except ipaddress.AddressValueError:
        pass

    hostname_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )

    if hostname_regex.match(target):
        return target

    raise ValueError(f"Invalid target: {target}")


def main() -> None:
    """
    CLI entry point.
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
    except ValueError as e:
        print(f"[ERROR] {e}")
        raise SystemExit(1)

    ctx = DiscoveryContext(
        target=target,
        run_started_at=datetime.now(timezone.utc),
        source_host=socket.gethostname(),
        assumptions=[
            "No credentials",
            "Agentless execution",
            "Non-exploitative discovery",
        ],
        run_id=args.run_id,
    )
    network = NetworkDiscoveryModule(ctx)
    identity = IdentityDiscoveryDomain(ctx)

    orchestrator = DiscoveryOrchestrator([
        network,
        identity,
    ])
    run = orchestrator.run(ctx)

    print("=== FINDINGS (JSON) ===")
    for f in run.findings:
        print(f.to_dict())

    print("=== EVENTS (JSON) ===")
    for e in run.events:
        print(e.to_dict())

    report_md = generate_markdown_report(run)
    run_json = serialize_run_to_json(run)

    md_output_path = f"{args.output_dir}/discovery_report.md"
    json_output_path = f"{args.output_dir}/discovery_run.json"

    if not args.no_files:
        with open(md_output_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(run_json, f, indent=2)

    print("=== MARKDOWN REPORT ===")
    print(report_md)

if __name__ == "__main__":
    main()