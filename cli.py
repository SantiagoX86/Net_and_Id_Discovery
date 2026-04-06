# ---------------------------------------------------------------------
# cli.py
#
# Milestone: M5 – Entry / Control Layer (CLI)
# Updated for M6 registration only
#
# Design intent:
# - Thin control-layer entry point only
# - No discovery business logic
# - No authentication, negotiation, or exploitative behavior
# - Deterministic execution across all domains
# - M6 addition is limited to module registration only
# ---------------------------------------------------------------------

from __future__ import annotations  # Enables forward-reference-friendly type hint behavior

import argparse  # Used to parse controlled command-line arguments
import ipaddress  # Used to validate IPv4 input safely
import re  # Used to validate hostnames with a regex
import socket  # Used only to retrieve the local source hostname (not for probing here)
import json  # Used to write JSON output artifacts
from datetime import datetime, timezone  # Used to create UTC-normalized run timestamps

# Import core orchestration primitives from the frozen core framework
from Core_Framework import DiscoveryContext, DiscoveryOrchestrator

# Import the existing validated discovery domains
from Network_Discovery_Domain import NetworkDiscoveryModule
from Identity_Discovery_Domain import IdentityDiscoveryDomain

# Import the new M6 Host Configuration inference-only domain
# This is the only new import required for M6 registration
from Host_Config_Discovery_Domain import HostConfigDiscoveryDomain

# Import the existing validated output/reporting functions
from Output_Reporting import generate_markdown_report, serialize_run_to_json


def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser for controlled discovery execution.

    This function defines the authoritative control-layer interface.
    It accepts only approved execution parameters and does not perform
    any discovery logic itself.
    """

    # Create the top-level parser object with a descriptive help banner
    parser = argparse.ArgumentParser(
        description="WAUIG Bank - Enterprise Security Discovery Orchestration Framework"
    )

    # Add the required target parameter
    # This is the authoritative execution input for the framework
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname for discovery execution.",
    )

    # Add an optional output directory parameter
    # This controls where Markdown/JSON artifacts are written if file output is enabled
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory for optional output artifacts. Default: current directory.",
    )

    # Add an optional switch to suppress file creation
    # This is useful for quick console-only validation runs
    parser.add_argument(
        "--no-files",
        action="store_true",
        help="Disable file artifact generation and print results to console only.",
    )

    # Add an optional run identifier override
    # This supports traceability across executions when needed
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run identifier override.",
    )

    # Return the fully built parser to the caller
    return parser


def validate_target(target: str) -> str:
    """
    Validate target as either IPv4 address or hostname.

    Returns:
    - normalized target string if valid

    Raises:
    - ValueError if the supplied target is invalid

    This preserves M5's control-layer responsibility for input validation
    without introducing any discovery behavior.
    """

    # First, attempt to validate the target as an IPv4 address
    try:
        ipaddress.IPv4Address(target)  # Will raise if the value is not a valid IPv4 address
        return target  # If valid, return it unchanged
    except ipaddress.AddressValueError:
        pass  # If not a valid IPv4 address, continue on to hostname validation

    # Define a conservative hostname validation regex
    # This enforces length and label formatting constraints
    hostname_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )

    # If the regex matches, treat the value as a valid hostname
    if hostname_regex.match(target):
        return target

    # If neither IPv4 nor hostname validation succeeds, raise a controlled error
    raise ValueError(f"Invalid target: {target}")


def main() -> None:
    """
    CLI entry point.

    Responsibilities:
    - Parse approved CLI arguments
    - Validate target input
    - Construct DiscoveryContext
    - Register and invoke orchestrated modules
    - Print and optionally persist results

    Non-responsibilities:
    - No discovery logic
    - No inference logic
    - No direct protocol interaction
    """

    # Build the parser that defines the allowed CLI interface
    parser = build_parser()

    # Parse the actual command-line arguments supplied by the operator
    args = parser.parse_args()

    # Validate the target input before doing anything else
    try:
        target = validate_target(args.target)
    except ValueError as e:
        # Print a controlled error message and exit cleanly with non-zero status
        print(f"[ERROR] {e}")
        raise SystemExit(1)

    # Construct the shared immutable execution context
    # This context is passed into every module
    ctx = DiscoveryContext(
        target=target,  # The validated target host/IP
        run_started_at=datetime.now(timezone.utc),  # UTC-aware execution start time
        source_host=socket.gethostname(),  # Local source host identifier
        assumptions=[
            "No credentials",  # Security constraint
            "Agentless execution",  # Architectural constraint
            "Non-exploitative discovery",  # Project safety constraint
        ],
        run_id=args.run_id,  # Optional operator-supplied trace ID
    )

    # Instantiate the Network Discovery domain
    # This remains the first discovery module in deterministic execution order
    network = NetworkDiscoveryModule(ctx)

    # Instantiate the Identity Discovery domain
    # This remains downstream of Network so it can run in the established sequence
    identity = IdentityDiscoveryDomain(ctx)

    # Instantiate the Host Configuration Discovery domain
    # This is the new M6 module and is inference-only
    # It must execute after Network and Identity so it can consume prior findings
    host_config = HostConfigDiscoveryDomain(ctx)

    # Build the orchestrator with modules in strict deterministic order
    # M6 is added only as a registration change; no control logic is altered
    orchestrator = DiscoveryOrchestrator([
        network,       # First: network findings
        identity,      # Second: identity findings
        host_config,   # Third: inference-only host configuration findings
    ])

    # Execute the orchestrated discovery run using the shared context
    run = orchestrator.run(ctx)

    # Print findings to console in JSON-like dictionary form
    print("=== FINDINGS (JSON) ===")
    for f in run.findings:
        print(f.to_dict())

    # Print orchestrator events to console in JSON-like dictionary form
    print("=== EVENTS (JSON) ===")
    for e in run.events:
        print(e.to_dict())

    # Generate the Markdown report from the run result
    report_md = generate_markdown_report(run)

    # Generate the structured JSON-serializable run object
    run_json = serialize_run_to_json(run)

    # Build the Markdown artifact output path
    md_output_path = f"{args.output_dir}/discovery_report.md"

    # Build the JSON artifact output path
    json_output_path = f"{args.output_dir}/discovery_run.json"

    # Only write files if the operator did not disable file output
    if not args.no_files:
        # Write the Markdown report artifact
        with open(md_output_path, "w", encoding="utf-8") as f:
            f.write(report_md)

        # Write the JSON run artifact
        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(run_json, f, indent=2)

    # Print the Markdown report to console for immediate operator review
    print("=== MARKDOWN REPORT ===")
    print(report_md)


# Standard Python module-entry guard
# Ensures main() runs only when this file is executed directly
if __name__ == "__main__":
    main()