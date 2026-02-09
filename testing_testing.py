# testing_testing.py (developer harness - Phase 4 verification)

import socket
import json
from datetime import datetime, timezone

from Core_Framework import DiscoveryContext, DiscoveryOrchestrator
from Network_Discovery_Domain import NetworkDiscoveryModule

# NEW: import M3 reporting functions
from Output_Reporting import generate_markdown_report, serialize_run_to_json


def main() -> None:
    # Update target as needed for your lab
    target_ip = "192.168.145.129"

    ctx = DiscoveryContext(
        target=target_ip,
        run_started_at=datetime.now(timezone.utc),
        source_host=socket.gethostname(),
        assumptions=[
            "No credentials",
            "Agentless execution",
            "Non-exploitative discovery",
        ],
        run_id="dev-harness-run",
    )

    network = NetworkDiscoveryModule(ctx)
    orchestrator = DiscoveryOrchestrator([network])

    run = orchestrator.run(ctx)

    # Existing: print findings/events
    print("=== FINDINGS ===")
    for f in run.findings:
        print(f.to_dict())

    print("=== EVENTS ===")
    for e in run.events:
        print(e.to_dict())

    # NEW: Generate Markdown report (human-readable)
    report_md = generate_markdown_report(run)

    print("\n=== MARKDOWN REPORT (PREVIEW) ===\n")
    print(report_md)

    # NEW: Persist artifacts (optional but useful)
    with open("network_report.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    with open("run_results.json", "w", encoding="utf-8") as f:
        json.dump(serialize_run_to_json(run), f, indent=2)

    print("\nSaved: network_report.md, run_results.json")


if __name__ == "__main__":
    main()
