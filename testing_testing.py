# testing_testing.py (developer harness - Phase 4 verification)

import socket
import json
from datetime import datetime, timezone

from Core_Framework import DiscoveryContext, DiscoveryOrchestrator
from Network_Discovery_Domain import NetworkDiscoveryModule
from Identity_Discovery_Domain import IdentityDiscoveryDomain

# NEW: import M3 reporting functions
from Output_Reporting import generate_markdown_report, serialize_run_to_json

# class FailingModule:
#     def __init__(self, context):
#         self.context = context
#
#     def execute(self):
#         raise RuntimeError("Intentional failure for resilience testing")

def main() -> None:
    # Update target as needed for your lab
    target_ip = input("What is the IP of the device being scanned? ")

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
    identity = IdentityDiscoveryDomain(ctx)

    orchestrator = DiscoveryOrchestrator([
        network,
        identity
    ])

    run = orchestrator.run(ctx)

    # Existing: print findings/events
    print("=== FINDINGS (JSON) ===")
    for f in run.findings:
        print(json.dumps(f.to_dict(), indent=2, sort_keys=True))

    print("=== EVENTS (JSON) ===")
    for e in run.events:
        print(json.dumps(e.to_dict(), indent=2, sort_keys=True))

    # NEW: Generate Markdown report (human-readable)
    report_md = generate_markdown_report(run)

    print("\n=== MARKDOWN REPORT (PREVIEW) ===\n")
    print(report_md)

    # NEW: Persist artifacts (optional but useful)
    with open(f"network_report_{str(ctx.run_started_at)[:-10]}.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    with open(f"run_results_{str(ctx.run_started_at)[:-10]}.json", "w", encoding="utf-8") as f:
        json.dump(serialize_run_to_json(run), f, indent=2)

    print("\nSaved: network_report.md, run_results.json")


if __name__ == "__main__":
    main()
