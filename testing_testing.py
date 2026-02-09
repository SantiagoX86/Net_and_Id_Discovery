# test_run.py (temporary developer verification)

from Core_Framework import (
    DiscoveryContext,
    DiscoveryOrchestrator,
)
from Network_Discovery_Domain import NetworkDiscoveryModule
import socket
from datetime import datetime, timezone

ctx = DiscoveryContext(
    target="192.168.145.129",
    run_started_at=datetime.now(timezone.utc),
    source_host=socket.gethostname(),
    assumptions=[
        "No credentials",
        "Agentless execution",
        "Non-exploitative discovery",
    ],
)

network = NetworkDiscoveryModule(ctx)
orchestrator = DiscoveryOrchestrator([network])

result = orchestrator.run(ctx)

print("=== FINDINGS ===")
for f in result.findings:
    print(f.to_dict())

print("=== EVENTS ===")
for e in result.events:
    print(e.to_dict())
