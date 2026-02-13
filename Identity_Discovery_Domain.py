"""
Identity_Discovery_Domain.py

Milestone: M4 – Identity Discovery Domain (Phase A: scaffolding only)

Design intent:
- Agentless, non-exploitative identity exposure discovery.
- Integrates with the existing Core Framework module contract.
- No functional discovery logic in this phase (structure-only).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import socket

def _utc_now_iso() -> str:
    """Return UTC timestamp in ISO8601 'Z' format (consistent with existing domains)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def _tcp_connect(host: str, port: int, timeout_s: float) -> tuple[bool, str | None]:
    """
    Minimal TCP connect check.
    Returns (is_open, error_string). Never sends protocol data.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True, None
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        # timeout -> filtered/unreachable; refused -> closed; OSError -> routing/etc
        return False, type(e).__name__

class IdentityDiscoveryDomain:
    """
    Identity Discovery Domain (scaffold).

    Core Framework contract expectations (based on your orchestrator):
    - Module has a `.context` attribute
    - Module implements `execute(self)` with no parameters
    - Module returns a list of finding dictionaries
    """

    name: str = "IdentityDiscoveryDomain"

    def __init__(self, context: Any, *, timeout_s: float = 1.0) -> None:
        # Orchestrator-owned shared context for this run.
        self.context = context

        # Timeout used later for controlled, low-noise protocol checks.
        self.timeout_s = timeout_s

        # Placeholder: identity-adjacent service ports we may evaluate in later phases.
        # (No network interaction is performed in Phase A.)
        self.identity_service_ports: Dict[int, str] = {
            88: "Kerberos",
            389: "LDAP",
            636: "LDAPS",
            445: "SMB",
            5985: "WinRM",
            5986: "WinRM-HTTPS",
        }

    def execute(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        target = getattr(self.context, "target", None)
        if not target:
            # No target means we cannot probe; keep behavior safe and deterministic.
            return findings

        # Phase B1: SMB exposure signal (TCP/445) — connect only, no negotiation/auth.
        is_open, err = _tcp_connect(target, 445, self.timeout_s)

        if is_open:
            findings.append(
                self._make_finding(
                    category="identity_service_exposed",
                    target=f"{target}:445",
                    evidence={
                        "method": "tcp_connect",
                        "port": 445,
                        "service_hint": "SMB",
                        "note": "Connectivity-only signal; no SMB negotiation or authentication performed.",
                        "timeout_s": self.timeout_s,
                    },
                    confidence=0.7,
                )
            )
        else:
            # Optional: only record anomalies, not normal closed/filtered states.
            # Treat OSError as potentially interesting (routing/interface/firewall issues).
            if err == "OSError":
                findings.append(
                    self._make_finding(
                        category="identity_probe_error",
                        target=f"{target}:445",
                        evidence={
                            "method": "tcp_connect",
                            "port": 445,
                            "service_hint": "SMB",
                            "error": err,
                            "timeout_s": self.timeout_s,
                        },
                        confidence=0.5,
                    )
                )

        return findings


    def _make_finding(
        self,
        *,
        category: str,
        target: str,
        evidence: Dict[str, Any],
        confidence: float,
    ) -> Dict[str, Any]:
        """
        Helper to keep finding shape consistent across domains.
        (Not used in Phase A, but included now to avoid refactoring later.)
        """
        return {
            "domain": "identity",
            "category": category,
            "target": target,
            "evidence": evidence,
            "confidence": confidence,
            "observed_at": _utc_now_iso(),
        }
