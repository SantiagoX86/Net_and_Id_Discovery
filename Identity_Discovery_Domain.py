"""
Identity_Discovery_Domain.py

Milestone: M4 – Identity Discovery Domain (Phase B: controlled exposure probes)

Design intent:
- Agentless, non-exploitative identity exposure discovery.
- Integrates with the existing Core Framework module contract.
- Minimal interaction only (TCP connect signals). No negotiation, no auth, no exploitation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Tuple

import socket

from Core_Framework import DiscoveryContext, DiscoveryFinding, DiscoveryModule


def _utc_now() -> datetime:
    """Return an aware UTC datetime (contract-native)."""
    return datetime.now(timezone.utc)


def _tcp_connect(host: str, port: int, timeout_s: float) -> Tuple[bool, str | None]:
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


class IdentityDiscoveryDomain(DiscoveryModule):
    """
    Identity Discovery Domain (M4).

    Contract:
    - Implements execute() -> List[DiscoveryFinding]
    - No credential use, no authentication attempts, no exploitation
    """

    name: str = "identity"

    def __init__(self, context: DiscoveryContext, *, timeout_s: float = 1.0) -> None:
        super().__init__(context)
        self.timeout_s = timeout_s

        # Identity-adjacent ports (deterministic ordering enforced at probe-time).
        self.identity_service_ports: Dict[int, str] = {
            88: "Kerberos",
            135: "RPC",
            389: "LDAP",
            636: "LDAPS",
            445: "SMB",
            5985: "WinRM",
            5986: "WinRM-HTTPS",
        }

        # M4 validated probes (explicit order; deterministic).
        self._probe_order: List[int] = [445, 5985, 135, 389, 636]

    def execute(self) -> List[DiscoveryFinding]:
        findings: List[DiscoveryFinding] = []

        target = getattr(self.context, "target", None)
        if not target:
            return findings

        for port in self._probe_order:
            service_hint = self.identity_service_ports.get(port, "unknown")
            is_open, err = _tcp_connect(target, port, self.timeout_s)

            if is_open:
                note_map = {
                    445: "Connectivity-only signal; no SMB negotiation or authentication performed.",
                    5985: "Connectivity-only signal; no WinRM HTTP request or authentication performed.",
                    135: "Connectivity-only signal; no RPC endpoint enumeration performed (no EPM queries).",
                    389: "Connectivity-only signal; no LDAP bind, negotiation, or authentication performed.",
                    636: "Connectivity-only signal; no TLS negotiation or LDAP bind performed.",
                }
                note = note_map.get(
                    port,
                    "Connectivity-only signal; no protocol negotiation or authentication performed.",
                )

                findings.append(
                    self._make_finding(
                        category="identity_service_exposed",
                        target=f"{target}:{port}",
                        evidence={
                            "method": "tcp_connect",
                            "port": port,
                            "service_hint": service_hint,
                            "note": note,
                            "timeout_s": self.timeout_s,
                        },
                        confidence=0.7,
                    )
                )
            else:
                # Optional: only record anomalies (not normal closed/filtered states).
                if err == "OSError":
                    findings.append(
                        self._make_finding(
                            category="identity_probe_error",
                            target=f"{target}:{port}",
                            evidence={
                                "method": "tcp_connect",
                                "port": port,
                                "service_hint": service_hint,
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
        evidence: Dict,
        confidence: float,
    ) -> DiscoveryFinding:
        """Construct a contract-native DiscoveryFinding."""
        return DiscoveryFinding(
            domain=self.name,
            category=category,
            target=target,
            evidence=evidence,
            confidence=confidence,
            observed_at=_utc_now(),
        )