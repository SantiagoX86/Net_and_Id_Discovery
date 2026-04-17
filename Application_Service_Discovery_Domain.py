# ---------------------------------------------------------------------
# Application_Service_Discovery_Domain.py
#
# Milestone: M7 – Application / Service Discovery Domain
#
# This module implements a discovery-only producer that:
# - Performs connect-only TCP exposure checks on an approved bounded port set
# - Produces direct-observation findings only
# - Uses a producer-owned governed evidence field: application_service_hint
# - Performs NO inference, NO response parsing, and NO protocol negotiation
# ---------------------------------------------------------------------

from __future__ import annotations  # Enables forward-reference-friendly type hint behavior

from datetime import datetime, timezone  # Used to generate UTC-normalized timestamps
from typing import Dict, List, Tuple  # Used for explicit structured type contracts

import socket  # Used only for standard OS-level TCP connection establishment

# Import the frozen core framework contracts
from Core_Framework import DiscoveryContext, DiscoveryFinding, DiscoveryModule


def _utc_now() -> datetime:
    """
    Return an aware UTC datetime.

    This helper ensures all emitted findings use UTC-normalized timestamps
    consistent with the project-wide evidence contract.
    """
    return datetime.now(timezone.utc)


def _tcp_connect(host: str, port: int, timeout_s: float) -> Tuple[bool, str | None]:
    """
    Perform a minimal TCP connect-only check.

    Returns:
    - (True, None) when the TCP connection is successfully established
    - (False, <error type name>) when the connection is not successfully established

    Guardrails:
    - No payload is sent
    - No socket reads are performed
    - No protocol negotiation is attempted
    - No application-layer interaction occurs
    """
    try:
        # Use the standard OS socket API to perform a single bounded TCP connect.
        # The socket is closed immediately when the context manager exits.
        with socket.create_connection((host, port), timeout=timeout_s):
            return True, None

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        # Return a controlled non-success result without raising an exception.
        # The calling domain decides whether a non-success should produce a finding.
        return False, type(e).__name__


class ApplicationServiceDiscoveryDomain(DiscoveryModule):
    """
    Application / Service Discovery Domain (M7).

    Responsibilities:
    - Probe only the approved application/service port set
    - Emit only direct-observation findings for successful connect-only exposure
    - Preserve deterministic execution order and governed evidence structure

    Non-responsibilities:
    - No inference
    - No upstream finding consumption for meaning assignment
    - No HTTP requests, TLS handshakes, banner grabbing, or metadata extraction
    """

    # Domain name used in all findings emitted by this module
    name: str = "application_service"

    def __init__(self, context: DiscoveryContext, *, timeout_s: float = 1.0) -> None:
        """
        Initialize the domain with the shared DiscoveryContext and a fixed timeout.

        Parameters:
        - context: shared immutable execution context
        - timeout_s: bounded static timeout for all TCP connection attempts

        This constructor defines only local, deterministic configuration.
        """
        # Initialize the shared base module contract
        super().__init__(context)

        # Store the fixed timeout used for all application/service probes
        self.timeout_s = timeout_s

        # Define the approved bounded port-to-classification mapping.
        # This mapping is static, deterministic, and producer-owned.
        self.application_service_ports: Dict[int, str] = {
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }

        # Define the fixed deterministic probe order for this domain.
        # This ordering must not vary at runtime.
        self._probe_order: List[int] = [80, 443, 8080, 8443]

    def execute(
        self,
        prior_findings: tuple[DiscoveryFinding, ...] = (),
    ) -> List[DiscoveryFinding]:
        """
        Execute bounded application/service exposure discovery.

        Inputs:
        - prior_findings: accepted only because it is part of the shared module contract

        Output:
        - List of new DiscoveryFinding objects for successful application/service exposure only

        Important behavior:
        - This domain does NOT consume prior_findings
        - Only successful TCP connect-only observations generate findings
        - Closed, refused, filtered, timeout, or other non-success outcomes generate no finding
        """
        # Initialize a local findings list for this execution.
        # No persistent mutable state is carried across runs.
        findings: List[DiscoveryFinding] = []

        # Retrieve the target from the shared immutable context.
        target = getattr(self.context, "target", None)

        # If no target is available, return no findings.
        # This preserves safe failure behavior without raising.
        if not target:
            return findings

        # Iterate through the approved application/service ports in strict fixed order.
        for port in self._probe_order:
            # Resolve the producer-owned deterministic classification value
            # from the approved static port mapping.
            application_service_hint = self.application_service_ports[port]

            # Perform a single bounded connect-only TCP check.
            # No protocol interaction occurs beyond connection establishment.
            is_open, _err = _tcp_connect(target, port, self.timeout_s)

            # Per the approved minimal output model for this domain,
            # only successful observations generate findings.
            # All non-success outcomes produce no finding.
            if not is_open:
                continue

            # Define controlled explanatory note text by port.
            # These notes clarify what was NOT done and reinforce guardrails.
            note_map = {
                80: "Connectivity-only signal; no HTTP request, response read, or metadata extraction performed.",
                443: "Connectivity-only signal; no TLS handshake, response read, or metadata extraction performed.",
                8080: "Connectivity-only signal; no HTTP request, response read, or metadata extraction performed.",
                8443: "Connectivity-only signal; no TLS handshake, response read, or metadata extraction performed.",
            }

            # Construct and append the governed positive finding for this observed exposure.
            findings.append(
                self._make_finding(
                    category="application_service_exposed",
                    target=f"{target}:{port}",
                    evidence={
                        "method": "tcp_connect",
                        "port": port,
                        "application_service_hint": application_service_hint,
                        "note": note_map[port],
                        "timeout_s": self.timeout_s,
                    },
                    confidence=0.70,
                )
            )

        # Return all findings generated by this discovery domain.
        return findings

    def _make_finding(
        self,
        *,
        category: str,
        target: str,
        evidence: Dict,
        confidence: float,
    ) -> DiscoveryFinding:
        """
        Construct a contract-native DiscoveryFinding.

        This helper centralizes finding creation so the emitted structure remains
        uniform and easy to audit.
        """
        return DiscoveryFinding(
            domain=self.name,  # Authoritative producing domain name
            category=category,  # Approved category for this domain
            target=target,  # Port-qualified target for the observed exposure
            evidence=evidence,  # Governed direct-observation evidence only
            confidence=confidence,  # Static deterministic confidence value
            observed_at=_utc_now(),  # UTC-normalized timestamp
        )