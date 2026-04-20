# ---------------------------------------------------------------------
# Telemetry_Logging_Exposure_Discovery_Domain.py
#
# Milestone: M7 – Telemetry / Logging Exposure Discovery Domain
#
# Design intent:
# - Discovery-only producer for bounded telemetry/logging exposure
# - Connect-only TCP interaction on an approved port set
# - No inference, no response parsing, and no protocol negotiation
# - Deterministic execution and governed evidence output
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


class TelemetryLoggingExposureDiscoveryDomain(DiscoveryModule):
    """
    Telemetry / Logging Exposure Discovery Domain (M7).

    Responsibilities:
    - Probe only the approved telemetry/logging port set
    - Emit only direct-observation findings for successful connect-only exposure
    - Preserve deterministic execution order and governed evidence structure

    Non-responsibilities:
    - No inference
    - No upstream finding consumption for meaning assignment
    - No syslog/GELF/OTLP/HTTP payload transmission
    - No TLS handshakes, banner grabbing, response reads, or metadata extraction
    """

    # Domain name used in all findings emitted by this module
    name: str = "telemetry_logging"

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

        # Store the fixed timeout used for all telemetry/logging probes
        self.timeout_s = timeout_s

        # Define the approved bounded port-to-classification mapping.
        # This mapping is static, deterministic, and producer-owned.
        self.telemetry_logging_ports: Dict[int, str] = {
            514: "SYSLOG",
            6514: "SYSLOG-TLS",
            12201: "GELF",
            24224: "LOG-FORWARD",
            4317: "OTLP-GRPC",
            4318: "OTLP-HTTP",
        }

        # Define the fixed deterministic probe order for this domain.
        # This ordering must not vary at runtime.
        self._probe_order: List[int] = [514, 4317, 4318, 6514, 12201, 24224]

    def execute(
        self,
        prior_findings: tuple[DiscoveryFinding, ...] = (),
    ) -> List[DiscoveryFinding]:
        """
        Execute bounded telemetry/logging exposure discovery.

        Inputs:
        - prior_findings: accepted only because it is part of the shared module contract

        Output:
        - List of new DiscoveryFinding objects for successful telemetry/logging exposure only

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

        # Define controlled explanatory note text by port.
        # These notes clarify what was NOT done and reinforce guardrails.
        note_map = {
            514: "Connectivity-only signal; no syslog message transmission, response read, or metadata extraction performed.",
            6514: "Connectivity-only signal; no TLS handshake, syslog message transmission, response read, or metadata extraction performed.",
            12201: "Connectivity-only signal; no GELF payload transmission, response read, or metadata extraction performed.",
            24224: "Connectivity-only signal; no log-forward payload transmission, response read, or metadata extraction performed.",
            4317: "Connectivity-only signal; no OTLP gRPC payload transmission, response read, or metadata extraction performed.",
            4318: "Connectivity-only signal; no OTLP HTTP request, response read, or metadata extraction performed.",
        }

        # Iterate through the approved telemetry/logging ports in strict fixed order.
        for port in self._probe_order:
            # Resolve the producer-owned deterministic classification value
            # from the approved static port mapping.
            telemetry_logging_hint = self.telemetry_logging_ports[port]

            # Perform a single bounded connect-only TCP check.
            # No protocol interaction occurs beyond connection establishment.
            is_open, _err = _tcp_connect(target, port, self.timeout_s)

            # Per the approved minimal output model for this domain,
            # only successful observations generate findings.
            # All non-success outcomes produce no finding.
            if not is_open:
                continue

            # Construct and append the governed positive finding for this observed exposure.
            findings.append(
                self._make_finding(
                    category="telemetry_logging_exposed",
                    target=f"{target}:{port}",
                    evidence={
                        "method": "tcp_connect",
                        "port": port,
                        "telemetry_logging_hint": telemetry_logging_hint,
                        "note": note_map[port],
                        "timeout_s": self.timeout_s,
                    },
                    confidence=0.70,
                )
            )

        # Return all positive direct-observation findings for this module execution.
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

        This helper centralizes finding creation so emitted records remain
        consistent across all positive telemetry/logging observations.
        """
        # Build and return the normalized governed finding object.
        return DiscoveryFinding(
            domain=self.name,
            category=category,
            target=target,
            evidence=evidence,
            confidence=confidence,
            observed_at=_utc_now(),
        )