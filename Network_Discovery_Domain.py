"""
WAUIG Bank - Enterprise Security Discovery Orchestration Framework
Network Discovery Domain (Milestone M2) - v1 (Fully Annotated)

Purpose:
- Provide safe, agentless, non-exploitative network visibility against a target.
- Operate from a low-privilege vantage point (no raw sockets).
- Emit normalized findings compatible with the core framework contracts.

What this module does:
- Host reachability (ICMP echo via system ping)
- TCP connect-based port discovery across a predefined port set
- Heuristic service mapping (based on port number)

What this module does NOT do (by requirement):
- No exploitation, fuzzing, brute force, or authentication attempts
- No raw packet crafting (no SYN scans)
- No target state modification

Dependencies:
- This module depends on the core framework contracts (M1):
  - DiscoveryContext
  - DiscoveryFinding
  - DiscoveryModule

NOTE:
- This is an implementation artifact for Phase 4 (Construct).
- Output formatting/serialization is handled in M3.
"""

# =========================
# Imports
# =========================

# socket is used for TCP connect probing using standard OS APIs.
import socket

# subprocess is used to call system utilities (ping) in a controlled way.
import subprocess

# datetime/timezone provides consistent UTC timestamps.
from datetime import datetime, timezone

# typing provides explicit contracts and readability.
from typing import Dict, List, Tuple

# Import core framework primitives.
# In M5 we will refactor this into a proper package structure.
from Core_Framework import DiscoveryContext, DiscoveryFinding, DiscoveryModule


# =========================
# Configuration (Domain-Local)
# =========================
# In enterprise codebases, these will typically move to a central config
# layer (planned for later milestones), but it is acceptable to keep
# defaults close to the domain for early implementation.


def default_port_map() -> Dict[int, str]:
    """Return the default enterprise-relevant port -> service hint mapping."""

    # These are common attack surface and administrative exposure points.
    # They are intentionally limited to reduce scan footprint.
    return {
        21: "FTP",
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        88: "Kerberos",
        135: "RPC",
        139: "SMB",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM",
        5986: "WinRM-HTTPS",
    }


# =========================
# Network Discovery Domain
# =========================


class NetworkDiscoveryModule(DiscoveryModule):
    """
    Implements the Network Discovery domain.

    Architectural fit:
    - This class is a pluggable discovery domain (ADD: Discovery Domain Layer)
    - It inherits the standardized interface from DiscoveryModule (M1)
    - It returns normalized DiscoveryFinding objects for orchestration/output
    """

    # Domain identifier used in findings.
    name = "network"

    def __init__(
        self,
        context: DiscoveryContext,
        port_map: Dict[int, str] | None = None,
        tcp_timeout_s: float = 1.0,
        ping_timeout_s: int = 1,
    ):
        """
        Initialize the network domain with controlled defaults.

        Why these parameters exist:
        - port_map: allows safe configurability without changing code
        - tcp_timeout_s: bounds execution time and avoids hanging
        - ping_timeout_s: bounds ICMP waiting time

        Note:
        - These are technical constraints aligned with TRD performance and
          safety requirements.
        """

        # Initialize the base class (stores context).
        super().__init__(context)

        # Use provided port map or default enterprise set.
        self.port_map = port_map if port_map is not None else default_port_map()

        # Store timeouts to ensure bounded execution.
        self.tcp_timeout_s = tcp_timeout_s
        self.ping_timeout_s = ping_timeout_s

    def execute(self) -> List[DiscoveryFinding]:
        """
        Execute network discovery tasks and return normalized findings.

        Contract:
        - Must return List[DiscoveryFinding]
        - Must not raise unhandled exceptions (best effort)
        """

        # Collect findings locally and return them.
        # We avoid storing state on the module beyond this function,
        # keeping execution predictable.
        findings: List[DiscoveryFinding] = []

        # 1) Determine host reachability.
        findings.extend(self._discover_host_presence())

        # 2) Probe enterprise-relevant ports using TCP connect.
        findings.extend(self._discover_open_ports())

        # Return all findings for the orchestrator to aggregate.
        return findings

    # -------------------------
    # Subsection: Host Presence
    # -------------------------

    def _discover_host_presence(self) -> List[DiscoveryFinding]:
        """Assess basic host presence using ICMP echo via system ping."""

        # Default to non-responsive unless proven otherwise.
        alive = False

        try:
            # Use the system 'ping' command.
            # -c 1 => send 1 packet
            # -W N => wait up to N seconds for a reply
            # This avoids raw packet operations and stays within a safe model.
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(self.ping_timeout_s), self.context.target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Return code 0 implies a reply was received.
            alive = result.returncode == 0

        except Exception as exc:
            # We do not raise; instead we produce a finding indicating
            # the method failed, which supports auditability.
            return [
                DiscoveryFinding(
                    domain=self.name,
                    category="host_presence",
                    target=self.context.target,
                    evidence={
                        "method": "icmp_echo_ping",
                        "reachable": False,
                        "error": str(exc),
                    },
                    confidence=0.4,
                    observed_at=datetime.now(timezone.utc),
                )
            ]

        # Produce the primary host_presence finding.
        return [
            DiscoveryFinding(
                domain=self.name,
                category="host_presence",
                target=self.context.target,
                evidence={
                    "method": "icmp_echo_ping",
                    "reachable": alive,
                    "timeout_s": self.ping_timeout_s,
                },
                # Confidence is higher on positive reachability.
                confidence=0.9 if alive else 0.6,
                observed_at=datetime.now(timezone.utc),
            )
        ]

    # -------------------------
    # Subsection: Open Port Scan
    # -------------------------

    def _discover_open_ports(self) -> List[DiscoveryFinding]:
        """Probe a predefined set of ports using TCP connect."""

        findings: List[DiscoveryFinding] = []

        # Iterate in sorted order to keep results deterministic.
        for port in sorted(self.port_map.keys()):
            # Attempt a standard TCP connection.
            open_state, error = self._tcp_connect_probe(self.context.target, port)

            # Only report confirmed open ports as positive exposure.
            if open_state:
                findings.append(
                    DiscoveryFinding(
                        domain=self.name,
                        category="open_port",
                        target=f"{self.context.target}:{port}",
                        evidence={
                            "method": "tcp_connect",
                            "port": port,
                            "service_hint": self.port_map.get(port, "unknown"),
                            "timeout_s": self.tcp_timeout_s,
                        },
                        confidence=0.85,
                        observed_at=datetime.now(timezone.utc),
                    )
                )

            # If the probe failed due to an error, we do NOT treat it as open.
            # We also avoid emitting a finding for every closed port to prevent
            # noisy output. However, persistent errors can be operationally
            # meaningful, so we record a low-noise error finding when a
            # non-timeout error occurs.
            elif error is not None and error != "timeout":
                findings.append(
                    DiscoveryFinding(
                        domain=self.name,
                        category="port_probe_error",
                        target=f"{self.context.target}:{port}",
                        evidence={
                            "method": "tcp_connect",
                            "port": port,
                            "service_hint": self.port_map.get(port, "unknown"),
                            "timeout_s": self.tcp_timeout_s,
                            "error": error,
                        },
                        confidence=0.5,
                        observed_at=datetime.now(timezone.utc),
                    )
                )

        return findings

    # -------------------------
    # Helper: TCP Connect Probe
    # -------------------------

    def _tcp_connect_probe(self, host: str, port: int) -> Tuple[bool, str | None]:
        """
        Attempt a TCP connection to determine whether a port is open.

        Returns:
        - (True, None) if connection succeeded
        - (False, "timeout") if timed out
        - (False, "<error>") for other socket errors

        Why this is safe:
        - Uses OS networking APIs (no raw packets)
        - Mimics what a benign client would do
        - Bounded by timeout
        """

        try:
            # create_connection performs DNS resolution if needed and attempts
            # a TCP handshake within the given timeout.
            with socket.create_connection((host, port), timeout=self.tcp_timeout_s):
                return True, None

        except socket.timeout:
            # Timeout implies no connection within allowed time.
            return False, "timeout"

        except OSError as exc:
            # OSError covers connection refused, unreachable, etc.
            # We expose a short error string for auditability.
            return False, exc.__class__.__name__

        except Exception as exc:
            # Catch-all for unexpected errors to avoid crashing the domain.
            return False, exc.__class__.__name__
