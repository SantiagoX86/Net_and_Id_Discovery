# ---------------------------------------------------------------------
# Host_Config_Discovery_Domain.py
#
# Milestone: M6 – Host Configuration Discovery Domain (Inference-Only)
#
# This module implements an inference-only discovery domain that:
# - Consumes prior findings from the orchestrator (read-only)
# - Produces new DiscoveryFinding objects (append-only)
# - Performs NO network interaction
# - Enforces deterministic, rule-based execution
# ---------------------------------------------------------------------

from __future__ import annotations  # Enables forward references in type hints (Python <3.10 compatibility)

from datetime import datetime, timezone  # Used for generating UTC timestamps
from typing import Dict, List, Sequence, Tuple  # Type hinting for structured inputs/outputs

# Import core framework contracts (DO NOT MODIFY these modules per M1–M5 freeze)
from Core_Framework import DiscoveryContext, DiscoveryFinding, DiscoveryModule


def _utc_now() -> datetime:
    """
    Return an aware UTC datetime.
    This ensures all timestamps are normalized and deterministic across runs.
    """
    return datetime.now(timezone.utc)  # Always use UTC (no local timezone drift)


class HostConfigDiscoveryDomain(DiscoveryModule):
    """
    Host Configuration Discovery Domain (M6).

    Responsibilities:
    - Consume prior findings from Network + Identity domains
    - Apply deterministic inference rules
    - Emit new findings WITHOUT modifying upstream data
    """

    # Domain name used in all output findings
    name: str = "host_configuration"

    # ------------------------------------------------------------------
    # Fixed rule execution order (MANDATORY per specification)
    # This ensures deterministic behavior across all runs
    # ------------------------------------------------------------------
    _RULE_ORDER: Tuple[str, ...] = (
        "HC-RM-001",   # Remote Management Exposure (WinRM / WinRM-HTTPS)
        "HC-RM-002",   # Remote Management Exposure (RDP)
        "HC-DS-001",   # Directory Service Exposure
        "HC-SMB-001",  # SMB Exposure Posture
        "HC-RPC-001",  # RPC Exposure Indicator
        "HC-NET-001",  # Unclassified Network Service Exposure
        "HC-NET-002",  # Reachable Host Without Identity Exposure
    )

    def __init__(self, context: DiscoveryContext) -> None:
        """
        Initialize the domain with the shared DiscoveryContext.
        """
        super().__init__(context)  # Call base class constructor (required by contract)

    def execute(
        self,
        prior_findings: tuple[DiscoveryFinding, ...] = (),
    ) -> List[DiscoveryFinding]:
        """
        Entry point for this domain.

        Inputs:
        - prior_findings: immutable tuple of findings from upstream modules

        Outputs:
        - List of newly derived DiscoveryFinding objects

        Phase A behavior:
        - Evaluate rules in fixed order
        - Currently emits no findings (rule logic not yet implemented)
        """

        findings: List[DiscoveryFinding] = []  # Initialize output list

        # Create a local immutable reference to upstream findings
        # This reinforces read-only contract compliance
        upstream = tuple(prior_findings)

        # Iterate through rules in STRICT predefined order
        for rule_id in self._RULE_ORDER:
            # Evaluate rule (currently stubbed)
            derived = self._evaluate_rule(rule_id, upstream)

            # If rule produced a finding, append it
            if derived is not None:
                findings.append(derived)

        # Return all derived findings (append-only model)
        return findings

    def _evaluate_rule(
        self,
        rule_id: str,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        Dispatch method that maps rule IDs to their implementation functions.

        Ensures:
        - Deterministic rule selection
        - No dynamic logic
        """

        # Static mapping of rule IDs to handler methods
        dispatch = {
            "HC-RM-001": self._rule_hc_rm_001,
            "HC-RM-002": self._rule_hc_rm_002,
            "HC-DS-001": self._rule_hc_ds_001,
            "HC-SMB-001": self._rule_hc_smb_001,
            "HC-RPC-001": self._rule_hc_rpc_001,
            "HC-NET-001": self._rule_hc_net_001,
            "HC-NET-002": self._rule_hc_net_002,
        }

        # Select the correct rule handler
        handler = dispatch[rule_id]

        # Execute the rule logic
        return handler(prior_findings)

    # ------------------------------------------------------------------
    # Phase B rule stubs (NO LOGIC YET — intentional)
    # ------------------------------------------------------------------

    def _rule_hc_rm_001(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        HC-RM-001: Remote Management Exposure (WinRM / WinRM-HTTPS).

        Trigger:
        - One or more prior identity findings exist where:
          - domain == "identity"
          - category == "identity_service_exposed"
          - evidence.service_hint is "WinRM" or "WinRM-HTTPS"

        Output:
        - category = "remote_management_exposure"
        - confidence = 0.85
        - target = host-only target from context
        """

        # Define the exact allowed upstream service hints for this rule.
        # This is fixed and deterministic per the specification.
        allowed_service_hints = {"WinRM", "WinRM-HTTPS"}

        # Collect only qualifying upstream findings for this rule.
        # We preserve upstream order and do not mutate the input data.
        matching_findings: List[DiscoveryFinding] = []

        for finding in prior_findings:
            # Rule applies only to Identity domain findings.
            if finding.domain != "identity":
                continue

            # Rule applies only to identity exposure findings.
            if finding.category != "identity_service_exposed":
                continue

            # Extract service hint from the evidence structure.
            service_hint = finding.evidence.get("service_hint")

            # Keep only WinRM / WinRM-HTTPS exposure findings.
            if service_hint in allowed_service_hints:
                matching_findings.append(finding)

        # If no qualifying findings exist, this rule emits nothing.
        if not matching_findings:
            return None

        # Build deterministic evidence structure required by the spec.
        evidence = self._build_evidence(
            rule_id="HC-RM-001",
            source_findings=matching_findings,
            rationale="Host exposes remote management capability via WinRM-related service exposure",
        )

        # Emit exactly one derived finding for this rule and target.
        return self._make_finding(
            category="remote_management_exposure",
            evidence=evidence,
            confidence=0.85,
        )

    def _rule_hc_rm_002(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        HC-RM-002: Remote Management Exposure (RDP).

        Trigger:
        - One or more prior identity findings exist where:
          - domain == "identity"
          - category == "identity_service_exposed"
          - evidence.service_hint is "RDP"

        Output:
        - category = "remote_management_exposure"
        - confidence = 0.85
        - target = host-only target from context
        """

        # Define the exact allowed upstream service hint for this rule.
        allowed_service_hint = "RDP"

        # Collect only qualifying upstream findings for this rule.
        # Preserve upstream ordering and do not mutate input.
        matching_findings: List[DiscoveryFinding] = []

        for finding in prior_findings:
            # Rule applies only to Identity domain findings.
            if finding.domain != "identity":
                continue

            # Rule applies only to identity exposure findings.
            if finding.category != "identity_service_exposed":
                continue

            # Extract service hint from the evidence structure.
            service_hint = finding.evidence.get("service_hint")

            # Keep only RDP exposure findings.
            if service_hint == allowed_service_hint:
                matching_findings.append(finding)

        # If no qualifying findings exist, this rule emits nothing.
        if not matching_findings:
            return None

        # Build deterministic evidence structure required by the spec.
        evidence = self._build_evidence(
            rule_id="HC-RM-002",
            source_findings=matching_findings,
            rationale="Host exposes remote desktop capability",
        )

        # Emit exactly one derived finding for this rule and target.
        return self._make_finding(
            category="remote_management_exposure",
            evidence=evidence,
            confidence=0.85,
        )

    def _rule_hc_ds_001(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        HC-DS-001: Directory Service Exposure.

        Trigger:
        - One or more prior identity findings exist where:
          - domain == "identity"
          - category == "identity_service_exposed"
          - evidence.service_hint is "LDAP", "LDAPS", or "Kerberos"

        Output:
        - category = "directory_service_exposure"
        - confidence = 0.90
        - target = host-only target from context
        """

        # Define the exact allowed upstream service hints for this rule.
        # This is fixed and deterministic per the specification.
        allowed_service_hints = {"LDAP", "LDAPS", "Kerberos"}

        # Collect only qualifying upstream findings for this rule.
        # Preserve upstream ordering and do not mutate input.
        matching_findings: List[DiscoveryFinding] = []

        for finding in prior_findings:
            # Rule applies only to Identity domain findings.
            if finding.domain != "identity":
                continue

            # Rule applies only to identity exposure findings.
            if finding.category != "identity_service_exposed":
                continue

            # Extract service hint from the evidence structure.
            service_hint = finding.evidence.get("service_hint")

            # Keep only directory-service exposure findings.
            if service_hint in allowed_service_hints:
                matching_findings.append(finding)

        # If no qualifying findings exist, this rule emits nothing.
        if not matching_findings:
            return None

        # Build deterministic evidence structure required by the spec.
        evidence = self._build_evidence(
            rule_id="HC-DS-001",
            source_findings=matching_findings,
            rationale="Host presents directory-service-related exposure signals",
        )

        # Emit exactly one derived finding for this rule and target.
        return self._make_finding(
            category="directory_service_exposure",
            evidence=evidence,
            confidence=0.90,
        )

    def _rule_hc_smb_001(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        HC-SMB-001: SMB Exposure Posture.

        Trigger:
        - One or more prior identity findings exist where:
          - domain == "identity"
          - category == "identity_service_exposed"
          - evidence.service_hint is "SMB" or "NetBIOS-SSN"

        Output:
        - category = "smb_exposure_posture"
        - confidence = 0.80
        - target = host-only target from context
        """

        # Define the exact allowed upstream service hints for this rule.
        allowed_service_hints = {"SMB", "NetBIOS-SSN"}

        # Collect only qualifying upstream findings for this rule.
        # Preserve upstream ordering and do not mutate input.
        matching_findings: List[DiscoveryFinding] = []

        for finding in prior_findings:
            # Rule applies only to Identity domain findings.
            if finding.domain != "identity":
                continue

            # Rule applies only to identity exposure findings.
            if finding.category != "identity_service_exposed":
                continue

            # Extract service hint from the evidence structure.
            service_hint = finding.evidence.get("service_hint")

            # Keep only SMB / NetBIOS-SSN exposure findings.
            if service_hint in allowed_service_hints:
                matching_findings.append(finding)

        # If no qualifying findings exist, this rule emits nothing.
        if not matching_findings:
            return None

        # Build deterministic evidence structure required by the spec.
        evidence = self._build_evidence(
            rule_id="HC-SMB-001",
            source_findings=matching_findings,
            rationale="Host exposes SMB-related service surface",
        )

        # Emit exactly one derived finding for this rule and target.
        return self._make_finding(
            category="smb_exposure_posture",
            evidence=evidence,
            confidence=0.80,
        )

    def _rule_hc_rpc_001(
            self,
            prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        HC-RPC-001: RPC Exposure Indicator.

        Trigger:
        - One or more prior identity findings exist where:
          - domain == "identity"
          - category == "identity_service_exposed"
          - evidence.service_hint == "RPC"

        Output:
        - category = "rpc_exposure_indicator"
        - confidence = 0.75
        """

        matching_findings: List[DiscoveryFinding] = []

        for finding in prior_findings:
            if finding.domain != "identity":
                continue

            if finding.category != "identity_service_exposed":
                continue

            service_hint = finding.evidence.get("service_hint")

            if service_hint == "RPC":
                matching_findings.append(finding)

        if not matching_findings:
            return None

        evidence = self._build_evidence(
            rule_id="HC-RPC-001",
            source_findings=matching_findings,
            rationale="Host exposes RPC endpoint mapper service",
        )

        return self._make_finding(
            category="rpc_exposure_indicator",
            evidence=evidence,
            confidence=0.75,
        )

    def _rule_hc_net_001(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """
        HC-NET-001: Unclassified Network Service Exposure.

        Trigger:
        - One or more prior network findings exist where:
          - domain == "network"
          - category == "open_port"
        - AND no prior identity findings exist where:
          - domain == "identity"
          - category == "identity_service_exposed"
          - target matches the same port-qualified target as the network finding

        Output:
        - category = "unclassified_network_service_exposure"
        - confidence = 0.60
        - target = host-only target from context
        """

        # Collect all network open_port findings in upstream order.
        network_open_ports: List[DiscoveryFinding] = []

        for finding in prior_findings:
            if finding.domain != "network":
                continue
            if finding.category != "open_port":
                continue
            network_open_ports.append(finding)

        # Collect the full set of port-qualified targets already classified by Identity.
        classified_identity_targets = {
            finding.target
            for finding in prior_findings
            if finding.domain == "identity"
            and finding.category == "identity_service_exposed"
        }

        # Keep only network open ports that were not classified by Identity
        # for the same exact port-qualified target.
        matching_findings: List[DiscoveryFinding] = []

        for finding in network_open_ports:
            if finding.target in classified_identity_targets:
                continue
            matching_findings.append(finding)

        # If no qualifying findings exist, this rule emits nothing.
        if not matching_findings:
            return None

        # Build deterministic evidence structure required by the spec.
        evidence = self._build_evidence(
            rule_id="HC-NET-001",
            source_findings=matching_findings,
            rationale="Host exposes a reachable network service that is not classified by the current Identity Discovery rule set",
        )

        # Emit exactly one derived finding for this rule and target.
        return self._make_finding(
            category="unclassified_network_service_exposure",
            evidence=evidence,
            confidence=0.60,
        )

    def _rule_hc_net_002(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
    ) -> DiscoveryFinding | None:
        """HC-NET-002: Reachable Host Without Identity Exposure."""
        return None

    # ------------------------------------------------------------------
    # Deterministic helper methods (used in Phase B)
    # ------------------------------------------------------------------

    def _host_target(self) -> str:
        """
        Return normalized host-only target.
        Removes any port qualification implicitly by using context target.
        """
        return self.context.target  # Context always stores base host

    def _filter_findings(
        self,
        prior_findings: Sequence[DiscoveryFinding],
        *,
        domain: str | None = None,
        category: str | None = None,
    ) -> List[DiscoveryFinding]:
        """
        Deterministically filter findings by domain and/or category.

        Important:
        - Preserves original ordering (NO sorting here)
        """

        results: List[DiscoveryFinding] = []  # Initialize result list

        for finding in prior_findings:  # Iterate in original order
            if domain is not None and finding.domain != domain:
                continue  # Skip if domain does not match

            if category is not None and finding.category != category:
                continue  # Skip if category does not match

            results.append(finding)  # Add matching finding

        return results  # Return filtered list

    def _extract_port(self, finding: DiscoveryFinding) -> int | None:
        """
        Extract port value from a finding's evidence (if present).
        """

        port = finding.evidence.get("port")  # Attempt to retrieve port field

        # Ensure port is valid integer before returning
        return port if isinstance(port, int) else None

    def _sorted_unique_strings(self, values: Sequence[str]) -> List[str]:
        """
        Deduplicate and sort string values deterministically.
        """

        return sorted({value for value in values if value})  # Set -> sorted list

    def _sorted_unique_ports(self, values: Sequence[int]) -> List[int]:
        """
        Deduplicate and sort port values deterministically.
        """

        return sorted({value for value in values if isinstance(value, int)})

    def _build_evidence(
        self,
        *,
        rule_id: str,
        source_findings: Sequence[DiscoveryFinding],
        rationale: str,
    ) -> Dict:
        """
        Build structured evidence required by M6 specification.

        Includes:
        - rule_id
        - source_categories
        - source_targets
        - source_ports
        - rationale
        """

        # Extract and normalize categories
        source_categories = self._sorted_unique_strings(
            [finding.category for finding in source_findings]
        )

        # Extract and normalize targets
        source_targets = self._sorted_unique_strings(
            [finding.target for finding in source_findings]
        )

        # Extract and normalize ports
        source_ports = self._sorted_unique_ports(
            [
                port
                for port in (self._extract_port(finding) for finding in source_findings)
                if port is not None
            ]
        )

        # Return structured evidence dictionary
        return {
            "rule_id": rule_id,
            "source_categories": source_categories,
            "source_targets": source_targets,
            "source_ports": source_ports,
            "rationale": rationale,
        }

    def _make_finding(
        self,
        *,
        category: str,
        evidence: Dict,
        confidence: float,
    ) -> DiscoveryFinding:
        """
        Construct a new DiscoveryFinding object for this domain.
        """

        return DiscoveryFinding(
            domain=self.name,  # Always "host_configuration"
            category=category,  # Must be one of approved categories
            target=self._host_target(),  # Host-only target (no port)
            evidence=evidence,  # Structured rule evidence
            confidence=confidence,  # Static confidence (per rule)
            observed_at=_utc_now(),  # Deterministic UTC timestamp
        )