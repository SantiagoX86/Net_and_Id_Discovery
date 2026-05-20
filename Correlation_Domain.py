# ---------------------------------------------------------------------
# Correlation_Domain.py
#
# Milestone: M8 – Correlation Domain
# Phase C – Network-Inclusive Correlation
#
# This module implements a correlation-only consuming domain that:
# - Consumes prior findings from the orchestrator as read-only input
# - Produces new correlation-owned DiscoveryFinding objects
# - Performs NO discovery activity
# - Performs NO network interaction
# - Performs NO socket usage, probing, authentication, negotiation, or parsing
# - Preserves upstream findings unchanged
#
# Phase C behavior:
# - Preserves specialized-domain correlation rules
# - Adds Network-inclusive correlation rules
# - Uses Identity, Application / Service, and Telemetry / Logging findings
# - Uses Network findings only for unclassified Network exposure relationships
# - Does NOT consume Host Configuration findings
# - Enforces tri-domain precedence over pairwise specialized-domain fallback rules
# - Does NOT treat expected Network/specialized overlap as correlation
# ---------------------------------------------------------------------

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

from Core_Framework import DiscoveryContext, DiscoveryFinding, DiscoveryModule


def _utc_now() -> datetime:
    """
    Return an aware UTC datetime for newly emitted correlation findings.
    """
    return datetime.now(timezone.utc)


class CorrelationDomain(DiscoveryModule):
    """
    Correlation Domain (M8).

    Responsibilities:
    - Consume previously produced governed findings from upstream modules
    - Apply deterministic, specification-defined correlation logic
    - Emit append-only correlation findings without modifying upstream findings

    Phase B constraints:
    - Specialized-domain correlation only
    - No Network-inclusive correlation rules
    - No Host Configuration correlation context
    - No mutation, suppression, deduplication, merge, normalization, or
      reinterpretation of upstream findings
    """

    name: str = "correlation"

    _RULE_ORDER: Tuple[str, ...] = (
        "COR-ID-AS-TL-001",
        "COR-ID-AS-001",
        "COR-ID-TL-001",
        "COR-AS-TL-001",
        "COR-NET-ID-001",
        "COR-NET-AS-001",
        "COR-NET-TL-001",
        "COR-NET-MULTI-001",
    )

    def __init__(self, context: DiscoveryContext) -> None:
        """
        Initialize the domain with the shared DiscoveryContext.
        """
        super().__init__(context)

    def execute(
        self,
        prior_findings: tuple[DiscoveryFinding, ...] = (),
    ) -> List[DiscoveryFinding]:
        """
        Execute M8 correlation logic.

        Inputs:
        - prior_findings: immutable tuple of findings produced by prior modules

        Outputs:
        - New correlation-owned DiscoveryFinding objects only

        Phase C behavior:
        - Evaluate specialized-domain rules in fixed order
        - Enforce tri-domain precedence
        - Prevent pairwise specialized-domain fallback rules when tri-domain correlation emits
        - Evaluate Network-inclusive rules after specialized-domain rules
        - Use only unclassified Network open_port findings for Network-inclusive rules
        - Ignore Host Configuration findings
        """

        upstream = tuple(prior_findings)
        findings: List[DiscoveryFinding] = []

        identity_findings = self._select_findings(
            upstream,
            domain="identity",
            category="identity_service_exposed",
        )

        application_findings = self._select_findings(
            upstream,
            domain="application_service",
            category="application_service_exposed",
        )

        telemetry_findings = self._select_findings(
            upstream,
            domain="telemetry_logging",
            category="telemetry_logging_exposed",
        )

        network_findings = self._select_findings(
            upstream,
            domain="network",
            category="open_port",
        )

        unclassified_network_findings = self._select_unclassified_network_findings(
            network_findings=network_findings,
            identity_findings=identity_findings,
            application_findings=application_findings,
            telemetry_findings=telemetry_findings,
        )

        tri_domain_emitted = False

        for rule_id in self._RULE_ORDER:
            if rule_id == "COR-ID-AS-TL-001":
                derived = self._rule_cor_id_as_tl_001(
                    identity_findings,
                    application_findings,
                    telemetry_findings,
                )

                if derived is not None:
                    findings.append(derived)
                    tri_domain_emitted = True

                continue

            if tri_domain_emitted and rule_id in {
                "COR-ID-AS-001",
                "COR-ID-TL-001",
                "COR-AS-TL-001",
            }:
                continue

            if rule_id == "COR-ID-AS-001":
                derived = self._rule_cor_id_as_001(
                    identity_findings,
                    application_findings,
                )
            elif rule_id == "COR-ID-TL-001":
                derived = self._rule_cor_id_tl_001(
                    identity_findings,
                    telemetry_findings,
                )
            elif rule_id == "COR-AS-TL-001":
                derived = self._rule_cor_as_tl_001(
                    application_findings,
                    telemetry_findings,
                )
            elif rule_id == "COR-NET-ID-001":
                derived = self._rule_cor_net_id_001(
                    unclassified_network_findings,
                    identity_findings,
                )
            elif rule_id == "COR-NET-AS-001":
                derived = self._rule_cor_net_as_001(
                    unclassified_network_findings,
                    application_findings,
                )
            elif rule_id == "COR-NET-TL-001":
                derived = self._rule_cor_net_tl_001(
                    unclassified_network_findings,
                    telemetry_findings,
                )
            elif rule_id == "COR-NET-MULTI-001":
                derived = self._rule_cor_net_multi_001(
                    unclassified_network_findings,
                    identity_findings,
                    application_findings,
                    telemetry_findings,
                )
            else:
                derived = None

            if derived is not None:
                findings.append(derived)

        return findings

    def _select_findings(
        self,
        prior_findings: Tuple[DiscoveryFinding, ...],
        domain: str,
        category: str,
    ) -> List[DiscoveryFinding]:
        """
        Select authorized Phase B source findings only.

        This method:
        - Uses exact domain/category matching
        - Preserves upstream order
        - Does not mutate source findings
        - Restricts correlation scope to the current execution target
        """

        selected: List[DiscoveryFinding] = []

        for finding in prior_findings:
            if finding.domain != domain:
                continue

            if finding.category != category:
                continue

            if not self._matches_execution_target(finding):
                continue

            selected.append(finding)

        return selected

    def _matches_execution_target(self, finding: DiscoveryFinding) -> bool:
        """
        Confirm the source finding belongs to the current execution target.

        Current framework runs are single-target. Source findings may target either:
        - the host itself, such as 192.168.145.129
        - a port-qualified target, such as 192.168.145.129:445
        """

        return (
            finding.target == self.context.target
            or finding.target.startswith(f"{self.context.target}:")
        )

    def _select_unclassified_network_findings(
        self,
        network_findings: Sequence[DiscoveryFinding],
        identity_findings: Sequence[DiscoveryFinding],
        application_findings: Sequence[DiscoveryFinding],
        telemetry_findings: Sequence[DiscoveryFinding],
    ) -> List[DiscoveryFinding]:
        """
        Select Network open_port findings that do not overlap specialized findings.

        A Network finding is unclassified for correlation purposes only when
        no authorized specialized discovery finding exists for the same
        port-qualified target.
        """

        specialized_targets = {
            finding.target
            for finding in (
                *identity_findings,
                *application_findings,
                *telemetry_findings,
            )
        }

        unclassified: List[DiscoveryFinding] = []

        for finding in network_findings:
            if finding.target in specialized_targets:
                continue

            unclassified.append(finding)

        return unclassified

    def _rule_cor_id_as_tl_001(
        self,
        identity_findings: Sequence[DiscoveryFinding],
        application_findings: Sequence[DiscoveryFinding],
        telemetry_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-ID-AS-TL-001:
        Identity, Application / Service, and Telemetry / Logging Correlation.
        """

        if not identity_findings or not application_findings or not telemetry_findings:
            return None

        source_findings = [
            *identity_findings,
            *application_findings,
            *telemetry_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-ID-AS-TL-001",
            correlated_domains=[
                "identity",
                "application_service",
                "telemetry_logging",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes identity, application/service, and telemetry/logging "
                "interfaces through independently governed discovery findings."
            ),
        )

        return self._make_finding(
            category="identity_application_telemetry_correlation",
            evidence=evidence,
        )

    def _rule_cor_id_as_001(
        self,
        identity_findings: Sequence[DiscoveryFinding],
        application_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-ID-AS-001:
        Identity and Application / Service Correlation.
        """

        if not identity_findings or not application_findings:
            return None

        source_findings = [
            *identity_findings,
            *application_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-ID-AS-001",
            correlated_domains=[
                "identity",
                "application_service",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes identity and application/service interfaces through "
                "independently governed discovery findings."
            ),
        )

        return self._make_finding(
            category="identity_application_correlation",
            evidence=evidence,
        )

    def _rule_cor_id_tl_001(
        self,
        identity_findings: Sequence[DiscoveryFinding],
        telemetry_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-ID-TL-001:
        Identity and Telemetry / Logging Correlation.
        """

        if not identity_findings or not telemetry_findings:
            return None

        source_findings = [
            *identity_findings,
            *telemetry_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-ID-TL-001",
            correlated_domains=[
                "identity",
                "telemetry_logging",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes identity and telemetry/logging interfaces through "
                "independently governed discovery findings."
            ),
        )

        return self._make_finding(
            category="identity_telemetry_correlation",
            evidence=evidence,
        )

    def _rule_cor_as_tl_001(
        self,
        application_findings: Sequence[DiscoveryFinding],
        telemetry_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-AS-TL-001:
        Application / Service and Telemetry / Logging Correlation.
        """

        if not application_findings or not telemetry_findings:
            return None

        source_findings = [
            *application_findings,
            *telemetry_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-AS-TL-001",
            correlated_domains=[
                "application_service",
                "telemetry_logging",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes application/service and telemetry/logging interfaces "
                "through independently governed discovery findings."
            ),
        )

        return self._make_finding(
            category="application_telemetry_correlation",
            evidence=evidence,
        )

    def _rule_cor_net_id_001(
        self,
        network_findings: Sequence[DiscoveryFinding],
        identity_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-NET-ID-001:
        Unclassified Network and Identity Correlation.
        """

        if not network_findings or not identity_findings:
            return None

        source_findings = [
            *network_findings,
            *identity_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-NET-ID-001",
            correlated_domains=[
                "network",
                "identity",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes unclassified Network service exposure alongside "
                "identity-domain exposure."
            ),
        )

        return self._make_finding(
            category="unclassified_network_identity_correlation",
            evidence=evidence,
        )

    def _rule_cor_net_as_001(
        self,
        network_findings: Sequence[DiscoveryFinding],
        application_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-NET-AS-001:
        Unclassified Network and Application / Service Correlation.
        """

        if not network_findings or not application_findings:
            return None

        source_findings = [
            *network_findings,
            *application_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-NET-AS-001",
            correlated_domains=[
                "network",
                "application_service",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes unclassified Network service exposure alongside "
                "application/service exposure."
            ),
        )

        return self._make_finding(
            category="unclassified_network_application_correlation",
            evidence=evidence,
        )

    def _rule_cor_net_tl_001(
        self,
        network_findings: Sequence[DiscoveryFinding],
        telemetry_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-NET-TL-001:
        Unclassified Network and Telemetry / Logging Correlation.
        """

        if not network_findings or not telemetry_findings:
            return None

        source_findings = [
            *network_findings,
            *telemetry_findings,
        ]

        evidence = self._build_evidence(
            correlation_rule_id="COR-NET-TL-001",
            correlated_domains=[
                "network",
                "telemetry_logging",
            ],
            source_findings=source_findings,
            rationale=(
                "Target exposes unclassified Network service exposure alongside "
                "telemetry/logging exposure."
            ),
        )

        return self._make_finding(
            category="unclassified_network_telemetry_correlation",
            evidence=evidence,
        )

    def _rule_cor_net_multi_001(
        self,
        network_findings: Sequence[DiscoveryFinding],
        identity_findings: Sequence[DiscoveryFinding],
        application_findings: Sequence[DiscoveryFinding],
        telemetry_findings: Sequence[DiscoveryFinding],
    ) -> DiscoveryFinding | None:
        """
        COR-NET-MULTI-001:
        Unclassified Network and Multi-Domain Correlation.
        """

        if not network_findings:
            return None

        specialized_domain_count = sum(
            [
                bool(identity_findings),
                bool(application_findings),
                bool(telemetry_findings),
            ]
        )

        if specialized_domain_count < 2:
            return None

        correlated_domains = ["network"]
        source_findings: List[DiscoveryFinding] = [*network_findings]

        if identity_findings:
            correlated_domains.append("identity")
            source_findings.extend(identity_findings)

        if application_findings:
            correlated_domains.append("application_service")
            source_findings.extend(application_findings)

        if telemetry_findings:
            correlated_domains.append("telemetry_logging")
            source_findings.extend(telemetry_findings)

        evidence = self._build_evidence(
            correlation_rule_id="COR-NET-MULTI-001",
            correlated_domains=correlated_domains,
            source_findings=source_findings,
            rationale=(
                "Target exposes unclassified Network service exposure alongside "
                "multiple independently governed specialized-domain exposure signals."
            ),
        )

        return self._make_finding(
            category="unclassified_network_multi_domain_correlation",
            evidence=evidence,
        )

    def _build_evidence(
        self,
        correlation_rule_id: str,
        correlated_domains: List[str],
        source_findings: Sequence[DiscoveryFinding],
        rationale: str,
    ) -> Dict:
        """
        Build required Correlation Domain evidence.

        Source findings are snapshotted for traceability without modifying or
        replacing the authoritative upstream findings.
        """

        return {
            "correlation_rule_id": correlation_rule_id,
            "correlated_domains": correlated_domains,
            "source_findings": [
                self._snapshot_source_finding(finding)
                for finding in source_findings
            ],
            "rationale": rationale,
        }

    def _snapshot_source_finding(self, finding: DiscoveryFinding) -> Dict:
        """
        Create a deterministic traceability snapshot of a source finding.
        """

        return {
            "domain": finding.domain,
            "category": finding.category,
            "target": finding.target,
            "evidence": dict(finding.evidence),
            "observed_at": finding.observed_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }

    def _make_finding(
        self,
        category: str,
        evidence: Dict,
    ) -> DiscoveryFinding:
        """
        Create a normalized correlation-owned DiscoveryFinding.
        """

        return DiscoveryFinding(
            domain="correlation",
            category=category,
            target=self.context.target,
            evidence=evidence,
            observed_at=_utc_now(),
        )