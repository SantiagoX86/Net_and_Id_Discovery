# ---------------------------------------------------------------------
# Correlation_Domain.py
#
# Milestone: M8 – Correlation Domain
# Phase B – Specialized-Domain Correlation
#
# This module implements a correlation-only consuming domain that:
# - Consumes prior findings from the orchestrator as read-only input
# - Produces new correlation-owned DiscoveryFinding objects
# - Performs NO discovery activity
# - Performs NO network interaction
# - Performs NO socket usage, probing, authentication, negotiation, or parsing
# - Preserves upstream findings unchanged
#
# Phase B behavior:
# - Implements specialized-domain correlation rules only
# - Uses Identity, Application / Service, and Telemetry / Logging findings
# - Does NOT consume Network findings
# - Does NOT consume Host Configuration findings
# - Enforces tri-domain precedence over pairwise fallback rules
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
        Execute specialized-domain correlation logic.

        Inputs:
        - prior_findings: immutable tuple of findings produced by prior modules

        Outputs:
        - New correlation-owned DiscoveryFinding objects only

        Phase B behavior:
        - Evaluate specialized-domain rules in fixed order
        - Enforce tri-domain precedence
        - Prevent pairwise fallback rules when tri-domain correlation emits
        - Ignore Network and Host Configuration findings
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

            if tri_domain_emitted:
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