"""
WAUIG Bank - Enterprise Security Discovery Orchestration Framework
Core Framework (Milestone M1) - v1

This module implements the domain-agnostic core primitives that every discovery
domain must reuse:

- DiscoveryContext: execution metadata + assumptions
- DiscoveryFinding: normalized output contract
- DiscoveryModule: abstract interface for domains
- DiscoveryOrchestrator: coordinates module execution + error resilience

Design intent (aligned to FRD/TRD/ADD):
- Orchestrator is unaware of domain internals
- Domains are pluggable and isolated
- Failures in one domain do not stop the run
- Output is structured, auditable, and serializable

NOTE:
- This is an implementation artifact for Phase 4 (Construct).
- Packaging / file-splitting will occur later (Milestone M5).
"""

# =========================
# Imports
# =========================

# Abstract Base Classes enforce a consistent module interface across domains.
from abc import ABC, abstractmethod

# Dataclasses reduce boilerplate and produce predictable, serializable shapes.
from dataclasses import dataclass, asdict

# datetime is used to timestamp runs and observations for auditability.
from datetime import datetime, timezone

# Typing clarifies contracts and improves maintainability.
from typing import Any, Dict, List, Optional


# =========================
# Core Data Models
# =========================

@dataclass(frozen=True)
class DiscoveryContext:
    """
    Immutable execution context for a discovery run.

    Why it exists:
    - Ensures findings are interpretable (who ran what, when, and under which assumptions)
    - Enables deterministic comparisons between runs
    - Provides a shared input contract to all domains

    How it fits:
    - Created by the Entry/Control layer (later: CLI/main.py)
    - Passed into each discovery domain at instantiation
    """

    # Identifier for the assessment target (host/IP/CIDR/hostname).
    target: str

    # When the run began (UTC).
    run_started_at: datetime

    # Identifier for the source host / vantage point (e.g., Kali hostname).
    source_host: str

    # Explicit scope/safety assumptions (e.g., "No credentials", "Agentless").
    assumptions: List[str]

    # Optional run identifier to correlate outputs (useful for logging/reporting).
    run_id: Optional[str] = None


@dataclass(frozen=True)
class DiscoveryFinding:
    """
    Normalized finding emitted by any discovery domain.

    Why it exists:
    - Establishes a consistent, machine-readable output contract across domains
    - Supports auditing (timestamp, evidence) and analysis (category, confidence)

    How it fits:
    - Domains emit lists of DiscoveryFinding objects
    - Orchestrator aggregates findings across modules
    - Output layer serializes these findings (M3)
    """

    # Domain identifier (e.g., "network", "identity").
    domain: str

    # Category within the domain (e.g., "open_port", "host_presence").
    category: str

    # Target entity the finding applies to (host, port, service, user, etc.).
    target: str

    # Evidence supporting the observation (method, raw details, etc.).
    evidence: Dict[str, Any]

    # Confidence score (0.0–1.0) reflecting observation reliability.
    confidence: float

    # When the observation was recorded (UTC).
    observed_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a JSON-serializable dictionary."""

        # dataclasses.asdict recursively converts nested dataclasses.
        data = asdict(self)

        # Ensure datetimes serialize predictably (ISO 8601 with Z).
        data["observed_at"] = self.observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

        return data


# =========================
# Module Contract
# =========================

class DiscoveryModule(ABC):
    """
    Abstract base class (ABC) for discovery domains.

    Why it exists:
    - Enforces a consistent contract: `execute()` must return normalized findings
    - Enables the orchestrator to treat all domains uniformly

    How it fits:
    - Each domain inherits from this base and implements `execute()`
    - Domains store their own findings and may use helper methods internally
    """

    # Human-readable domain name; subclasses must override.
    name: str = "base"

    def __init__(self, context: DiscoveryContext):
        # Shared run context; treated as read-only.
        self.context = context

    @abstractmethod
    def execute(self) -> List[DiscoveryFinding]:
        """Run domain discovery logic and return a list of normalized findings."""
        raise NotImplementedError


# =========================
# Orchestration Layer
# =========================

@dataclass(frozen=True)
class OrchestratorEvent:
    """
    Internal orchestrator event used to capture non-fatal execution issues.

    Why it exists:
    - FRD requires graceful failure without terminating the run
    - Enterprises typically capture execution issues in a structured, reviewable way

    How it fits:
    - Orchestrator collects these events in parallel to findings
    - Later reporting can include them without contaminating domain findings
    """

    module: str
    event_type: str
    message: str
    observed_at: datetime
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["observed_at"] = self.observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return data


@dataclass
class DiscoveryRunResult:
    """
    Aggregated result of a full orchestrated discovery run.

    Why it exists:
    - Keeps findings and orchestration events separate
    - Simplifies downstream serialization and reporting

    How it fits:
    - Returned by DiscoveryOrchestrator.run()
    - Output layer will serialize this (M3)
    """

    context: DiscoveryContext
    findings: List[DiscoveryFinding]
    events: List[OrchestratorEvent]


class DiscoveryOrchestrator:
    """
    Coordinates discovery modules and aggregates results.

    Core responsibilities:
    - Execute modules sequentially (deterministic by default)
    - Catch and record module errors (graceful failure)
    - Aggregate normalized findings

    Non-responsibilities (by design):
    - No domain logic
    - No output formatting (handled by Output layer in M3)
    """

    def __init__(self, modules: List[DiscoveryModule]):
        # Ordered list of modules to run.
        self.modules = modules

    def run(self, context: DiscoveryContext) -> DiscoveryRunResult:
        """
        Execute all modules and return aggregated results.

        Note:
        - `context` is provided explicitly here to ensure the orchestrator can be
          used consistently even if modules are created lazily in the future.
        """

        findings: List[DiscoveryFinding] = []
        events: List[OrchestratorEvent] = []

        for module in self.modules:
            # Defensive check: ensure module context aligns with run context.
            # (This prevents subtle bugs where modules are instantiated with
            # a different context than the one being executed.)
            if module.context is not context:
                events.append(
                    OrchestratorEvent(
                        module=getattr(module, "name", module.__class__.__name__),
                        event_type="context_mismatch",
                        message="Module context does not match orchestrator run context.",
                        observed_at=datetime.now(timezone.utc),
                        details={
                            "expected_target": context.target,
                            "module_target": getattr(module.context, "target", None),
                        },
                    )
                )

            try:
                # Execute the module and collect findings.
                module_findings = module.execute()

                # Normalize findings so downstream layers can treat them consistently.
                # Some modules may return DiscoveryFinding objects; others may return dicts.
                normalized: List[DiscoveryFinding] = []
                for f in module_findings:
                    if hasattr(f, "to_dict"):
                        f_copy = dict(f.to_dict())
                        if isinstance(f_copy.get("observed_at"), str):
                            ts = f_copy["observed_at"].replace("Z", "+00:00")
                            f_copy["observed_at"] = datetime.fromisoformat(ts)
                        normalized.append(DiscoveryFinding(**f_copy))
                    elif isinstance(f, dict):
                        # If observed_at is provided as an ISO8601 string, normalize to datetime.
                        f_copy = dict(f)
                        if isinstance(f_copy.get("observed_at"), str):
                            # Accept both "...Z" and "+00:00" formats.
                            ts = f_copy["observed_at"].replace("Z", "+00:00")
                            f_copy["observed_at"] = datetime.fromisoformat(ts)
                        normalized.append(DiscoveryFinding(**f_copy))
                    else:
                        raise TypeError(f"Unsupported finding type: {type(f)}")
                module_findings = normalized


                # Enforce contract: module must return a list.
                if not isinstance(module_findings, list):
                    raise TypeError("execute() must return List[DiscoveryFinding]")

                findings.extend(module_findings)

            except Exception as exc:
                # Graceful failure: record a structured orchestrator event.
                events.append(
                    OrchestratorEvent(
                        module=getattr(module, "name", module.__class__.__name__),
                        event_type="module_error",
                        message=str(exc),
                        observed_at=datetime.now(timezone.utc),
                        details={
                            "exception_type": exc.__class__.__name__,
                        },
                    )
                )

                # Continue execution; do not terminate the overall run.
                continue

        return DiscoveryRunResult(context=context, findings=findings, events=events)


# =========================
# Utility Helpers
# =========================

def utc_now() -> datetime:
    """Return an aware UTC datetime for consistent timestamping."""
    return datetime.now(timezone.utc)
