"""
WAUIG Bank - Enterprise Security Discovery Orchestration Framework
Output & Reporting Layer (Milestone M3) - v1 (Fully Annotated)

Purpose:
- Convert normalized discovery results into human- and machine-consumable artifacts
- Preserve auditability, determinism, and evidence integrity
- Decouple discovery logic from presentation concerns

Why this layer exists:
- Enterprise tools separate *collection* from *reporting*
- Allows the same findings to be reused across formats (JSON, Markdown, CSV)
- Prevents discovery domains from embedding presentation logic

What this module does:
- Serializes DiscoveryRunResult objects to JSON
- Produces analyst-friendly Markdown reports

What this module does NOT do:
- No discovery logic
- No modification of findings
- No environment interaction

SDLC Context:
- Phase 4 (Construct)
- Milestone M3 per Implementation Plan
"""

# =========================
# Imports
# =========================

# json is used for machine-readable serialization.
import json

# datetime utilities ensure consistent timestamp handling.
from datetime import datetime, timezone

# typing improves clarity of data contracts.
from typing import Dict, List

# Core framework contracts (produced in M1).
from Core_Framework import DiscoveryRunResult, DiscoveryFinding


# =========================
# JSON Serialization
# =========================


def serialize_run_to_json(run: DiscoveryRunResult) -> Dict:
    """
    Convert a DiscoveryRunResult into a JSON-serializable dictionary.

    Why this exists:
    - JSON is the primary interchange format in enterprise pipelines
    - Enables storage, diffing, ingestion into SIEMs or data lakes

    Design notes:
    - No formatting logic (indentation handled at write-time)
    - Field ordering is deterministic
    """

    return {
        "context": {
            "target": run.context.target,
            "run_started_at": run.context.run_started_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "source_host": run.context.source_host,
            "assumptions": run.context.assumptions,
            "run_id": run.context.run_id,
        },
        "findings": [finding.to_dict() for finding in run.findings],
        "events": [event.to_dict() for event in run.events],
    }


# =========================
# Markdown Reporting
# =========================


def generate_markdown_report(run: DiscoveryRunResult) -> str:
    """
    Generate a human-readable Markdown report from discovery results.

    Why Markdown:
    - Renders cleanly on GitHub, Confluence, internal portals
    - Ideal for security review and portfolio presentation

    Reporting philosophy:
    - Summarize first, then provide detail
    - Avoid per-port noise where possible
    - Preserve evidence verbatim
    """

    lines: List[str] = []

    # -------------------------
    # Header Section
    # -------------------------

    lines.append("# Network Discovery Report")
    lines.append("")

    lines.append(f"**Target:** `{run.context.target}`")
    lines.append(f"**Source Host:** `{run.context.source_host}`")
    lines.append(
        f"**Run Started:** {run.context.run_started_at.astimezone(timezone.utc).isoformat().replace('+00:00','Z')}"
    )
    lines.append("")

    # -------------------------
    # Host Presence Summary
    # -------------------------

    host_findings = [
        f for f in run.findings if f.category == "host_presence"
    ]

    lines.append("## Host Reachability")

    if host_findings:
        hf = host_findings[0]
        reachable = hf.evidence.get("reachable")
        status = "Reachable" if reachable else "Not Reachable"
        lines.append(f"- ICMP Echo: **{status}**")
    else:
        lines.append("- Host reachability not assessed")

    lines.append("")

    # -------------------------
    # Open Port Summary
    # -------------------------

    open_ports = [
        f for f in run.findings if f.category == "open_port"
    ]

    lines.append("## Exposed Services")

    if not open_ports:
        lines.append("- No externally reachable services observed")
    else:
        lines.append("| Port | Service | Confidence |")
        lines.append("|------|---------|------------|")
        for finding in open_ports:
            port = finding.evidence.get("port")
            service = finding.evidence.get("service_hint")
            conf = finding.confidence
            lines.append(f"| {port} | {service} | {conf} |")

    lines.append("")

    # -------------------------
    # Analyst Notes
    # -------------------------

    lines.append("## Analyst Notes")

    if open_ports:
        lines.append(
            "- One or more network services are externally reachable from this vantage point."
        )
        lines.append(
            "- Exposure is dependent on host firewall and network profile configuration."
        )
    else:
        lines.append(
            "- No network services were observed as externally reachable during this run."
        )
        lines.append(
            "- This may indicate a hardened firewall posture or disabled services."
        )

    lines.append("")

    # -------------------------
    # Appendix: Raw Findings
    # -------------------------

    lines.append("## Appendix: Raw Findings")

    for finding in run.findings:
        lines.append("```json")
        lines.append(json.dumps(finding.to_dict(), indent=2))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)
