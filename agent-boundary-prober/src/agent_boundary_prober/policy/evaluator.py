"""Classify supplied evidence without performing I/O or changing the inputs."""

from collections.abc import Sequence

from agent_boundary_prober.config import Configuration, destination_matches, validate_endpoint
from agent_boundary_prober.models import (
    CapabilityPolicy,
    Classification,
    Evidence,
    EvidenceKind,
    EvidenceSource,
    Finding,
    Observation,
    ObservationStatus,
    PolicyDecision,
)

TESTED_PATH_LIMITATION = (
    "This result applies only to the tested path and conditions; it does not prove "
    "the capability is unavailable through other paths."
)


def external_egress_policy(config: Configuration, target: str) -> CapabilityPolicy:
    """Resolve an external-egress decision using only the explicit allowlist."""
    normalized = validate_endpoint(target)
    allowed = config.boundaries.network.external_egress.allowed_destinations
    decision = (
        PolicyDecision.ALLOW
        if any(destination_matches(normalized, destination) for destination in allowed)
        else PolicyDecision.DENY
    )
    return CapabilityPolicy(decision=decision)


def evaluate(
    observation: Observation,
    policy: CapabilityPolicy,
    evidence: Sequence[Evidence] = (),
) -> Finding:
    """Evaluate one scoped capability; operator assertions never establish a result."""
    indexed: dict[str, list[Evidence]] = {}
    for item in evidence:
        indexed.setdefault(item.id, []).append(item)
    resolved = [
        item for ref in observation.evidence_refs for item in indexed.get(ref, [])
    ]
    missing = [ref for ref in observation.evidence_refs if ref not in indexed]
    ambiguous = [
        ref for ref in observation.evidence_refs if len(indexed.get(ref, [])) > 1
    ]
    limitations = list(observation.limitations)

    def finding(
        classification: Classification,
        rationale: str,
        *,
        limitation: str | None = None,
        remediation: str | None = None,
    ) -> Finding:
        combined = limitations + ([limitation] if limitation else [])
        return Finding(
            id=observation.id,
            policy=policy,
            observation=observation,
            classification=classification,
            rationale=rationale,
            evidence=resolved,
            confidence=observation.confidence,
            limitations=list(dict.fromkeys(combined)),
            remediation=remediation,
        )

    if missing or ambiguous:
        if missing:
            limitations.append("One or more observation evidence references are unresolved.")
        if ambiguous:
            limitations.append("Referenced evidence identifiers are duplicated and ambiguous.")
        return finding(
            Classification.UNKNOWN,
            "Evidence references are incomplete or ambiguous.",
        )

    kinds = {item.kind for item in resolved}
    outcomes = {
        EvidenceKind.CAPABILITY_AVAILABLE,
        EvidenceKind.CAPABILITY_UNAVAILABLE,
    }
    if outcomes.issubset(kinds):
        return finding(
            Classification.UNKNOWN,
            "Evidence reports both availability and unavailability for the same observation.",
            limitation="Resolve contradictory evidence before classifying this capability.",
        )

    if not policy.applicable:
        if observation.status != ObservationStatus.NOT_RUN or kinds.intersection(
            outcomes | {EvidenceKind.RISK_INDICATOR}
        ):
            return finding(
                Classification.UNKNOWN,
                "The non-applicability assertion conflicts with a reported test or risk.",
            )
        return finding(
            Classification.NOT_APPLICABLE,
            "The check does not apply for the explicitly recorded applicability reason.",
        )

    if policy.decision == PolicyDecision.NOT_DEFINED:
        return finding(
            Classification.UNKNOWN,
            "No policy decision is defined for this capability.",
            limitation="Availability alone does not establish permission.",
        )

    if observation.status in {ObservationStatus.NOT_RUN, ObservationStatus.INCONCLUSIVE}:
        return finding(
            Classification.UNKNOWN,
            "The capability was not tested conclusively.",
        )

    expected = (
        EvidenceKind.CAPABILITY_AVAILABLE
        if observation.status == ObservationStatus.OBSERVED
        else EvidenceKind.CAPABILITY_UNAVAILABLE
    )
    if kinds.intersection(outcomes - {expected}):
        return finding(
            Classification.UNKNOWN,
            "The reported observation status contradicts its evidence.",
        )

    supported = [
        item
        for item in resolved
        if item.kind == expected
        and item.source != EvidenceSource.OPERATOR_ASSERTION
        and (
            expected != EvidenceKind.CAPABILITY_UNAVAILABLE
            or item.source == EvidenceSource.CONTROLLED_TEST
        )
    ]
    risk = any(
        item.kind == EvidenceKind.RISK_INDICATOR
        and item.source != EvidenceSource.OPERATOR_ASSERTION
        for item in resolved
    )
    if not observation.verified or not supported:
        if risk:
            return finding(
                Classification.WARNING,
                "Evidence identifies a risk without establishing a definite policy violation.",
                limitation="The capability outcome is unverified or lacks conclusive evidence.",
                remediation="Investigate the risk using an authorized, controlled test.",
            )
        return finding(
            Classification.UNKNOWN,
            "The capability outcome is unverified or lacks qualifying evidence.",
            limitation="Operator assertions and missing evidence are not verification.",
        )

    if observation.status == ObservationStatus.OBSERVED:
        if policy.decision == PolicyDecision.DENY:
            return finding(
                Classification.VIOLATION,
                "A prohibited capability is verified as available.",
                remediation="Restrict the prohibited capability on the tested path.",
            )
        if risk:
            return finding(
                Classification.WARNING,
                "The permitted capability has a risk indicator, not an established violation.",
                remediation="Investigate the reported risk without assuming a policy violation.",
            )
        return finding(
            Classification.PASS,
            "The verified capability is explicitly permitted.",
        )

    if policy.decision == PolicyDecision.DENY:
        return finding(
            Classification.PASS,
            "A controlled test conclusively found the prohibited capability unavailable.",
            limitation=TESTED_PATH_LIMITATION,
        )
    if policy.required:
        return finding(
            Classification.VIOLATION,
            "A required capability is conclusively unavailable.",
            limitation=TESTED_PATH_LIMITATION,
            remediation="Restore the required capability on the tested path.",
        )
    return finding(
        Classification.PASS,
        "The permitted capability is optional, so its unavailability does not violate policy.",
        limitation=TESTED_PATH_LIMITATION,
    )
