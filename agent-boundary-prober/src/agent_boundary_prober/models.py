"""Payload-free evidence and explicit policy evaluation contracts."""

from enum import StrEnum
from typing import Annotated, Self
import unicodedata

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StringConstraints,
    model_validator,
)


def _single_line(value: str) -> str:
    if not value.strip() or any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for char in value
    ):
        raise ValueError("Use a nonempty, single-line, non-secret label")
    return value


Identifier = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
]
SafeLabel = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=2048),
    AfterValidator(_single_line),
]
Confidence = Annotated[
    float, Field(strict=True, ge=0.0, le=1.0, allow_inf_nan=False)
]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True
    )


class ObservationStatus(StrEnum):
    OBSERVED = "observed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    INCONCLUSIVE = "inconclusive"


class ObservationCategory(StrEnum):
    DIRECT_NETWORK = "direct_network"
    RELAY = "relay"
    IDENTITY = "identity"
    PERMISSIONS = "permissions"
    SHARED_STATE = "shared_state"


class EvidenceKind(StrEnum):
    CAPABILITY_AVAILABLE = "capability_available"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    RISK_INDICATOR = "risk_indicator"
    CONTEXT = "context"


class EvidenceSource(StrEnum):
    CONTROLLED_TEST = "controlled_test"
    PASSIVE_INVENTORY = "passive_inventory"
    OPERATOR_ASSERTION = "operator_assertion"


class Evidence(StrictModel):
    """A symbolic reference and typed outcome, never a raw probe payload."""

    id: Identifier
    kind: EvidenceKind
    source: EvidenceSource
    confidence: Confidence


class Observation(StrictModel):
    id: Identifier
    category: ObservationCategory
    subject: SafeLabel
    target: SafeLabel
    relationship: SafeLabel
    status: ObservationStatus
    verified: StrictBool
    evidence_refs: list[Identifier] = Field(default_factory=list, strict=True)
    confidence: Confidence
    limitations: list[SafeLabel] = Field(default_factory=list, strict=True)

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.verified and self.status in {
            ObservationStatus.NOT_RUN,
            ObservationStatus.INCONCLUSIVE,
        }:
            raise ValueError("An untested or inconclusive capability cannot be verified")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("Evidence references must be unique")
        return self


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NOT_DEFINED = "not_defined"


class Classification(StrEnum):
    PASS = "PASS"
    VIOLATION = "VIOLATION"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CapabilityPolicy(StrictModel):
    decision: PolicyDecision
    required: StrictBool = False
    applicable: StrictBool = True
    applicability_reason: SafeLabel | None = None

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if self.required and self.decision != PolicyDecision.ALLOW:
            raise ValueError("Only an allowed capability can be required")
        if not self.applicable and self.applicability_reason is None:
            raise ValueError("Non-applicability requires an explicit reason")
        if self.applicable and self.applicability_reason is not None:
            raise ValueError("An applicability reason is only valid for a non-applicable check")
        return self


class Finding(StrictModel):
    id: Identifier
    policy: CapabilityPolicy
    observation: Observation
    classification: Classification
    rationale: SafeLabel
    evidence: list[Evidence] = Field(strict=True)
    confidence: Confidence
    limitations: list[SafeLabel] = Field(strict=True)
    remediation: SafeLabel | None = None
