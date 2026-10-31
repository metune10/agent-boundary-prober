import json

from pydantic import ValidationError
import pytest

from agent_boundary_prober.models import CapabilityPolicy, Evidence, Finding, Observation
from agent_boundary_prober.policy import evaluate
from agent_boundary_prober.reporting import findings_to_json


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("nan"), float("inf"), "0.5", True])
def test_confidence_bounds(evidence, observation, confidence):
    with pytest.raises(ValidationError):
        Evidence.model_validate({**evidence.model_dump(), "confidence": confidence})
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation.model_dump(), "confidence": confidence})


@pytest.mark.parametrize("confidence", [0.0, 0.25, 1.0])
def test_valid_confidence(evidence, confidence):
    assert Evidence.model_validate({**evidence.model_dump(), "confidence": confidence}).confidence == confidence


@pytest.mark.parametrize("status", ["not_run", "inconclusive"])
def test_unexecuted_observation_cannot_be_verified(observation, status):
    with pytest.raises(ValidationError, match="cannot be verified"):
        Observation.model_validate({**observation.model_dump(), "status": status})


@pytest.mark.parametrize("field", ["credentials", "token", "secret", "raw_value", "payload", "url", "headers", "body"])
def test_evidence_rejects_raw_payload_fields(evidence, field):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Evidence.model_validate({**evidence.model_dump(), field: "synthetic-value"})


@pytest.mark.parametrize("identifier", ["https://user:pass@host", "Bearer value", "../file", "token=value", "x" * 65])
def test_evidence_references_are_symbolic_only(evidence, identifier):
    with pytest.raises(ValidationError):
        Evidence.model_validate({**evidence.model_dump(), "id": identifier})


@pytest.mark.parametrize("field,value", [("subject", ""), ("target", "bad\nlabel"), ("relationship", "bad\x00label"), ("limitations", ["bad\tlabel"]), ("target", "bad\u2028label"), ("target", "bad\u202elabel"), ("subject", "bad\x85label")])
def test_observation_labels_are_bounded_single_line(observation, field, value):
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation.model_dump(), field: value})


@pytest.mark.parametrize("field,value", [("status", "success"), ("category", "other"), ("verified", "true"), ("evidence_refs", ["duplicate", "duplicate"])])
def test_observation_rejects_invalid_state(observation, field, value):
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation.model_dump(), field: value})


@pytest.mark.parametrize(
    "values",
    [
        {"decision": "deny", "required": True},
        {"decision": "not_defined", "required": True},
        {"decision": "allow", "applicable": False},
        {"decision": "allow", "applicability_reason": "No reason needed"},
        {"decision": "allow", "applicable": "false"},
        {"decision": "maybe"},
    ],
)
def test_invalid_policy_contracts(values):
    with pytest.raises(ValidationError):
        CapabilityPolicy(**values)


def test_unknown_fields_in_reusable_models(evidence, observation):
    for model in (evidence, observation, CapabilityPolicy(decision="allow")):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            type(model).model_validate({**model.model_dump(), "unexpected": True})
    finding = evaluate(observation, CapabilityPolicy(decision="deny"), [evidence])
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Finding.model_validate({**finding.model_dump(), "unexpected": True})


def test_report_preserves_evidence_policy_confidence_and_limitations(evidence, observation):
    finding = evaluate(observation, CapabilityPolicy(decision="deny"), [evidence])
    text = findings_to_json([finding])
    report = json.loads(text)
    assert report["version"] == 1
    item = report["findings"][0]
    assert item["classification"] == "VIOLATION"
    assert item["policy"]["decision"] == "deny"
    assert item["observation"]["status"] == "observed"
    assert item["observation"]["evidence_refs"] == [evidence.id]
    assert item["evidence"] == [evidence.model_dump(mode="json")]
    assert item["limitations"] == observation.limitations
    assert item["confidence"] == observation.confidence
    assert item["evidence"][0]["confidence"] == evidence.confidence
    assert item["remediation"] == finding.remediation
    assert Finding.model_validate(item) == finding
    assert findings_to_json([finding]) == text


def test_report_empty_and_optional_remediation(evidence, observation):
    assert json.loads(findings_to_json([])) == {"version": 1, "findings": []}
    finding = evaluate(observation, CapabilityPolicy(decision="allow"), [evidence])
    assert "remediation" not in json.loads(findings_to_json([finding]))["findings"][0]


@pytest.mark.parametrize("field", ["evidence_refs", "limitations"])
def test_observation_sequences_are_strict(observation, field):
    values = observation.model_dump()
    values[field] = tuple(values[field])
    with pytest.raises(ValidationError, match="valid list"):
        Observation.model_validate(values)


@pytest.mark.parametrize("field", ["evidence", "limitations"])
def test_finding_sequences_are_strict(evidence, observation, field):
    values = evaluate(observation, CapabilityPolicy(decision="allow"), [evidence]).model_dump()
    values[field] = tuple(values[field])
    with pytest.raises(ValidationError, match="valid list"):
        Finding.model_validate(values)
