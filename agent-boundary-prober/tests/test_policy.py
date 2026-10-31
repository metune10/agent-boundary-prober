from copy import deepcopy

import pytest

from agent_boundary_prober.config import Configuration, load_config
from agent_boundary_prober.models import CapabilityPolicy, Evidence, Observation
from agent_boundary_prober.policy import evaluate, external_egress_policy
from agent_boundary_prober.policy.evaluator import TESTED_PATH_LIMITATION
from agent_boundary_prober.reporting import findings_to_json


def revise(model, **updates):
    return type(model).model_validate({**model.model_dump(), **updates})


@pytest.mark.parametrize(
    "status,verified,decision,required,expected",
    [
        ("observed", True, "deny", False, "VIOLATION"),
        ("observed", True, "allow", False, "PASS"),
        ("observed", True, "allow", True, "PASS"),
        ("observed", False, "deny", False, "UNKNOWN"),
        ("observed", False, "allow", False, "UNKNOWN"),
        ("failed", True, "deny", False, "PASS"),
        ("failed", True, "allow", False, "PASS"),
        ("failed", True, "allow", True, "VIOLATION"),
        ("failed", False, "deny", False, "UNKNOWN"),
        ("failed", False, "allow", True, "UNKNOWN"),
        ("not_run", False, "allow", False, "UNKNOWN"),
        ("not_run", False, "deny", False, "UNKNOWN"),
        ("inconclusive", False, "allow", True, "UNKNOWN"),
        ("inconclusive", False, "deny", False, "UNKNOWN"),
        ("observed", True, "not_defined", False, "UNKNOWN"),
        ("failed", True, "not_defined", False, "UNKNOWN"),
    ],
)
def test_classification_matrix(evidence, observation, status, verified, decision, required, expected):
    kind = "capability_unavailable" if status == "failed" else "capability_available"
    evidence = revise(evidence, kind=kind)
    observation = revise(observation, status=status, verified=verified)
    policy = CapabilityPolicy(decision=decision, required=required)
    finding = evaluate(observation, policy, [evidence])
    assert finding.classification == expected
    assert finding.evidence == [evidence]
    assert finding.confidence == observation.confidence
    assert all(item in finding.limitations for item in observation.limitations)
    if status == "failed" and expected in {"PASS", "VIOLATION"}:
        assert TESTED_PATH_LIMITATION in finding.limitations


def test_genuine_non_applicability_requires_not_run(observation):
    policy = CapabilityPolicy(
        decision="not_defined",
        applicable=False,
        applicability_reason="This relationship does not exist in the declared test scenario.",
    )
    observation = revise(observation, status="not_run", verified=False, evidence_refs=[])
    finding = evaluate(observation, policy)
    assert finding.classification == "NOT_APPLICABLE"
    assert finding.policy.applicability_reason == policy.applicability_reason


@pytest.mark.parametrize("status,verified", [("observed", True), ("failed", True), ("inconclusive", False)])
def test_non_applicability_cannot_hide_a_test(evidence, observation, status, verified):
    policy = CapabilityPolicy(decision="allow", applicable=False, applicability_reason="Synthetic reason")
    observation = revise(observation, status=status, verified=verified)
    assert evaluate(observation, policy, [evidence]).classification == "UNKNOWN"


def test_non_applicability_cannot_hide_risk(evidence, observation):
    evidence = revise(evidence, kind="risk_indicator")
    observation = revise(observation, status="not_run", verified=False)
    policy = CapabilityPolicy(decision="deny", applicable=False, applicability_reason="Synthetic reason")
    assert evaluate(observation, policy, [evidence]).classification == "UNKNOWN"


@pytest.mark.parametrize(
    "status,verified,decision,expected",
    [
        ("observed", False, "deny", "WARNING"),
        ("observed", True, "allow", "WARNING"),
        ("failed", False, "allow", "WARNING"),
        ("not_run", False, "deny", "UNKNOWN"),
        ("inconclusive", False, "deny", "UNKNOWN"),
        ("observed", False, "not_defined", "UNKNOWN"),
    ],
)
def test_risk_does_not_claim_a_violation(evidence, observation, status, verified, decision, expected):
    evidence = revise(evidence, kind="risk_indicator")
    observation = revise(observation, status=status, verified=verified)
    finding = evaluate(observation, CapabilityPolicy(decision=decision), [evidence])
    assert finding.classification == expected


@pytest.mark.parametrize("decision,expected", [("allow", "WARNING"), ("deny", "VIOLATION")])
def test_conclusive_availability_with_secondary_risk(evidence, observation, decision, expected):
    risk = revise(evidence, id="synthetic_risk", kind="risk_indicator")
    observation = revise(observation, evidence_refs=[evidence.id, risk.id])
    finding = evaluate(observation, CapabilityPolicy(decision=decision), [evidence, risk])
    assert finding.classification == expected


@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_missing_evidence_never_passes(observation, decision):
    finding = evaluate(observation, CapabilityPolicy(decision=decision))
    assert finding.classification == "UNKNOWN"
    assert any("unresolved" in limitation for limitation in finding.limitations)
    observation = revise(observation, evidence_refs=[])
    assert evaluate(observation, CapabilityPolicy(decision=decision)).classification == "UNKNOWN"


def test_unreferenced_evidence_cannot_verify_a_capability(evidence, observation):
    observation = revise(observation, evidence_refs=[])
    result = evaluate(observation, CapabilityPolicy(decision="allow"), [evidence])
    assert result.classification == "UNKNOWN"
    assert result.evidence == []


def test_contradictory_evidence_never_passes(evidence, observation):
    opposite = revise(evidence, id="opposite_result", kind="capability_unavailable")
    observation = revise(observation, evidence_refs=[evidence.id, opposite.id])
    result = evaluate(observation, CapabilityPolicy(decision="allow"), [evidence, opposite])
    assert result.classification == "UNKNOWN"
    assert result.evidence == [evidence, opposite]
    assert "contradictory" in " ".join(result.limitations)


def test_duplicate_evidence_is_ambiguous_and_preserved(evidence, observation):
    opposite = revise(evidence, kind="capability_unavailable")
    result = evaluate(observation, CapabilityPolicy(decision="allow"), [evidence, opposite])
    assert result.classification == "UNKNOWN"
    assert result.evidence == [evidence, opposite]
    assert any("duplicated" in limitation for limitation in result.limitations)


@pytest.mark.parametrize("status,kind", [("observed", "capability_unavailable"), ("failed", "capability_available")])
def test_status_and_evidence_must_agree(evidence, observation, status, kind):
    evidence = revise(evidence, kind=kind)
    observation = revise(observation, status=status)
    assert evaluate(observation, CapabilityPolicy(decision="deny"), [evidence]).classification == "UNKNOWN"


@pytest.mark.parametrize("kind", ["capability_available", "context", "risk_indicator"])
def test_operator_assertions_are_not_verification(evidence, observation, kind):
    evidence = revise(evidence, kind=kind, source="operator_assertion")
    assert evaluate(observation, CapabilityPolicy(decision="allow"), [evidence]).classification == "UNKNOWN"


def test_passive_absence_is_not_conclusive(evidence, observation):
    evidence = revise(evidence, kind="capability_unavailable", source="passive_inventory")
    observation = revise(observation, status="failed")
    assert evaluate(observation, CapabilityPolicy(decision="deny"), [evidence]).classification == "UNKNOWN"


def test_passive_availability_can_be_evidence(evidence, observation):
    evidence = revise(evidence, source="passive_inventory")
    observation = revise(observation, category="identity", relationship="identity_present")
    assert evaluate(observation, CapabilityPolicy(decision="allow"), [evidence]).classification == "PASS"


@pytest.mark.parametrize("confidence", [0.0, 0.1, 1.0])
def test_confidence_is_separate_from_classification(evidence, observation, confidence):
    observation = revise(observation, confidence=confidence)
    evidence = revise(evidence, confidence=confidence)
    finding = evaluate(observation, CapabilityPolicy(decision="deny"), [evidence])
    assert finding.classification == "VIOLATION"
    assert finding.confidence == confidence
    assert finding.evidence[0].confidence == confidence


def test_evaluation_is_pure_and_deterministic(evidence, observation, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("The evaluator must not perform file I/O")

    policy = CapabilityPolicy(decision="allow")
    before = deepcopy((observation.model_dump(), policy.model_dump(), evidence.model_dump()))
    monkeypatch.setattr("builtins.open", forbidden)
    first = evaluate(observation, policy, [evidence])
    second = evaluate(observation, policy, [evidence])
    assert first == second
    assert findings_to_json([first]) == findings_to_json([second])
    assert (observation.model_dump(), policy.model_dump(), evidence.model_dump()) == before


@pytest.mark.parametrize("target", ["canary.example", "artifacts.corp.example", "10.0.0.1", "172.16.0.1", "192.168.1.1"])
def test_internal_domains_private_space_and_approved_roles_do_not_allow_egress(example_path, target):
    config = load_config(example_path)
    assert external_egress_policy(config, target).decision == "deny"


@pytest.mark.parametrize(
    "destination,target,decision",
    [
        ("canary.example", "CANARY.EXAMPLE", "allow"),
        ("canary.example", "other.example", "deny"),
        ("*.corp.example", "child.corp.example", "allow"),
        ("*.corp.example", "deep.child.corp.example", "allow"),
        ("*.corp.example", "corp.example", "deny"),
        ("*.corp.example", "evilcorp.example", "deny"),
        ("*.corp.example", "corp.example.evil", "deny"),
        ("192.0.2.0/24", "192.0.2.5", "allow"),
        ("192.0.2.0/24", "192.0.3.1", "deny"),
        ("192.0.2.0/24", "host.example", "deny"),
        ("192.0.2.0/24", "2001:db8::1", "deny"),
        ("2001:db8::/32", "2001:db8::1", "allow"),
        ("2001:db8::1", "2001:0DB8::1", "allow"),
        ("2001:db8::1", "2001:db8::2", "deny"),
        ("192.0.2.1", "192.0.2.1", "allow"),
        ("192.0.2.1", "canary.example", "deny"),
    ],
)
def test_explicit_allowlist_literal_matching(config_data, destination, target, decision):
    config_data["boundaries"]["network"]["external_egress"]["allowed_destinations"] = [destination]
    config = Configuration.model_validate(config_data)
    assert external_egress_policy(config, target).decision == decision


@pytest.mark.parametrize("target", ["https://canary.example", "user@host", "*.corp.example", "host:443"])
def test_policy_resolution_rejects_ambiguous_targets(example_path, target):
    with pytest.raises(ValueError):
        external_egress_policy(load_config(example_path), target)


def test_allowlist_decision_evaluates_observation(config_data, observation, evidence):
    config_data["boundaries"]["network"]["external_egress"]["allowed_destinations"] = [observation.target]
    config = Configuration.model_validate(config_data)
    finding = evaluate(observation, external_egress_policy(config, observation.target), [evidence])
    assert finding.classification == "PASS"


def test_large_reference_set_and_applicability_reason_remain_valid(observation):
    observation = revise(observation, evidence_refs=[f"missing_{index}" for index in range(100)])
    result = evaluate(observation, CapabilityPolicy(decision="allow"))
    assert result.classification == "UNKNOWN"
    observation = revise(observation, status="not_run", verified=False, evidence_refs=[])
    policy = CapabilityPolicy(decision="allow", applicable=False, applicability_reason="x" * 2048)
    assert evaluate(observation, policy).classification == "NOT_APPLICABLE"
