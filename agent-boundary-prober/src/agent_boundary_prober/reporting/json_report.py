"""Deterministic JSON reports that preserve model information."""

from collections.abc import Sequence
import json

from agent_boundary_prober.models import Finding


def findings_to_json(findings: Sequence[Finding]) -> str:
    return json.dumps(
        {
            "version": 1,
            "findings": [finding.model_dump(mode="json", exclude_none=True) for finding in findings],
        },
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
