# Agent Boundary Prober

Phase 1 is a local-only foundation for policy-driven auditing of AI agent
sandboxes. It validates YAML operator assertions, models supplied observations
and payload-free evidence, classifies capabilities, and serializes findings.
It does not inspect or verify the configured Kubernetes environment.

## Setup and local commands

Python 3.12 or newer is required. From this directory:

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/abp validate examples/kubernetes.yaml
.venv/bin/abp show examples/kubernetes.yaml
.venv/bin/python -m pytest -q
```

Use any available Python 3.12+ executable in place of `python3.13`. Installing
the package creates the `abp` entry point in `.venv/bin`; activating the virtual
environment also makes `abp` available directly.

`validate` prints the schema version, environment, assertion-only status, and
an explicit statement that no probes ran. `show` prints normalized configuration
JSON only. Both commands validate first and return 1 for file, YAML, or schema
errors. Missing arguments and invalid CLI syntax return 2. Success returns 0.
Errors go to stderr without raw configuration values or tracebacks.

The `output` settings describe future audit reports. They do not suppress
configuration fields, change `show` into text, or cause evidence collection.
The library JSON reporter preserves evidence and limitations unconditionally.
There is no audit execution command or text finding renderer in this phase.

## Configuration contract

[`examples/kubernetes.yaml`](examples/kubernetes.yaml) contains the complete
version 1 example. Every listed section and field is required except `relay`
for a service without the `potential_fetch_relay` role. Unknown fields at
every level are rejected. Scalar types are not coerced to booleans or integers.
Sequence fields require actual lists; YAML sets are not converted into lists.
Schema version 1 and environment type `kubernetes` are currently supported.

These conservative Phase 1 choices make underspecified cases explicit:

- DNS names are ASCII, case-normalized, and contain valid DNS labels. Patterns
  allow an exact name or a leading `*.` only. A wildcard matches descendants at
  any depth, not the suffix itself. Trailing dots, Unicode DNS names, URLs,
  ports, credentials, paths, and scoped IPv6 addresses are rejected.
- Service endpoints are exact DNS names or unscoped IPv4/IPv6 literals.
  Service IDs use lowercase letters, digits, and underscores, start with a
  letter, and have at most 64 characters. IDs must be unique.
- CIDRs must explicitly include a numeric prefix length and have no host bits. IPv4/IPv6
  spellings are normalized. Allowlists accept exact hosts, IPs, DNS patterns,
  and CIDRs. Duplicate normalized entries are rejected.
- External egress supports `mode: allowlist` with `default: deny` only.
  `external_egress_policy` uses only explicit destinations. It does not
  resolve DNS, follow redirects, infer a hostname's IPs, or treat private
  CIDRs, internal domains, or `approved_internal` roles as permission.
  It resolves an external-egress check, not a general internal traffic policy.
- Service roles can overlap. The supported roles are `approved_internal` and
  `potential_fetch_relay`. A potential relay must have a relay section; a
  non-relay cannot have one. `arbitrary_fetch` accepts YAML booleans or
  the literal `unknown`. `redirect_behavior` accepts `follows`, `blocks`, or
  `unknown`. Disabled relays must leave both behavior fields `unknown`.
- Shared-state paths are canonical absolute POSIX paths with no whitespace,
  control characters, backslashes, trailing slash, empty segment, `.` or `..`.
  The filesystem root is rejected. Paths are never opened, resolved, or checked
  for existence. Cross-run mode is `opt_in`; synthetic markers and cleanup
  must remain enabled.
- All five probe safety protections must be true. Active probe flags must be
  false. `passive_inventory` can be true or false, but neither value executes
  inventory in Phase 1. Sensitive-resource directives describe intended scope,
  not detected identities, verified permissions, or an authorization grant.
- Output formats are a nonempty, unique list containing `text` and/or `json`.
  Configuration is UTF-8 YAML, limited to 1 MiB, 32 node levels, and 10,000
  nodes. Duplicate mapping keys, non-string keys, and aliases are rejected.
  Loading uses `yaml.safe_load`; unsafe YAML constructors are not enabled.

The declared domains, networks, service roles, relay behaviors, safety flags,
and environment type are operator assertions. They are not findings about a
running environment. Explicit `unknown` values remain unknown.

## Models and policy evaluation

`models.py` defines strict models for `Evidence`, `Observation`,
`CapabilityPolicy`, and `Finding`. An observation identifies its category,
subject, target, relationship, status, verification state, symbolic evidence
references, confidence, and limitations. Categories cover direct network
access, relays, identities, permissions, and shared state.

`observed` means an available capability was reported. `failed` describes a
conclusive negative capability test, not an arbitrary timeout, DNS failure,
authorization failure, or collector error. Those ambiguous outcomes must be
`inconclusive`. Unexecuted checks must be `not_run`. Neither can be marked
verified. Supplying `verified: true` alone is insufficient for a pass.

`policy.evaluate(observation, policy, evidence)` is pure and deterministic.
It does not load configuration, run tests, inspect resources, modify inputs,
use the clock, or generate random IDs. Finding IDs reuse observation IDs;
callers should give observations unique IDs within a report.

| Supplied state | Classification |
| --- | --- |
| Verified available capability, explicit deny | `VIOLATION` |
| Verified available capability, explicit allow, no risk indicator | `PASS` |
| Conclusively unavailable required capability | `VIOLATION` |
| Conclusively unavailable optional allowed capability | `PASS`, scoped to the tested path |
| Conclusively unavailable denied capability | `PASS`, with an explicit tested-path limitation |
| Untested, inconclusive, missing or contradictory evidence | `UNKNOWN` |
| No policy decision (`not_defined`) | `UNKNOWN` |
| Risk indicator without a definite violation | `WARNING` |
| Explicit non-applicability reason, no test and no outcome or risk evidence | `NOT_APPLICABLE` |

Warnings do not override a verified prohibited capability. A permitted
capability with a risk indicator produces a warning instead of a clean pass.
Non-applicability cannot hide an executed or inconclusive test. Contradictions
and unresolved or duplicated references produce unknown results; duplicated
referenced evidence records are retained for inspection.

Availability requires referenced availability evidence from a controlled test
or passive inventory, plus a verified observation. Absence requires referenced
unavailability evidence from a controlled test; a passive inventory omission
does not establish absence. Operator-assertion evidence never verifies a
capability. Evidence sources are supplied by callers, not authenticated by
this library. A future collector must distinguish evidence that proves
presence from evidence that proves a usable relationship or permission.

Confidence is a finite number from 0 to 1. Observation confidence is preserved
on findings, and each evidence record retains its own confidence. It is not a
classification threshold or a substitute for verification.

Only external-egress policy has a configuration resolver in Phase 1.
Other discovery directives do not define allow/deny policy. Callers must use
`not_defined` unless an explicit applicable `CapabilityPolicy` exists, and
must bind that policy and its evidence to the same observation and conditions.

For example, this code reports an untested capability as `UNKNOWN`:

```python
from agent_boundary_prober.config import load_config
from agent_boundary_prober.models import Observation
from agent_boundary_prober.policy import evaluate, external_egress_policy
from agent_boundary_prober.reporting import findings_to_json

config = load_config("examples/kubernetes.yaml")
observation = Observation(
    id="canary_egress",
    category="direct_network",
    subject="example_agent",
    target="canary.example",
    relationship="direct_egress",
    status="not_run",
    verified=False,
    confidence=0.0,
    limitations=["Phase 1 does not implement probes."],
)
policy = external_egress_policy(config, observation.target)
finding = evaluate(observation, policy)
print(findings_to_json([finding]))
```

## Evidence, reporting, and safety

Evidence contains a symbolic identifier, an enumerated outcome and source,
and confidence. It has no raw body, token, credential, secret, URL, arbitrary
metadata, or payload field. Unknown fields are rejected rather than retained.
Never put credentials or secret values into identifiers, observation labels,
limitations, remediation, or configuration. Bounded single-line labels are a
caller contract, not a general secret detector or redaction system.

`reporting.findings_to_json` returns a version 1 object containing a `findings`
array. Enum values, policy requirements, observations, referenced evidence,
confidence, limitations, and non-null remediation are preserved. Unrelated
evidence is excluded. Null optional fields are omitted. Reporting does not
reevaluate findings, change classifications, or inspect external resources.

No network requests, relay requests, Kubernetes API calls, secret inspection,
shell probes, marker writes, subprocess execution, or destructive actions are
implemented. The CLI reads only the specified configuration. Tests use
synthetic inputs and block network resolution, network sends, and child
processes. pytest temporary files remain under `.pytest-tmp` in this project.
Setup can download ordinary declared Python packages; tests and the CLI do
not require external connectivity or a Kubernetes cluster.

## Layout and limitations

`config.py` owns YAML loading and validation. `models.py` owns data contracts.
`policy/evaluator.py` owns classifications and literal egress policy matching.
`cli.py` owns the two local commands. `reporting/json_report.py` owns JSON
serialization. The tests cover each surface without a live environment.

This foundation cannot establish actual reachability, relay behavior, identity
availability, effective permissions, or cross-run isolation. It cannot prove
authorization to conduct an audit. It trusts callers to supply truthful,
correctly scoped evidence and an applicable policy. It makes no global safety
claim from a failed test on a single path. There are no plugins, hooks, cloud
SDKs, remote resources, or Kubernetes dependencies.

The recommended next phase is an authorization-gated passive inventory
collector with explicit scope and typed, payload-free evidence. Keep runtime
facts separate from operator assertions, handle collector failures as
inconclusive, and test the collector offline with synthetic fixtures before
considering separately authorized controlled-canary probes.
