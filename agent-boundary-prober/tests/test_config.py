from copy import deepcopy

from pydantic import ValidationError
import pytest
import yaml

from agent_boundary_prober.config import (
    MAX_CONFIG_BYTES,
    ConfigError,
    Configuration,
    load_config,
)


def replace(data, path, value):
    for part in path[:-1]:
        data = data[part]
    data[path[-1]] = value


def test_exact_example_and_unknown_states(example_path):
    config = load_config(example_path)
    assert config.version == 1
    assert config.environment.type == "kubernetes"
    assert config.boundaries.services[0].roles == [
        "approved_internal",
        "potential_fetch_relay",
    ]
    assert config.boundaries.services[0].relay.arbitrary_fetch == "unknown"
    assert config.boundaries.services[0].relay.redirect_behavior == "unknown"
    assert config.probes.passive_inventory is True
    assert config.probes.direct_connectivity is False
    assert config.boundaries.network.external_egress.allowed_destinations == []


@pytest.mark.parametrize("version", [0, 2, -1, True, 1.0, "1", None])
def test_invalid_version(config_data, version):
    config_data["version"] = version
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.1/8", "10.0.0.0/33", "999.1.1.1/8", "10.0.0.0", "::1/64", "fe80::%en0/64", "x/8", " 10.0.0.0/8", "10.0.0.0/255.0.0.0", "10.0.0.0/\u0668"],
)
def test_invalid_cidrs(config_data, cidr):
    config_data["boundaries"]["network"]["internal_cidrs"] = [cidr]
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "pattern",
    ["*", "*.*", "corp.*", "a.*.example", "https://corp.example", "a..example", ".example", "corp.example.", "-bad.example", "bad_.example", "x.example:443", "10.0.0.1", "*.10.0.0.1", "caf\u00e9.example", "bad example", "\u212a.example", "*.\u212a.example"],
)
def test_invalid_domain_patterns(config_data, pattern):
    config_data["boundaries"]["network"]["internal_domains"] = [pattern]
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "endpoint",
    ["https://artifacts.corp.example", "host:443", "host/path", "user@host", "*.corp.example", "999.1.1.1", "host.", "host\n", "[::1]", "fe80::1%en0", "", "\u212a.example"],
)
def test_invalid_endpoints(config_data, endpoint):
    config_data["boundaries"]["services"][0]["endpoint"] = endpoint
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize("endpoint", ["service", "SERVICE.CORP.EXAMPLE", "192.0.2.1", "2001:DB8::1"])
def test_valid_endpoints(config_data, endpoint):
    config_data["boundaries"]["services"][0]["endpoint"] = endpoint
    config = Configuration.model_validate(config_data)
    assert config.boundaries.services[0].endpoint == endpoint.lower()


@pytest.mark.parametrize(
    "path,value",
    [
        (("environment", "type"), "docker"),
        (("boundaries", "network", "external_egress", "mode"), "allow_all"),
        (("boundaries", "network", "external_egress", "default"), "allow"),
        (("boundaries", "services", 0, "roles"), ["trusted"]),
        (("boundaries", "services", 0, "relay", "arbitrary_fetch"), "yes"),
        (("boundaries", "services", 0, "relay", "redirect_behavior"), "sometimes"),
        (("boundaries", "sensitive_resources", "kubernetes_api"), "read_secrets"),
        (("boundaries", "sensitive_resources", "cloud_metadata"), "ignore"),
        (("boundaries", "sensitive_resources", "kubelet"), "ignore"),
        (("boundaries", "sensitive_resources", "container_runtime_socket"), "connect"),
        (("boundaries", "sensitive_resources", "secret_stores"), "collect"),
        (("boundaries", "shared_state", "cross_run_validation", "mode"), "automatic"),
        (("output", "formats"), ["yaml"]),
        (("output", "formats"), []),
        (("output", "formats"), ["json", "json"]),
    ],
)
def test_invalid_enum_values(config_data, path, value):
    replace(config_data, path, value)
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("environment",),
        ("boundaries",),
        ("boundaries", "network"),
        ("boundaries", "network", "external_egress"),
        ("boundaries", "services", 0),
        ("boundaries", "services", 0, "relay"),
        ("boundaries", "sensitive_resources"),
        ("boundaries", "shared_state"),
        ("boundaries", "shared_state", "cross_run_validation"),
        ("probes",),
        ("probes", "safety"),
        ("output",),
    ],
)
def test_unknown_fields_rejected_everywhere(config_data, path):
    section = config_data
    for part in path:
        section = section[part]
    section["unexpected"] = "must_not_be_ignored"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Configuration.model_validate(config_data)


def test_duplicate_service_ids(config_data):
    config_data["boundaries"]["services"].append(
        deepcopy(config_data["boundaries"]["services"][0])
    )
    with pytest.raises(ValidationError, match="Service IDs must be unique"):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize("identifier", ["bad-id", "9service", "Bad", "", "a" * 65])
def test_invalid_service_identifiers(config_data, identifier):
    config_data["boundaries"]["services"][0]["id"] = identifier
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize("roles", [[], ["approved_internal", "approved_internal"]])
def test_invalid_role_lists(config_data, roles):
    config_data["boundaries"]["services"][0]["roles"] = roles
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


def test_relay_role_requires_configuration(config_data):
    del config_data["boundaries"]["services"][0]["relay"]
    with pytest.raises(ValidationError, match="require explicit relay configuration"):
        Configuration.model_validate(config_data)


def test_relay_configuration_requires_role(config_data):
    config_data["boundaries"]["services"][0]["roles"] = ["approved_internal"]
    with pytest.raises(ValidationError, match="requires the potential_fetch_relay role"):
        Configuration.model_validate(config_data)


def test_plain_service_without_relay_is_valid(config_data):
    service = config_data["boundaries"]["services"][0]
    service["roles"] = ["approved_internal"]
    del service["relay"]
    assert Configuration.model_validate(config_data).boundaries.services[0].relay is None


@pytest.mark.parametrize("arbitrary_fetch", [True, False, "unknown"])
@pytest.mark.parametrize("redirect_behavior", ["follows", "blocks", "unknown"])
def test_relay_assertions_are_preserved(config_data, arbitrary_fetch, redirect_behavior):
    relay = config_data["boundaries"]["services"][0]["relay"]
    relay["arbitrary_fetch"] = arbitrary_fetch
    relay["redirect_behavior"] = redirect_behavior
    normalized = Configuration.model_validate(config_data).boundaries.services[0].relay
    assert normalized.arbitrary_fetch == arbitrary_fetch
    assert normalized.redirect_behavior == redirect_behavior


def test_disabled_relay_must_remain_unknown(config_data):
    relay = config_data["boundaries"]["services"][0]["relay"]
    relay["enabled"] = False
    assert Configuration.model_validate(config_data).boundaries.services[0].relay.enabled is False
    relay["arbitrary_fetch"] = False
    with pytest.raises(ValidationError, match="leave behavior explicitly unknown"):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "path",
    ["relative", "~/workspace", "/", "/workspace/../secret", "/workspace/.", "//shared", "/shared//run", "/shared/", "C:\\workspace", "/shared\\run", "/bad\x00path"],
)
def test_invalid_shared_paths(config_data, path):
    config_data["boundaries"]["shared_state"]["paths"] = [path]
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "flag",
    ["use_controlled_canaries", "avoid_secret_value_collection", "avoid_destructive_actions", "enforce_probe_timeouts", "require_authorization_for_active_tests"],
)
@pytest.mark.parametrize("value", [False, 1, "true"])
def test_safety_protections_cannot_be_disabled_or_coerced(config_data, flag, value):
    config_data["probes"]["safety"][flag] = value
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize("flag", ["use_synthetic_marker", "cleanup_after_test"])
def test_cross_run_safety_cannot_be_disabled(config_data, flag):
    config_data["boundaries"]["shared_state"]["cross_run_validation"][flag] = False
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "flag", ["direct_connectivity", "relay_behavior", "identity_permissions", "cross_run_state"]
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_active_probes_are_rejected(config_data, flag, value):
    config_data["probes"][flag] = value
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


@pytest.mark.parametrize(
    "text",
    ["version: [", "version: 1\n  bad: indentation", "!!python/object/apply:os.system ['never execute']", "version: 1\nversion: 2", "x: &ref [*ref]", "x: &ref 1\ny: *ref", "1: bad_key", "? [complex, key]\n: value", "", "null", "[]", "hello"],
)
def test_bad_yaml_is_rejected_without_execution(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


@pytest.mark.parametrize(
    "path,value",
    [
        (("boundaries", "network", "internal_domains"), ["Corp.Example", "corp.example"]),
        (("boundaries", "network", "internal_cidrs"), ["2001:db8::/32", "2001:0db8::/32"]),
        (("boundaries", "network", "external_egress", "allowed_destinations"), ["HOST.EXAMPLE", "host.example"]),
        (("boundaries", "shared_state", "paths"), ["/shared", "/shared"]),
    ],
)
def test_normalized_duplicates_rejected(config_data, path, value):
    replace(config_data, path, value)
    with pytest.raises(ValidationError, match="unique after normalization"):
        Configuration.model_validate(config_data)


def test_normalization_and_roundtrip(config_data, tmp_path):
    config_data["boundaries"]["network"]["internal_domains"] = ["*.CORP.EXAMPLE"]
    config_data["boundaries"]["network"]["internal_cidrs"] = ["2001:0DB8::/32"]
    config_data["boundaries"]["network"]["external_egress"]["allowed_destinations"] = [
        "Canary.Example", "*.OTHER.EXAMPLE", "192.0.2.1", "2001:0DB8::1", "198.51.100.0/24"
    ]
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    config = load_config(path)
    assert config.boundaries.network.internal_domains == ["*.corp.example"]
    assert config.boundaries.network.internal_cidrs == ["2001:db8::/32"]
    assert config.boundaries.network.external_egress.allowed_destinations == [
        "canary.example", "*.other.example", "192.0.2.1", "2001:db8::1", "198.51.100.0/24"
    ]
    assert Configuration.model_validate_json(config.model_dump_json()) == config


@pytest.mark.parametrize("destination", ["https://host.example", "*", "10.0.0.1/8", "x.example:443"])
def test_invalid_allowlist_destinations(config_data, destination):
    config_data["boundaries"]["network"]["external_egress"]["allowed_destinations"] = [destination]
    with pytest.raises(ValidationError):
        Configuration.model_validate(config_data)


def test_file_failures_and_resource_limits(tmp_path):
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path / "missing.yaml")
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path)
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"\xff")
    with pytest.raises(ConfigError, match="UTF-8"):
        load_config(path)
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ConfigError, match="size limit"):
        load_config(path)
    path.write_text("[" * 40 + "0" + "]" * 40, encoding="utf-8")
    with pytest.raises(ConfigError, match="nesting"):
        load_config(path)
    path.write_text("[" + ",".join("0" for _ in range(10_001)) + "]", encoding="utf-8")
    with pytest.raises(ConfigError, match="node limits"):
        load_config(path)


def test_schema_errors_do_not_echo_raw_values(config_data, tmp_path):
    sentinel = "synthetic-sensitive-value-not-a-real-secret"
    config_data["environment"]["type"] = sentinel
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    with pytest.raises(ConfigError) as captured:
        load_config(path)
    assert sentinel not in str(captured.value)
    assert "environment.type" in str(captured.value)


@pytest.mark.parametrize(
    "path",
    [
        ("boundaries", "network", "internal_domains"),
        ("boundaries", "network", "internal_cidrs"),
        ("boundaries", "network", "external_egress", "allowed_destinations"),
        ("boundaries", "services"),
        ("boundaries", "services", 0, "roles"),
        ("boundaries", "shared_state", "paths"),
        ("output", "formats"),
    ],
)
def test_sequence_fields_reject_implicit_conversion(config_data, path):
    section = config_data
    for part in path:
        section = section[part]
    replace(config_data, path, tuple(section))
    with pytest.raises(ValidationError, match="valid list"):
        Configuration.model_validate(config_data)


def test_yaml_set_is_not_a_configuration_sequence(config_data, tmp_path):
    config_data["output"]["formats"] = {"json"}
    path = tmp_path / "set.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    with pytest.raises(ConfigError, match="valid list"):
        load_config(path)


def test_invalid_file_path_is_a_clear_error():
    with pytest.raises(ConfigError, match="Invalid configuration file path"):
        load_config("invalid\x00path")
