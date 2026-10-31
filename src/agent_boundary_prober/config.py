"""Strict operator assertions, with no environment inspection or probe execution."""

from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path, PurePosixPath
import re
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    ValidationError,
    model_validator,
)
import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from agent_boundary_prober.models import StrictModel

MAX_CONFIG_BYTES = 1_048_576
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_SERVICE_ID = r"^[a-z][a-z0-9_]{0,63}$"


def _clean_text(value: str) -> str:
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Whitespace and control characters are not permitted")
    return value


def _hostname(value: str) -> str:
    value = _clean_text(value)
    if len(value) > 253 or not value.isascii():
        raise ValueError("Use an ASCII hostname of at most 253 characters")
    value = value.lower()
    labels = value.split(".")
    if any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("Use DNS labels without URLs, ports, paths, or trailing dots")
    if all(label.isdigit() for label in labels):
        raise ValueError("An IP address is not a hostname pattern")
    return value


def validate_hostname_pattern(value: str) -> str:
    if value.startswith("*."):
        return "*." + _hostname(value[2:])
    return _hostname(value)


def validate_endpoint(value: str) -> str:
    value = _clean_text(value)
    if "%" in value:
        raise ValueError("Scoped IP addresses are not supported")
    try:
        return str(ip_address(value))
    except ValueError:
        return _hostname(value)


def validate_cidr(value: str) -> str:
    value = _clean_text(value)
    if "/" not in value or "%" in value:
        raise ValueError("Use explicit, unscoped CIDR notation")
    prefix = value.rsplit("/", 1)[1]
    if not prefix.isascii() or not prefix.isdecimal():
        raise ValueError("CIDRs require a numeric prefix length")
    try:
        return str(ip_network(value, strict=True))
    except ValueError:
        raise ValueError("Use a valid IPv4 or IPv6 network without host bits") from None


def validate_destination(value: str) -> str:
    if "/" in value:
        return validate_cidr(value)
    if value.startswith("*."):
        return validate_hostname_pattern(value)
    return validate_endpoint(value)


def _shared_path(value: str) -> str:
    _clean_text(value)
    if (
        not PurePosixPath(value).is_absolute()
        or value == "/"
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        raise ValueError("Use a canonical absolute POSIX path other than the filesystem root")
    return value


def _must_be_true(value: bool) -> bool:
    if not value:
        raise ValueError("This safety protection must remain enabled")
    return value


def _must_be_false(value: bool) -> bool:
    if value:
        raise ValueError("Active probes are unsupported in Phase 1 and must remain disabled")
    return value


def _unique(values: list[str]) -> list[str]:
    if len(set(values)) != len(values):
        raise ValueError("Entries must be unique after normalization")
    return values


HostnamePattern = Annotated[
    str, StringConstraints(strict=True), AfterValidator(validate_hostname_pattern)
]
Endpoint = Annotated[
    str, StringConstraints(strict=True), AfterValidator(validate_endpoint)
]
CIDR = Annotated[str, StringConstraints(strict=True), AfterValidator(validate_cidr)]
Destination = Annotated[
    str, StringConstraints(strict=True), AfterValidator(validate_destination)
]
SharedPath = Annotated[str, StringConstraints(strict=True), AfterValidator(_shared_path)]
SafetyEnabled = Annotated[StrictBool, AfterValidator(_must_be_true)]
ActiveDisabled = Annotated[StrictBool, AfterValidator(_must_be_false)]
ServiceRole = Literal["approved_internal", "potential_fetch_relay"]


class Environment(StrictModel):
    type: Literal["kubernetes"]


class ExternalEgress(StrictModel):
    mode: Literal["allowlist"]
    default: Literal["deny"]
    allowed_destinations: Annotated[
        list[Destination], Field(strict=True), AfterValidator(_unique)
    ]


class NetworkBoundary(StrictModel):
    internal_domains: Annotated[
        list[HostnamePattern], Field(strict=True), AfterValidator(_unique)
    ]
    internal_cidrs: Annotated[list[CIDR], Field(strict=True), AfterValidator(_unique)]
    external_egress: ExternalEgress


class Relay(StrictModel):
    enabled: StrictBool
    arbitrary_fetch: StrictBool | Literal["unknown"]
    redirect_behavior: Literal["follows", "blocks", "unknown"]

    @model_validator(mode="after")
    def validate_disabled_relay(self) -> Self:
        if not self.enabled and (
            self.arbitrary_fetch != "unknown" or self.redirect_behavior != "unknown"
        ):
            raise ValueError("Disabled relays must leave behavior explicitly unknown")
        return self


class Service(StrictModel):
    id: Annotated[str, StringConstraints(strict=True, pattern=_SERVICE_ID)]
    endpoint: Endpoint
    roles: Annotated[
        list[ServiceRole], Field(strict=True, min_length=1), AfterValidator(_unique)
    ]
    relay: Relay | None = None

    @model_validator(mode="after")
    def validate_relay_role(self) -> Self:
        is_relay = "potential_fetch_relay" in self.roles
        if is_relay and self.relay is None:
            raise ValueError("Potential fetch relays require explicit relay configuration")
        if not is_relay and self.relay is not None:
            raise ValueError("Relay configuration requires the potential_fetch_relay role")
        return self


class SensitiveResources(StrictModel):
    kubernetes_api: Literal["detect_and_check_authorized_permissions"]
    cloud_metadata: Literal["detect"]
    kubelet: Literal["detect"]
    container_runtime_socket: Literal["detect"]
    secret_stores: Literal["inventory_if_authorized"]


class CrossRunValidation(StrictModel):
    mode: Literal["opt_in"]
    use_synthetic_marker: SafetyEnabled
    cleanup_after_test: SafetyEnabled


class SharedState(StrictModel):
    paths: Annotated[list[SharedPath], Field(strict=True), AfterValidator(_unique)]
    cross_run_validation: CrossRunValidation


class Boundaries(StrictModel):
    network: NetworkBoundary
    services: list[Service] = Field(strict=True)
    sensitive_resources: SensitiveResources
    shared_state: SharedState

    @model_validator(mode="after")
    def validate_service_ids(self) -> Self:
        ids = [service.id for service in self.services]
        if len(ids) != len(set(ids)):
            raise ValueError("Service IDs must be unique")
        return self


class ProbeSafety(StrictModel):
    use_controlled_canaries: SafetyEnabled
    avoid_secret_value_collection: SafetyEnabled
    avoid_destructive_actions: SafetyEnabled
    enforce_probe_timeouts: SafetyEnabled
    require_authorization_for_active_tests: SafetyEnabled


class Probes(StrictModel):
    passive_inventory: StrictBool
    direct_connectivity: ActiveDisabled
    relay_behavior: ActiveDisabled
    identity_permissions: ActiveDisabled
    cross_run_state: ActiveDisabled
    safety: ProbeSafety


class Output(StrictModel):
    formats: Annotated[
        list[Literal["text", "json"]],
        Field(strict=True, min_length=1),
        AfterValidator(_unique),
    ]
    include_evidence: StrictBool
    include_limitations: StrictBool


class Configuration(StrictModel):
    version: Annotated[StrictInt, Field(ge=1, le=1)]
    environment: Environment
    boundaries: Boundaries
    probes: Probes
    output: Output


class ConfigError(ValueError):
    """A safe, user-facing configuration error without raw input values."""


def _check_yaml_structure(text: str) -> None:
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if root is None:
        raise ConfigError("Configuration must be a nonempty YAML mapping")
    stack: list[tuple[Node, int]] = [(root, 0)]
    seen: set[int] = set()
    while stack:
        node, depth = stack.pop()
        if id(node) in seen:
            raise ConfigError("YAML aliases are unsupported; use explicit configuration")
        seen.add(id(node))
        if depth > 32 or len(seen) > 10_000:
            raise ConfigError("Configuration exceeds YAML nesting or node limits")
        if isinstance(node, MappingNode):
            keys: set[str] = set()
            for key, value in node.value:
                if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                    raise ConfigError("YAML mapping keys must be strings")
                if key.value in keys:
                    raise ConfigError("Duplicate YAML mapping keys are not permitted")
                keys.add(key.value)
                stack.extend(((key, depth + 1), (value, depth + 1)))
        elif isinstance(node, SequenceNode):
            stack.extend((child, depth + 1) for child in node.value)


def load_config(path: str | Path) -> Configuration:
    """Read only the named local YAML file, not any resources declared inside it."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as error:
        raise ConfigError(f"Cannot read configuration file: {error.strerror}") from None
    except ValueError:
        raise ConfigError("Invalid configuration file path") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("Configuration exceeds the 1 MiB size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("Configuration must be UTF-8 encoded") from None
    try:
        _check_yaml_structure(text)
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigError(f"Invalid YAML{location}; check syntax and safe scalar types") from None
    except RecursionError:
        raise ConfigError("Configuration exceeds YAML nesting limits") from None
    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a YAML mapping")
    try:
        return Configuration.model_validate(data)
    except ValidationError as error:
        details = []
        for issue in error.errors(include_input=False, include_url=False):
            location = ".".join(str(part) for part in issue["loc"]) or "configuration"
            details.append(f"{location!r}: {issue['msg']}")
        raise ConfigError("Invalid configuration:\n" + "\n".join(details)) from None


def destination_matches(target: str, destination: str) -> bool:
    """Pure literal matching; never resolve DNS or infer trust from private space."""
    normalized = validate_endpoint(target)
    try:
        address: IPv4Address | IPv6Address | None = ip_address(normalized)
    except ValueError:
        address = None
    if "/" in destination:
        return address is not None and address in ip_network(destination)
    if destination.startswith("*."):
        return address is None and normalized.endswith("." + destination[2:])
    return normalized == destination
