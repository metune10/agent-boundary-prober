from pathlib import Path
import os
import socket
import subprocess

import pytest
import yaml

from agent_boundary_prober.models import Evidence, Observation

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = PROJECT_ROOT / "examples" / "kubernetes.yaml"


@pytest.fixture
def config_data():
    return yaml.safe_load(EXAMPLE_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def example_path():
    return EXAMPLE_PATH


@pytest.fixture
def evidence():
    return Evidence(
        id="synthetic_result",
        kind="capability_available",
        source="controlled_test",
        confidence=0.95,
    )


@pytest.fixture
def observation(evidence):
    return Observation(
        id="egress_check",
        category="direct_network",
        subject="synthetic_agent",
        target="canary.example",
        relationship="direct_egress",
        status="observed",
        verified=True,
        evidence_refs=[evidence.id],
        confidence=0.9,
        limitations=["Synthetic unit-test input, not an executed probe."],
    )


@pytest.fixture(autouse=True)
def no_network_or_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must not execute network requests or child processes")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("connect", "connect_ex", "sendto", "sendmsg"):
        monkeypatch.setattr(socket.socket, name, forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
