import json
from pathlib import Path

from typer.testing import CliRunner
import pytest
import yaml

from agent_boundary_prober.cli import app
from agent_boundary_prober.config import Configuration, load_config

runner = CliRunner()


def test_validate_success_reports_assertions_not_probes(example_path):
    result = runner.invoke(app, ["validate", str(example_path)])
    assert result.exit_code == 0, result.output
    assert "schema version 1" in result.stdout
    assert "environment kubernetes" in result.stdout
    assert "operator assertions, not verified environment facts" in result.stdout
    assert "No probes were executed." in result.stdout
    assert result.stderr == ""


def test_show_stdout_is_only_normalized_json(example_path):
    result = runner.invoke(app, ["show", str(example_path)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data == load_config(example_path).model_dump(mode="json")
    assert data["boundaries"]["services"][0]["relay"]["arbitrary_fetch"] == "unknown"
    assert data["probes"]["direct_connectivity"] is False
    assert result.stderr == ""


def test_show_normalizes_without_changing_the_file(config_data, tmp_path):
    config_data["boundaries"]["services"][0]["endpoint"] = "ARTIFACTS.CORP.EXAMPLE"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    before = path.read_bytes()
    result = runner.invoke(app, ["show", str(path)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["boundaries"]["services"][0]["endpoint"] == "artifacts.corp.example"
    assert path.read_bytes() == before


@pytest.mark.parametrize("command", ["validate", "show"])
@pytest.mark.parametrize("failure", ["missing", "directory", "malformed", "schema", "unsafe", "active"])
def test_failure_codes_and_clean_stdout(command, failure, config_data, tmp_path):
    path = tmp_path / "bad.yaml"
    if failure == "directory":
        path = tmp_path
    elif failure == "malformed":
        path.write_text("version: [", encoding="utf-8")
    elif failure == "unsafe":
        path.write_text("!!python/object/apply:os.system ['never execute']", encoding="utf-8")
    elif failure in {"schema", "active"}:
        if failure == "schema":
            config_data["unexpected"] = True
        else:
            config_data["probes"]["direct_connectivity"] = True
        path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    result = runner.invoke(app, [command, str(path)])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Configuration error:" in result.stderr
    assert "No probes were executed." in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("command", ["validate", "show"])
def test_missing_argument_is_usage_error(command):
    assert runner.invoke(app, [command]).exit_code == 2


@pytest.mark.parametrize("command", ["validate", "show"])
def test_commands_read_only_the_supplied_configuration(command, example_path, monkeypatch):
    original_open = Path.open
    opened = []

    def checked_open(path, *args, **kwargs):
        assert path == example_path, "Configured paths must not be inspected"
        assert args == ("rb",) and kwargs == {}, "The CLI must only read its YAML file"
        opened.append(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", checked_open)
    result = runner.invoke(app, [command, str(example_path)])
    assert result.exit_code == 0, result.output
    assert opened == [example_path]


def test_show_is_json_even_if_text_only_requested(config_data, tmp_path):
    config_data["output"] = {
        "formats": ["text"], "include_evidence": False, "include_limitations": False
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    result = runner.invoke(app, ["show", str(path)])
    assert result.exit_code == 0, result.output
    assert Configuration.model_validate(json.loads(result.stdout)).output.formats == ["text"]


def test_help_describes_no_probe_execution():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "No probes" in result.stdout
