"""Local configuration commands. No probe runner exists in Phase 1."""

from pathlib import Path
from typing import Annotated

import typer

from agent_boundary_prober.config import ConfigError, Configuration, load_config

app = typer.Typer(
    help="Validate operator-provided assertions. No probes are executed in Phase 1.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)


def _configuration(path: Path) -> Configuration:
    try:
        return load_config(path)
    except ConfigError as error:
        typer.echo(f"Configuration error: {error}", err=True)
        typer.echo("No probes were executed.", err=True)
        raise typer.Exit(code=1) from None


@app.command()
def validate(
    path: Annotated[Path, typer.Argument(help="Path to a local YAML configuration.")],
) -> None:
    """Validate the configuration, not the environment."""
    config = _configuration(path)
    typer.echo(
        f"Valid configuration: schema version {config.version}, "
        f"environment {config.environment.type}."
    )
    typer.echo("These are operator assertions, not verified environment facts.")
    typer.echo("No probes were executed.")


@app.command()
def show(
    path: Annotated[Path, typer.Argument(help="Path to a local YAML configuration.")],
) -> None:
    """Print normalized configuration JSON only. No probes are executed."""
    config = _configuration(path)
    typer.echo(config.model_dump_json(indent=2))
